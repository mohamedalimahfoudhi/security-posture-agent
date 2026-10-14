import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

def route_question(question: str) -> str:
    """
    Determine the category of the question to optimize DB retrieval.
    Returns one of: 'technology', 'vendor', 'threat', 'assessment', 'alert', 'general'
    """
    q_lower = question.lower()
    
    tech_keywords = ['technology', 'technologies', 'software', 'hardware', 'asset', 'assets', 'internet exposed', 'running', 'server', 'database', 'environment', 'posture']
    vendor_keywords = ['vendor', 'vendors', 'third party', 'third parties', 'third-party', 'supplier', 'provider', 'supply chain', 'architecture', 'architectures', 'service', 'services']
    threat_keywords = ['threat', 'vulnerability', 'vulnerabilities', 'cve', 'ransomware', 'exploit', 'attack', 'risk', 'risks']
    assessment_keywords = ['assessment', 'assessments', 'audit', 'compliance']
    alert_keywords = ['alert', 'alerts', 'incident', 'incidents', 'detect']
    
    # Priority matching
    if any(k in q_lower for k in alert_keywords):
        return 'alert'
    if any(k in q_lower for k in assessment_keywords):
        return 'assessment'
    if any(k in q_lower for k in threat_keywords):
        return 'threat'
    if any(k in q_lower for k in vendor_keywords):
        return 'vendor'
    if any(k in q_lower for k in tech_keywords):
        return 'technology'
        
    return 'general'

def build_customer_profile(cur, customer_id: int, intent: str) -> str:
    """
    Query the database based on the intent and build a structured Markdown profile.
    """
    # 1. Base check: has the customer uploaded any documents/inventory?
    cur.execute("SELECT COUNT(*) FROM documents WHERE customer_id = %s", (customer_id,))
    doc_count = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM assets WHERE customer_id = %s", (customer_id,))
    asset_count = cur.fetchone()[0]

    try:
        cur.execute("""SELECT COUNT(*) FROM third_party_architectures a
            JOIN customer_vendors cv ON cv.id = a.customer_vendor_id
            WHERE cv.customer_id = %s""", (customer_id,))
        architecture_count = cur.fetchone()[0]
    except Exception as e:
        # Table may not exist in this database version
        logger.warning(f"third_party_architectures table unavailable: {e}")
        cur.connection.rollback()
        architecture_count = 0

    cur.execute("SELECT COUNT(*) FROM customer_vendors WHERE customer_id = %s", (customer_id,))
    vendor_count = cur.fetchone()[0]

    # A customer with no uploaded documents/assets/architectures but with
    # registered third-party relationships (customer_vendors) still has
    # inventory relevant for third-party risk analysis (e.g. breach exposure).
    if doc_count == 0 and asset_count == 0 and architecture_count == 0 and vendor_count == 0:
        return "No inventory has been uploaded yet. Upload architecture documents or assets to enable customer-specific risk analysis."
    
    profile = ["# CUSTOMER PROFILE\n"]
    profile.append("## Architecture")
    profile.append(f"- Documents: {doc_count}")
    profile.append(f"- Technologies: {asset_count}")
    profile.append(f"- Third Parties: {vendor_count}")
    profile.append(f"- Third-Party Architectures: {architecture_count}\n")
    
    # 2. Technology / Assets
    if intent in ['technology', 'general', 'threat', 'vendor']:
        cur.execute("""
            SELECT technology, version, vendor, internet_exposed, criticality 
            FROM assets 
            WHERE customer_id = %s AND technology IS NOT NULL
            ORDER BY CASE WHEN criticality='CRITICAL' THEN 1 WHEN criticality='HIGH' THEN 2 ELSE 3 END,
                     internet_exposed DESC, updated_at DESC NULLS LAST
            LIMIT 20
        """, (customer_id,))
        assets = cur.fetchall()
        if assets:
            profile.append("## Technology Inventory")
            for a in assets:
                tech = a[0]
                version = f" {a[1]}" if a[1] else ""
                vendor = f" ({a[2]})" if a[2] else ""
                profile.append(f"- {tech}{version}{vendor}")
            
            internet_exposed = [a[0] for a in assets if a[3]]
            if internet_exposed:
                profile.append("\n## Internet Exposed")
                for tech in set(internet_exposed):
                    profile.append(f"- {tech}")
                    
            critical_tech = [a[0] for a in assets if a[4] == 'CRITICAL']
            if critical_tech:
                profile.append("\n## Critical Technologies")
                for tech in set(critical_tech):
                    profile.append(f"- {tech}")
            profile.append("")
                    
    # 3. Third-Party Vendors
    if intent in ['vendor', 'general', 'threat']:
        cur.execute("""
            SELECT vendor, relationship_type, base_risk_score 
            FROM customer_vendors 
            WHERE customer_id = %s AND vendor IS NOT NULL
            ORDER BY base_risk_score DESC 
            LIMIT 20
        """, (customer_id,))
        vendors = cur.fetchall()
        if vendors:
            profile.append("## Third Parties")
            for v in vendors:
                profile.append(f"- {v[0]} (Type: {v[1]}, Risk Score: {v[2]})")
            profile.append("")
            
    # 3b. Vendor-provided architectures, services, and technology context
    if intent in ['vendor', 'general', 'threat', 'technology']:
        try:
            cur.execute("""SELECT cv.vendor, a.name, a.criticality, a.risk_score,
                COALESCE(string_agg(DISTINCT t.technology_name, ', '), 'No technologies mapped'),
                COALESCE(string_agg(DISTINCT s.service_name, ', '), 'No services mapped')
                FROM third_party_architectures a JOIN customer_vendors cv ON cv.id=a.customer_vendor_id
                LEFT JOIN architecture_technologies t ON t.architecture_id=a.id
                LEFT JOIN architecture_services s ON s.architecture_id=a.id
                WHERE cv.customer_id=%s GROUP BY cv.vendor,a.id ORDER BY a.risk_score DESC LIMIT 10""", (customer_id,))
            architectures = cur.fetchall()
            if architectures:
                profile.append("## Third-Party Architectures")
                for architecture in architectures:
                    profile.append(f"- {architecture[0]} / {architecture[1]} [Criticality: {architecture[2]}, Risk: {architecture[3]}] Technologies: {architecture[4]}; Services: {architecture[5]}")
                profile.append("")
        except Exception as e:
            logger.warning(f"Error fetching third-party architectures: {e}")
            cur.connection.rollback()

    # 4. Third-Party Exposures (Threats to vendors)
    if intent in ['threat', 'vendor', 'general']:
        try:
            cur.execute("""
                SELECT v.vendor, t.title, t.cve_id, e.risk_score, e.priority
                FROM third_party_exposures e
                JOIN customer_vendors v ON e.customer_vendor_id = v.id
                JOIN threat_events t ON e.threat_event_id = t.id
                WHERE e.customer_id = %s
                ORDER BY e.risk_score DESC
                LIMIT 10
            """, (customer_id,))
            exposures = cur.fetchall()
            if exposures:
                profile.append("## Current Third Party Exposures")
                for ex in exposures:
                    cve = f" ({ex[2]})" if ex[2] else ""
                    profile.append(f"- Vendor {ex[0]} exposed to {ex[1]}{cve} [Risk Score: {ex[3]}, Priority: {ex[4]}]")
                profile.append("")
        except Exception as e:
            # Table might not exist or columns might be slightly different in this db version
            logger.warning(f"Error fetching third_party_exposures: {e}")
            cur.connection.rollback()
            
    # 5. Open Assessments
    if intent in ['assessment', 'general', 'threat', 'technology']:
        cur.execute("""
            SELECT technology, vendor, threat_summary, severity 
            FROM assessments 
            WHERE customer_id = %s AND threat_summary IS NOT NULL
            ORDER BY risk_score DESC 
            LIMIT 10
        """, (customer_id,))
        assessments = cur.fetchall()
        if assessments:
            profile.append(f"## Open Assessments")
            for a in assessments:
                tech = a[0] or a[1] or "Unknown"
                profile.append(f"- {tech}: {a[2]} [Severity: {a[3]}]")
            profile.append("")
            
    # 6. Active Alerts
    if intent in ['alert', 'general', 'threat']:
        cur.execute("""
            SELECT title, risk_level, status 
            FROM alerts 
            WHERE customer_id = %s AND status IN ('NEW', 'OPEN', 'CRITICAL') AND title IS NOT NULL
            ORDER BY risk_score DESC 
            LIMIT 10
        """, (customer_id,))
        alerts = cur.fetchall()
        if alerts:
            profile.append(f"## Critical Alerts")
            for a in alerts:
                profile.append(f"- {a[0]} [Risk: {a[1]}, Status: {a[2]}]")
            profile.append("")
            
    # 7. Recent Threat Events (CVEs)
    if intent in ['threat', 'general']:
        cur.execute("""
            SELECT DISTINCT c.cve_id, c.title, c.severity 
            FROM cve_events c
            JOIN assessments a ON a.event_id = c.id
            WHERE a.customer_id = %s AND c.title IS NOT NULL
            ORDER BY c.severity DESC
            LIMIT 10
        """, (customer_id,))
        cves = cur.fetchall()
        if cves:
            profile.append("## Recent Threat Events (CVEs)")
            for c in cves:
                profile.append(f"- {c[0]}: {c[1]} [Severity: {c[2]}]")
            profile.append("")

    # 8. Third-Party Security Profiles (business role, tech/services/assets, risk)
    if intent in ['vendor', 'threat', 'general', 'technology']:
        try:
            cur.execute("""
                SELECT cv.vendor,
                       p.business_role,
                       p.data_access_level,
                       p.privileged_access,
                       p.criticality,
                       p.risk_score,
                       COALESCE(string_agg(DISTINCT t.technology || COALESCE(' ' || t.version, ''), ', '), 'No technologies mapped') AS technologies,
                       COALESCE(string_agg(DISTINCT s.service_name, ', '), 'No services mapped') AS services,
                       COALESCE(string_agg(DISTINCT x.asset_type || ':' || x.value, ', '), 'No external assets mapped') AS assets
                FROM customer_vendors cv
                JOIN third_party_profiles p ON p.customer_vendor_id = cv.id
                LEFT JOIN third_party_profile_technologies t ON t.profile_id = p.id
                LEFT JOIN third_party_profile_services s ON s.profile_id = p.id
                LEFT JOIN third_party_external_assets x ON x.profile_id = p.id
                WHERE cv.customer_id = %s
                GROUP BY cv.vendor, p.id
                ORDER BY p.risk_score DESC
                LIMIT 20
            """, (customer_id,))
            profiles = cur.fetchall()
            if profiles:
                profile.append("## Third-Party Security Profiles")
                for pr in profiles:
                    vendor_name, role, access, priv, crit, risk, techs, services_str, assets_str = pr
                    access_str = access or "UNKNOWN"
                    priv_str = "YES" if priv else "NO"
                    profile.append(
                        f"- {vendor_name} [Role: {role or 'N/A'}, Access: {access_str}, "
                        f"Privileged: {priv_str}, Criticality: {crit or 'MEDIUM'}, Risk: {risk}]"
                    )
                    profile.append(f"  - Technologies: {techs}")
                    profile.append(f"  - Services: {services_str}")
                    profile.append(f"  - External Assets: {assets_str}")
                profile.append("")

            # Privileged access list (explicit answer support)
            cur.execute("""
                SELECT cv.vendor, p.business_role, p.risk_score
                FROM customer_vendors cv
                JOIN third_party_profiles p ON p.customer_vendor_id = cv.id
                WHERE cv.customer_id = %s AND p.privileged_access = TRUE
                ORDER BY p.risk_score DESC
            """, (customer_id,))
            privileged_vendors = cur.fetchall()
            if privileged_vendors:
                profile.append("## Vendors with Privileged Access")
                for pv in privileged_vendors:
                    profile.append(f"- {pv[0]} [Role: {pv[1] or 'N/A'}, Risk: {pv[2]}]")
                profile.append("")
        except Exception as e:
            logger.warning(f"Error fetching third-party profiles: {e}")
            cur.connection.rollback()

    # 9. Architecture Changes (for "what changed" questions)
    if intent in ['vendor', 'threat', 'general', 'alert']:
        try:
            cur.execute("""
                SELECT cv.vendor, ac.added_technologies, ac.removed_technologies,
                       ac.changed_versions, ac.risk_before, ac.risk_after,
                       ac.risk_delta, ac.risk_impact, ac.reason, ac.created_at
                FROM architecture_changes ac
                JOIN customer_vendors cv ON cv.id = ac.customer_vendor_id
                WHERE ac.customer_id = %s
                ORDER BY ac.created_at DESC
                LIMIT 20
            """, (customer_id,))
            arch_changes = cur.fetchall()
            if arch_changes:
                profile.append("## Architecture Changes")
                for ac in arch_changes:
                    vendor_name, added, removed, changed, risk_before, risk_after, risk_delta, risk_impact, reason, created_at = ac
                    profile.append(
                        f"- {vendor_name} [Risk: {risk_before} → {risk_after} ({risk_delta:+d}, {risk_impact})]"
                    )
                    if added:
                        try:
                            import json as _json
                            added_list = _json.loads(added) if isinstance(added, str) else added
                            for t in added_list:
                                profile.append(f"    - Added: {t.get('technology')}")
                        except Exception:
                            profile.append(f"    - Added: {added}")
                    if changed:
                        try:
                            import json as _json
                            changed_list = _json.loads(changed) if isinstance(changed, str) else changed
                            for c in changed_list:
                                profile.append(f"    - Version: {c.get('technology')} {c.get('from_version')} → {c.get('to_version')}")
                        except Exception:
                            profile.append(f"    - Version: {changed}")
                    if removed:
                        try:
                            import json as _json
                            removed_list = _json.loads(removed) if isinstance(removed, str) else removed
                            for t in removed_list:
                                profile.append(f"    - Removed: {t.get('technology')}")
                        except Exception:
                            profile.append(f"    - Removed: {removed}")
                    if reason:
                        profile.append(f"    - Reason: {reason}")
                profile.append("")
        except Exception as e:
            logger.warning(f"Error fetching architecture changes: {e}")
            cur.connection.rollback()

    # 10. Third-Party Alerts (for "what are the most important alerts" questions)
    if intent in ['alert', 'threat', 'vendor', 'general']:
        try:
            cur.execute("""
                SELECT a.vendor, a.affected_technology, a.alert_type, a.severity,
                       a.risk_score, a.risk_delta, a.confidence, a.business_relevance,
                       a.recommended_action, a.status, a.created_at
                FROM third_party_alerts a
                WHERE a.customer_id = %s
                ORDER BY a.risk_score DESC, a.created_at DESC
                LIMIT 20
            """, (customer_id,))
            tp_alerts = cur.fetchall()
            if tp_alerts:
                profile.append("## Third-Party Alerts")
                for al in tp_alerts:
                    vendor_name, tech, alert_type, severity, risk, delta, conf, relevance, rec, status, created = al
                    tech_str = f" [{tech}]" if tech else ""
                    profile.append(
                        f"- {vendor_name}{tech_str} {alert_type} [Severity: {severity}, Risk: {risk}, "
                        f"Delta: {delta:+d}, Confidence: {conf}, Status: {status}]"
                    )
                    if relevance:
                        profile.append(f"    - Business Relevance: {relevance}")
                    if rec:
                        profile.append(f"    - Recommended Action: {rec}")
                profile.append("")
        except Exception as e:
            logger.warning(f"Error fetching third-party alerts: {e}")
            cur.connection.rollback()

    # 11. Exposures with Evidence + Recommended Actions (from correlation intelligence)
    if intent in ['threat', 'vendor', 'general', 'alert']:
        try:
            cur.execute("""
                SELECT v.vendor,
                       t.title,
                       t.cve_id,
                       e.risk_score,
                       e.priority,
                       e.affected_technology,
                       e.evidence,
                       e.recommended_action,
                       e.match_confidence
                FROM third_party_exposures e
                JOIN customer_vendors v ON e.customer_vendor_id = v.id
                LEFT JOIN threat_events t ON e.threat_event_id = t.id
                WHERE e.customer_id = %s
                ORDER BY e.risk_score DESC
                LIMIT 20
            """, (customer_id,))
            exposures = cur.fetchall()
            if exposures:
                profile.append("## Threat Exposures with Evidence")
                for ex in exposures:
                    vendor_name, title, cve_id, risk, priority, tech, evidence, rec_action, conf = ex
                    cve = f" ({cve_id})" if cve_id else ""
                    tech_str = f" [Technology: {tech}]" if tech else ""
                    profile.append(
                        f"- {vendor_name} exposed to {title}{cve} [Risk: {risk}, Priority: {priority}]{tech_str}"
                    )
                    if evidence:
                        try:
                            import json as _json
                            if isinstance(evidence, str):
                                evidence_list = _json.loads(evidence)
                            else:
                                evidence_list = evidence
                            for ev in evidence_list:
                                profile.append(f"    - Evidence: {ev}")
                        except Exception:
                            profile.append(f"    - Evidence: {evidence}")
                    if rec_action:
                        profile.append(f"    - Recommended Action: {rec_action}")
                    if conf is not None:
                        profile.append(f"    - Confidence: {conf}%")
                profile.append("")

            # Exposures with affected technology (for CVE-to-vendor answers)
            cur.execute("""
                SELECT DISTINCT t.cve_id, v.vendor, e.affected_technology, e.risk_score
                FROM third_party_exposures e
                JOIN threat_events t ON t.id = e.threat_event_id
                JOIN customer_vendors v ON v.id = e.customer_vendor_id
                WHERE e.customer_id = %s AND e.affected_technology IS NOT NULL AND t.cve_id IS NOT NULL
                ORDER BY e.risk_score DESC
                LIMIT 20
            """, (customer_id,))
            cve_tech_matches = cur.fetchall()
            if cve_tech_matches:
                profile.append("## CVE to Vendor Technology Matches")
                for cm in cve_tech_matches:
                    profile.append(
                        f"- {cm[0]} affects {cm[2]} at vendor {cm[1]} [Risk Score: {cm[3]}]"
                    )
                profile.append("")
        except Exception as e:
            # Column may not exist on older databases
            logger.warning(f"Error fetching exposure intelligence (columns may not exist yet): {e}")
            cur.connection.rollback()

    # 11. Third-Party SOC Alerts (continuous monitoring layer)
    if intent in ['alert', 'vendor', 'threat', 'general']:
        try:
            cur.execute("""
                SELECT vendor, alert_type, severity, affected_technology,
                       risk_score, risk_delta, confidence, evidence,
                       business_relevance, recommended_action, status, created_at
                FROM third_party_alerts
                WHERE customer_id = %s
                ORDER BY risk_score DESC, created_at DESC
                LIMIT 25
            """, (customer_id,))
            tp_alerts = cur.fetchall()
            if tp_alerts:
                profile.append("## Third-Party SOC Alerts")
                for al in tp_alerts:
                    vendor_name, alert_type, severity, tech, risk, risk_delta, conf, evidence, relevance, rec_action, status, created_at = al
                    tech_str = f" [{tech}]" if tech else ""
                    profile.append(
                        f"- {vendor_name}{tech_str}: {alert_type} [Severity: {severity}, Risk: {risk}, Status: {status}]"
                    )
                    if relevance:
                        profile.append(f"    - Business Relevance: {relevance}")
                    if evidence:
                        try:
                            import json as _json
                            evidence_list = _json.loads(evidence) if isinstance(evidence, str) else evidence
                            for ev in evidence_list:
                                profile.append(f"    - Evidence: {ev}")
                        except Exception:
                            profile.append(f"    - Evidence: {evidence}")
                    if rec_action:
                        profile.append(f"    - Recommended Action: {rec_action}")
                    if conf is not None:
                        profile.append(f"    - Confidence: {int(conf * 100)}%")
                profile.append("")

            # Weekly summary for posture-change questions
            cur.execute("""
                SELECT COUNT(*) FROM third_party_alerts
                WHERE customer_id = %s AND created_at >= NOW() - INTERVAL '7 days'
            """, (customer_id,))
            week_count = cur.fetchone()[0]
            if week_count:
                profile.append(f"## Third-Party Alerts This Week: {week_count}")

            cur.execute("""
                SELECT vendor, risk_score, alert_type, affected_technology
                FROM third_party_alerts
                WHERE customer_id = %s AND severity = 'CRITICAL' AND status = 'NEW'
                ORDER BY risk_score DESC
                LIMIT 10
            """, (customer_id,))
            critical_alerts = cur.fetchall()
            if critical_alerts:
                profile.append("## Critical Third-Party Alerts (New)")
                for ca in critical_alerts:
                    tech_str = f" / {ca[3]}" if ca[3] else ""
                    profile.append(f"- {ca[0]}{tech_str}: {ca[2]} [Risk: {ca[1]}]")
                profile.append("")
        except Exception as e:
            logger.warning(f"Error fetching third_party_alerts: {e}")
            cur.connection.rollback()

    # 12. Data Breach Intelligence (third-party exposure monitoring)
    if intent in ['threat', 'vendor', 'general', 'alert']:
        try:
            # Breach exposures correlated to this customer's vendors
            cur.execute("""
                SELECT DISTINCT v.vendor,
                       te.title,
                       te.severity,
                       te.confidence,
                       te.published_date,
                       te.source_url,
                       te.raw_metadata,
                       e.risk_score,
                       e.priority,
                       e.acknowledged,
                       e.created_at
                FROM third_party_exposures e
                JOIN customer_vendors v ON e.customer_vendor_id = v.id
                JOIN threat_events te ON e.threat_event_id = te.id
                WHERE e.customer_id = %s
                  AND te.source_type = 'breach_report'
                ORDER BY te.published_date DESC NULLS LAST, e.risk_score DESC
                LIMIT 20
            """, (customer_id,))
            breach_exposures = cur.fetchall()
            if breach_exposures:
                profile.append("## Data Breach Intelligence (Third-Party Exposure)")
                for b in breach_exposures:
                    vendor_name, title, severity, conf, published, source_url, raw_meta, risk, priority, ack, created = b
                    date_str = published.strftime("%Y-%m-%d") if published else "Unknown"
                    ack_str = "ACKNOWLEDGED" if ack else "NEW"
                    profile.append(
                        f"- {vendor_name} affected by '{title}' [Severity: {severity}, "
                        f"Risk: {risk}, Priority: {priority}, Breach Date: {date_str}, "
                        f"Status: {ack_str}]"
                    )
                    # Exposed data types from raw_metadata
                    if raw_meta:
                        try:
                            import json as _json
                            raw = _json.loads(raw_meta) if isinstance(raw_meta, str) else raw_meta
                            data_types = raw.get("data_types") or []
                            if data_types:
                                profile.append(f"    - Exposed Data Types: {', '.join(data_types)}")
                            source = raw.get("source") or "breach source"
                            profile.append(f"    - Source: {source}")
                            if raw.get("severity_source") == "inferred":
                                profile.append("    - Note: Severity inferred from breach metadata (not source-provided)")
                        except Exception:
                            pass
                    if source_url:
                        profile.append(f"    - Reference: {source_url}")
                profile.append("")

            # Summary counts for "how many breaches" questions
            cur.execute("""
                SELECT COUNT(DISTINCT te.id)
                FROM third_party_exposures e
                JOIN threat_events te ON e.threat_event_id = te.id
                WHERE e.customer_id = %s AND te.source_type = 'breach_report'
            """, (customer_id,))
            breach_count = cur.fetchone()[0]
            if breach_count:
                profile.append(f"## Total Data Breaches Affecting Third Parties: {breach_count}")

            # Highest-risk breach questions
            cur.execute("""
                SELECT DISTINCT v.vendor, te.title, te.severity, e.risk_score
                FROM third_party_exposures e
                JOIN customer_vendors v ON e.customer_vendor_id = v.id
                JOIN threat_events te ON e.threat_event_id = te.id
                WHERE e.customer_id = %s AND te.source_type = 'breach_report'
                ORDER BY e.risk_score DESC
                LIMIT 5
            """, (customer_id,))
            top_risks = cur.fetchall()
            if top_risks:
                profile.append("## Highest-Risk Breach Exposures")
                for tr in top_risks:
                    profile.append(f"- {tr[0]} / {tr[1]} [Severity: {tr[2]}, Risk: {tr[3]}]")
                profile.append("")
        except Exception as e:
            logger.warning(f"Error fetching data breach intelligence: {e}")
            cur.connection.rollback()

    return "\n".join(profile)
