"""
Vendor Architecture Document Processor.

Connects the existing Architecture Intelligence extraction pipeline
(DocumentProcessor + TechnologyExtractor) with third_party_profiles.

Flow:
    Uploaded architecture document (documents table)
        -> DocumentProcessor.extract_text(file_path, file_type)
        -> TechnologyExtractor.extract_from_text(text, filename)
        -> third_party_profile (find/create for customer_vendor_id)
        -> third_party_profile_technologies (upsert)
        -> third_party_profile_services (derived)
        -> refresh profile risk
"""
import logging
import os
import json
from typing import Dict, Any, List, Optional

from app.database.connection import get_connection
from app.document_processor import DocumentProcessor
from app.ai.technology_extractor import TechnologyExtractor

logger = logging.getLogger(__name__)

# Map technology categories to service types for vendor profiles
CATEGORY_TO_SERVICE_TYPE = {
    "cloud_provider": "Cloud Service",
    "web_server": "Web Service",
    "database": "Data Service",
    "security_tools": "Security Service",
    "monitoring": "Monitoring Service",
    "container": "Container Service",
    "devops": "DevOps Service",
    "network_devices": "Network Service",
    "other": "Managed Service",
}

# Well-known SaaS / managed services that should be recorded as services too
SAAS_SERVICE_KEYWORDS = [
    "microsoft 365", "office 365", "azure ad", "aws", "amazon web services",
    "google cloud", "salesforce", "servicenow", "workday", "okta",
    "active directory", "exchange online", "sharepoint online", "teams",
    "auto", "sap", "oracle cloud", "dropbox", "slack", "zoom",
]


def _is_service_like(tech_name: str, category: str) -> bool:
    """Determine if a technology should also be represented as a vendor service."""
    name_lower = (tech_name or "").lower().strip()
    if not name_lower:
        return False

    # Cloud providers / SaaS platforms are almost always services
    if category == "cloud_provider":
        return True

    for keyword in SAAS_SERVICE_KEYWORDS:
        if keyword in name_lower:
            return True

    return False


def _load_document(conn, cur, document_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """Load a document row and verify tenant ownership."""
    cur.execute("""
        SELECT id, filename, file_type, file_path, extraction_status, customer_id
        FROM documents
        WHERE id = %s AND customer_id = %s
    """, (document_id, customer_id))
    row = cur.fetchone()
    if not row:
        return None
    return {
        "id": row[0],
        "filename": row[1],
        "file_type": row[2],
        "file_path": row[3],
        "extraction_status": row[4],
        "customer_id": row[5],
    }


def _find_or_create_profile(cur, customer_vendor_id: int) -> int:
    """Find an existing profile for the relationship or create one."""
    cur.execute(
        "SELECT id FROM third_party_profiles WHERE customer_vendor_id = %s",
        (customer_vendor_id,),
    )
    row = cur.fetchone()
    if row:
        return row[0]

    cur.execute("""
        INSERT INTO third_party_profiles (customer_vendor_id)
        VALUES (%s)
        RETURNING id
    """, (customer_vendor_id,))
    return cur.fetchone()[0]


def _upsert_technology(cur, profile_id: int, tech: Dict[str, Any]) -> bool:
    """Upsert a technology into third_party_profile_technologies.

    Returns True if a new row was inserted, False if skipped (duplicate).
    """
    technology = (tech.get("technology") or "").strip()
    if not technology:
        return False

    version = (tech.get("version") or "unknown").strip() or "unknown"
    category = (tech.get("category") or "other").lower()
    source = "architecture_document"

    # Dedup: same profile + technology + version already mapped
    cur.execute("""
        SELECT id FROM third_party_profile_technologies
        WHERE profile_id = %s AND technology = %s AND version = %s
    """, (profile_id, technology, version))
    if cur.fetchone():
        return False

    cur.execute("""
        INSERT INTO third_party_profile_technologies
            (profile_id, technology, version, category, source)
        VALUES (%s, %s, %s, %s, %s)
    """, (profile_id, technology, version, category, source))
    return True


def _upsert_service(cur, profile_id: int, service_name: str, service_type: str) -> bool:
    """Upsert a service into third_party_profile_services."""
    service_name = (service_name or "").strip()
    if not service_name:
        return False

    cur.execute("""
        SELECT id FROM third_party_profile_services
        WHERE profile_id = %s AND service_name = %s
    """, (profile_id, service_name))
    if cur.fetchone():
        return False

    cur.execute("""
        INSERT INTO third_party_profile_services
            (profile_id, service_name, service_type, criticality)
        VALUES (%s, %s, %s, 'MEDIUM')
    """, (profile_id, service_name, service_type))
    return True


def _load_profile_technologies(cur, profile_id: int) -> List[Dict[str, Any]]:
    """Load the current technologies mapped to a profile."""
    cur.execute("""
        SELECT technology, version, category
        FROM third_party_profile_technologies
        WHERE profile_id = %s
    """, (profile_id,))
    return [
        {"technology": r[0], "version": r[1], "category": r[2]}
        for r in cur.fetchall()
    ]


def _load_profile_services(cur, profile_id: int) -> List[Dict[str, Any]]:
    """Load the current services mapped to a profile."""
    cur.execute("""
        SELECT service_name, service_type
        FROM third_party_profile_services
        WHERE profile_id = %s
    """, (profile_id,))
    return [
        {"service_name": r[0], "service_type": r[1]}
        for r in cur.fetchall()
    ]


def _apply_diff_to_profile(cur, profile_id: int, diff: Dict[str, Any]) -> Dict[str, int]:
    """Apply the architecture diff to the profile.

    - Upsert added technologies
    - Update versions for changed technologies
    - Remove technologies no longer present
    - Add/remove services

    Returns counts of operations performed.
    """
    counts = {"added": 0, "removed": 0, "version_changed": 0, "services_added": 0, "services_removed": 0}

    # 1. Add new technologies
    for tech in diff.get("added_technologies", []):
        if _upsert_technology(cur, profile_id, tech):
            counts["added"] += 1

    # 2. Update versions for changed technologies
    for change in diff.get("changed_versions", []):
        tech_name = change.get("technology")
        new_version = change.get("to_version")
        if not tech_name:
            continue
        cur.execute("""
            UPDATE third_party_profile_technologies
            SET version = %s, updated_at = CURRENT_TIMESTAMP
            WHERE profile_id = %s AND technology = %s
        """, (new_version, profile_id, tech_name))
        if cur.rowcount:
            counts["version_changed"] += 1

    # 3. Remove technologies no longer present
    for tech in diff.get("removed_technologies", []):
        tech_name = tech.get("technology")
        if not tech_name:
            continue
        cur.execute("""
            DELETE FROM third_party_profile_technologies
            WHERE profile_id = %s AND technology = %s
        """, (profile_id, tech_name))
        if cur.rowcount:
            counts["removed"] += 1

    # 4. Add new services
    for svc in diff.get("added_services", []):
        if _upsert_service(cur, profile_id, svc.get("service_name"), svc.get("service_type") or "Managed Service"):
            counts["services_added"] += 1

    # 5. Remove services no longer present
    for svc in diff.get("removed_services", []):
        svc_name = svc.get("service_name")
        if not svc_name:
            continue
        cur.execute("""
            DELETE FROM third_party_profile_services
            WHERE profile_id = %s AND service_name = %s
        """, (profile_id, svc_name))
        if cur.rowcount:
            counts["services_removed"] += 1

    return counts


def _record_architecture_change(
    cur,
    customer_id: int,
    customer_vendor_id: int,
    profile_id: int,
    previous_document_id: Optional[int],
    current_document_id: int,
    diff: Dict[str, Any],
    risk_before: int,
    risk_after: int,
    reason: str,
) -> int:
    """Insert a structured architecture change event. Returns the change id."""
    risk_delta = risk_after - risk_before
    if risk_delta >= 30:
        risk_impact = "CRITICAL"
    elif risk_delta >= 20:
        risk_impact = "HIGH"
    elif risk_delta >= 10:
        risk_impact = "MEDIUM"
    elif risk_delta > 0:
        risk_impact = "LOW"
    else:
        risk_impact = "NONE"

    cur.execute("""
        INSERT INTO architecture_changes (
            customer_id, customer_vendor_id, profile_id,
            previous_document_id, current_document_id,
            added_technologies, removed_technologies, changed_versions,
            added_services, removed_services,
            risk_before, risk_after, risk_delta, risk_impact, reason
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (
        customer_id, customer_vendor_id, profile_id,
        previous_document_id, current_document_id,
        json.dumps(diff.get("added_technologies", [])),
        json.dumps(diff.get("removed_technologies", [])),
        json.dumps(diff.get("changed_versions", [])),
        json.dumps(diff.get("added_services", [])),
        json.dumps(diff.get("removed_services", [])),
        risk_before, risk_after, risk_delta, risk_impact, reason,
    ))
    return cur.fetchone()[0]


def _correlate_new_technologies(cur, customer_id, customer_vendor_id, profile_id, vendor_id, added_technologies):
    """Re-run threat correlation for newly added technologies.

    For each added technology, find matching threat_events and create
    third_party_exposures if they don't already exist.
    """
    from app.risk.third_party_profile_risk import refresh_profile_risk

    exposures_created = 0
    for tech in added_technologies:
        tech_name = (tech.get("technology") or "").strip()
        if not tech_name:
            continue

        # Find threat events matching this technology
        cur.execute("""
            SELECT id, title, cve_id, severity, description
            FROM threat_events
            WHERE correlated = TRUE
              AND (
                array_to_string(affected_technologies, ' ') ILIKE %s
                OR title ILIKE %s
                OR description ILIKE %s
              )
            ORDER BY severity DESC
            LIMIT 10
        """, (f'%{tech_name}%', f'%{tech_name}%', f'%{tech_name}%'))
        matches = cur.fetchall()

        for m in matches:
            event_id, title, cve_id, severity, description = m

            # Check if exposure already exists
            cur.execute("""
                SELECT 1 FROM third_party_exposures
                WHERE threat_event_id = %s AND customer_id = %s AND vendor_id = %s
                LIMIT 1
            """, (event_id, customer_id, vendor_id))
            if cur.fetchone():
                continue

            # Build evidence
            evidence = [
                f"{tech_name} newly added to vendor architecture",
                f"Threat: {title}",
            ]
            if severity and severity.upper() == "CRITICAL":
                evidence.append("Critical vulnerability severity")
            if cve_id:
                evidence.append(f"CVE: {cve_id}")

            # Build recommended action
            recommended_action = f"Review newly discovered {tech_name} and validate its exposure"
            if cve_id:
                recommended_action = f"Apply patch for {cve_id} on {tech_name} and monitor authentication logs"

            # Insert exposure
            cur.execute("""
                INSERT INTO third_party_exposures (
                    threat_event_id, customer_id, vendor_id, customer_vendor_id,
                    match_type, match_confidence, matched_text,
                    base_severity, cvss_score,
                    risk_score, risk_factors, priority, soc_guidance,
                    profile_id, affected_technology, evidence, recommended_action,
                    acknowledged, muted, created_at, updated_at
                ) VALUES (
                    %s, %s, %s, %s,
                    'architecture_change', 85, %s,
                    %s, NULL,
                    70, '{}', 'HIGH', '{}',
                    %s, %s, %s, %s,
                    FALSE, FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                )
            """, (
                event_id, customer_id, vendor_id, customer_vendor_id,
                tech_name,
                severity or "UNKNOWN",
                profile_id, tech_name,
                json.dumps(evidence), recommended_action,
            ))
            exposures_created += 1

    # Refresh risk after new exposures
    if exposures_created:
        try:
            refresh_profile_risk(profile_id)
        except Exception as e:
            logger.warning("Failed to refresh profile risk after correlation: %s", e)

    return exposures_created


def process_vendor_architecture(
    customer_vendor_id: int,
    document_id: int,
    customer_id: int,
) -> Dict[str, Any]:
    """Extract technologies/services from a vendor architecture document.

    Reuses DocumentProcessor + TechnologyExtractor, then maps the extracted
    technologies into the vendor's third_party_profile.

    Detects architecture changes vs the previous document, records a change
    event, re-runs threat correlation for newly added technologies, and
    refreshes the profile risk.

    Returns a summary dict with counts of inserted technologies/services.
    """
    conn = get_connection()
    cur = conn.cursor()
    try:
        # 1. Load the document (tenant-checked)
        document = _load_document(conn, cur, document_id, customer_id)
        if not document:
            raise ValueError(f"Document {document_id} not found for customer {customer_id}")

        file_path = document["file_path"]
        file_type = document["file_type"]
        filename = document["filename"]

        # 2. Ensure the file still exists on disk
        if not os.path.exists(file_path):
            logger.warning("Document file missing at %s - attempting fallback lookup", file_path)
            raise ValueError(f"Document file missing at {file_path}")

        # 3. Extract text using existing DocumentProcessor
        processor = DocumentProcessor()
        text_content = processor.extract_text(file_path, file_type)
        if not text_content or len(text_content.strip()) < 10:
            raise ValueError("Could not extract sufficient text from the architecture document")

        # 4. Extract technologies using existing TechnologyExtractor
        extractor = TechnologyExtractor()
        result = extractor.extract_from_text(text_content, filename)

        if result.get("status") == "failed":
            raise ValueError(result.get("reason", "Technology extraction failed"))

        assets = result.get("assets", [])

        # 5. Find or create the third-party profile
        profile_id = _find_or_create_profile(cur, customer_vendor_id)

        # 6. Load previous state for change detection
        previous_technologies = _load_profile_technologies(cur, profile_id)
        previous_services = _load_profile_services(cur, profile_id)

        # Get previous document id + risk before
        cur.execute("SELECT document_id, risk_score FROM third_party_profiles WHERE id = %s", (profile_id,))
        profile_row = cur.fetchone()
        previous_document_id = profile_row[0] if profile_row else None
        risk_before = profile_row[1] if profile_row else 0

        # 7. Derive services from the new assets
        new_services = []
        service_names = set()
        for asset in assets:
            tech_name = asset.get("technology")
            category = (asset.get("category") or "other").lower()
            if _is_service_like(tech_name, category):
                svc = tech_name or ""
                if svc and svc not in service_names:
                    service_names.add(svc)
                    new_services.append({
                        "service_name": svc,
                        "service_type": CATEGORY_TO_SERVICE_TYPE.get(category, "Managed Service"),
                    })

        # 8. Compute the diff between previous and current footprints
        from app.risk.vendor_architecture_diff import compare_architectures, has_changes
        diff = compare_architectures(
            previous_technologies=previous_technologies,
            current_technologies=assets,
            previous_services=previous_services,
            current_services=new_services,
        )

        # 9. Apply the diff to the profile (upsert/update/remove)
        counts = _apply_diff_to_profile(cur, profile_id, diff)

        # 10. Update the profile with the new document link
        cur.execute("""
            UPDATE third_party_profiles
            SET document_id = %s, updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (document_id, profile_id))

        conn.commit()

        # 11. Refresh risk after technology mapping
        from app.risk.third_party_profile_risk import refresh_profile_risk
        risk = None
        try:
            risk = refresh_profile_risk(profile_id)
        except Exception as e:
            logger.warning("Failed to refresh profile risk for %s: %s", profile_id, e)

        risk_after = risk["risk_score"] if risk else risk_before

        # 12. Record the architecture change event (if any changes)
        change_id = None
        if has_changes(diff):
            reason_parts = []
            if diff.get("added_technologies"):
                reason_parts.append(f"{len(diff['added_technologies'])} new technology(ies)")
            if diff.get("changed_versions"):
                reason_parts.append(f"{len(diff['changed_versions'])} version change(s)")
            if diff.get("removed_technologies"):
                reason_parts.append(f"{len(diff['removed_technologies'])} technology removal(s)")
            reason = "Architecture document updated: " + ", ".join(reason_parts) if reason_parts else "Architecture document updated"

            change_id = _record_architecture_change(
                cur,
                customer_id=customer_id,
                customer_vendor_id=customer_vendor_id,
                profile_id=profile_id,
                previous_document_id=previous_document_id,
                current_document_id=document_id,
                diff=diff,
                risk_before=risk_before,
                risk_after=risk_after,
                reason=reason,
            )
            conn.commit()

        # 13. Re-run threat correlation for newly added technologies
        exposures_created = 0
        if diff.get("added_technologies"):
            # Get vendor_id for correlation
            cur.execute("SELECT vendor_id FROM customer_vendors WHERE id = %s", (customer_vendor_id,))
            vendor_row = cur.fetchone()
            vendor_id = vendor_row[0] if vendor_row else None
            if vendor_id:
                exposures_created = _correlate_new_technologies(
                    cur, customer_id, customer_vendor_id, profile_id, vendor_id,
                    diff.get("added_technologies", []),
                )
                conn.commit()

        # 14. Generate third-party alerts from new exposures / architecture changes
        alerts_created = 0
        try:
            from app.correlation.third_party_alert_engine import run_alert_engine
            alert_result = run_alert_engine(limit=100)
            alerts_created = alert_result.get("total_created", 0)
        except Exception:
            logger.warning("Third-party alert engine failed after architecture processing", exc_info=True)

        return {
            "profile_id": profile_id,
            "document_id": document_id,
            "technologies_extracted": len(assets),
            "technologies_added": counts["added"],
            "technologies_removed": counts["removed"],
            "version_changes": counts["version_changed"],
            "services_added": counts["services_added"],
            "services_removed": counts["services_removed"],
            "change_id": change_id,
            "diff": diff,
            "exposures_created": exposures_created,
            "alerts_created": alerts_created,
            "risk_before": risk_before,
            "risk_after": risk_after,
            "risk": risk,
        }

    except Exception:
        conn.rollback()
        logger.exception("Vendor architecture processing failed")
        raise
    finally:
        cur.close()
        conn.close()
