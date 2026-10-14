from app.database.connection import get_connection
import json

def calculate_profile_risk(profile_id):
    """
    Compute explainable risk score for a third-party profile.
    
    Scoring factors (cumulative, max 100):
    - Critical vendor relationship: +30
    - High relationship: +20
    - Privileged access: +20
    - Sensitive data access: +15
    - Internet exposed assets: +20
    - Critical CVE affecting mapped technology: +30
    - Known exploitation: +20
    - Ransomware/extortion relevance: +25
    """
    conn = get_connection()
    cur = conn.cursor()
    
    # 1. Base profile attributes
    cur.execute("""
        SELECT p.criticality, p.privileged_access, p.data_access_level, p.customer_vendor_id,
               (SELECT count(*) FROM third_party_external_assets x 
                WHERE x.profile_id = p.id AND x.exposure_status ILIKE '%%exposed%%'),
               (SELECT count(*) FROM third_party_profile_technologies t 
                WHERE t.profile_id = p.id)
        FROM third_party_profiles p WHERE p.id = %s
    """, (profile_id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return None

    criticality, privileged, data_access, cv_id, exposed_count, tech_count = row
    score = 0
    reasons = []
    evidence = []
    confidence = 0.75

    # --- Relationship criticality ---
    crit_score = {'CRITICAL': 30, 'HIGH': 20, 'MEDIUM': 10, 'LOW': 0}.get(
        (criticality or 'MEDIUM').upper(), 10
    )
    score += crit_score
    if crit_score >= 30:
        reasons.append('Critical vendor relationship')
        evidence.append('Vendor relationship is CRITICAL')
    elif crit_score >= 20:
        reasons.append('High vendor relationship')
        evidence.append('Vendor relationship is HIGH')

    # --- Privileged access ---
    if privileged:
        score += 20
        reasons.append('Vendor has privileged access')
        evidence.append('Vendor has privileged access')

    # --- Sensitive data access ---
    if data_access and data_access.upper() not in ('NONE', 'LOW'):
        score += 15
        reasons.append('Vendor has sensitive data access')
        evidence.append(f'Data access level: {data_access}')

    # --- Internet exposed assets ---
    if exposed_count:
        score += 20
        reasons.append('Internet exposed assets detected')
        evidence.append(f'{exposed_count} internet-exposed asset(s)')

    # --- CVE / Threat matching against mapped technologies ---
    threat_evidence = _get_threat_matches(cur, profile_id, cv_id)
    for t in threat_evidence:
        if t['type'] == 'critical_cve':
            score += 30
            reasons.append('Critical vulnerability affects mapped technology')
            evidence.append(t['detail'])
        if t['type'] == 'exploitation':
            score += 20
            reasons.append('Known exploitation reported')
            evidence.append(t['detail'])
        if t['type'] == 'ransomware':
            score += 25
            reasons.append('Ransomware/extortion relevance')
            evidence.append(t['detail'])
        if t.get('confidence'):
            confidence = max(confidence, t['confidence'])

    # Cap at 100
    score = min(100, score)

    # Severity
    if score >= 90:
        severity = 'CRITICAL'
    elif score >= 70:
        severity = 'HIGH'
    elif score >= 40:
        severity = 'MEDIUM'
    else:
        severity = 'LOW'

    # Update profile
    cur.execute(
        "UPDATE third_party_profiles SET risk_score = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
        (score, profile_id)
    )
    conn.commit()
    cur.close()
    conn.close()

    return {
        'risk_score': score,
        'severity': severity,
        'confidence': round(confidence, 2),
        'reasons': reasons,
        'evidence': evidence,
    }


def _get_threat_matches(cur, profile_id, customer_vendor_id):
    """Query threat_events that match the profile's technologies."""
    results = []

    # Get technologies mapped to this profile
    cur.execute("""
        SELECT technology, version, category
        FROM third_party_profile_technologies
        WHERE profile_id = %s
    """, (profile_id,))
    technologies = cur.fetchall()

    if not technologies:
        return results

    # Build technology patterns for matching
    tech_names = [t[0].lower() for t in technologies if t[0]]

    for tech_name in tech_names:
        # Match threat events where affected_technologies, title, or description
        # contain the technology name
        cur.execute("""
            SELECT id, title, cve_id, severity, description, source_type,
                   iocs, affected_technologies
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
            event_id, title, cve_id, severity, description, source_type, iocs, affected_techs = m
            sev = (severity or 'UNKNOWN').upper()

            type_tags = []
            if sev == 'CRITICAL':
                type_tags.append('critical_cve')
            if cve_id or source_type == 'cve':
                type_tags.append('critical_cve')

            # Check for exploitation keywords
            desc_text = (description or '') + ' ' + (title or '')
            desc_lower = desc_text.lower()
            if any(k in desc_lower for k in ['exploit', 'exploitation', 'exploited', 'metasploit', 'poc', 'proof of concept', 'weaponized']):
                type_tags.append('exploitation')

            # Check for ransomware/extortion
            if any(k in desc_lower for k in ['ransomware', 'extortion', 'ransom', 'lockbit', 'blackcat', 'clop', 'hive']):
                type_tags.append('ransomware')

            if not type_tags:
                # Still add as a general threat match if critical
                if sev == 'CRITICAL':
                    type_tags.append('critical_cve')
                else:
                    continue

            for tag in set(type_tags):
                results.append({
                    'type': tag,
                    'event_id': event_id,
                    'cve_id': cve_id,
                    'title': title,
                    'severity': sev,
                    'detail': f'{title or "Threat"} affecting {tech_name} (Severity: {sev})',
                    'confidence': 0.85 if sev == 'CRITICAL' else 0.70,
                })

    return results


def refresh_profile_risk(profile_id):
    """Refresh risk score for a profile and return the result."""
    return calculate_profile_risk(profile_id)