from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from app.auth.deps import get_current_user, require_roles
from app.database.connection import get_connection
from app.risk.third_party_profile_risk import calculate_profile_risk, refresh_profile_risk

router = APIRouter(tags=['Third Party Profiles'])


class Profile(BaseModel):
    business_role: Optional[str] = None
    description: Optional[str] = None
    data_access_level: Optional[str] = None
    privileged_access: bool = False
    criticality: str = 'MEDIUM'


class Item(BaseModel):
    technology: Optional[str] = None
    version: Optional[str] = None
    category: Optional[str] = None
    source: Optional[str] = None
    service_name: Optional[str] = None
    service_type: Optional[str] = None
    asset_type: Optional[str] = None
    value: Optional[str] = None
    exposure_status: Optional[str] = None
    last_seen: Optional[str] = None


def _profile(profile_id, user):
    """Tenant-ownership check: profile -> customer_vendor -> customer_id -> user."""
    c = get_connection()
    q = c.cursor()
    q.execute('''
        SELECT p.id FROM third_party_profiles p
        JOIN customer_vendors cv ON cv.id = p.customer_vendor_id
        WHERE p.id = %s AND cv.customer_id = %s
    ''', (profile_id, user['customer_id']))
    r = q.fetchone()
    q.close()
    c.close()
    if not r:
        raise HTTPException(404, 'Profile not found')


def _get_profile_id_for_relationship(customer_id, vendor_id):
    """Resolve (customer, vendor relationship) -> profile id, or None."""
    c = get_connection()
    q = c.cursor()
    q.execute('''
        SELECT p.id
        FROM customer_vendors cv
        LEFT JOIN third_party_profiles p ON p.customer_vendor_id = cv.id
        WHERE cv.id = %s AND cv.customer_id = %s
    ''', (vendor_id, customer_id))
    r = q.fetchone()
    q.close()
    c.close()
    return r[0] if r else None


def _get_vendor_relationship(customer_id, vendor_id):
    """Return the customer_vendors row (or None)."""
    c = get_connection()
    q = c.cursor()
    q.execute('''
        SELECT cv.id, cv.customer_id, cv.vendor, cv.relationship_type,
               cv.data_sensitivity, cv.criticality, cv.base_risk_score,
               cv.sla_penalty_risk, cv.regulatory_flags, cv.incident_count,
               v.name, v.id
        FROM customer_vendors cv
        LEFT JOIN vendors v ON v.id = cv.vendor_id
        WHERE cv.id = %s AND cv.customer_id = %s
    ''', (vendor_id, customer_id))
    row = q.fetchone()
    q.close()
    c.close()
    if not row:
        return None
    return {
        'id': row[0],
        'customer_id': row[1],
        'vendor': row[2],
        'relationship_type': row[3],
        'data_sensitivity': row[4],
        'criticality': row[5],
        'base_risk_score': row[6],
        'sla_penalty_risk': row[7],
        'regulatory_flags': row[8],
        'incident_count': row[9],
        'vendor_name': row[10],
        'vendor_id': row[11],
    }


@router.post('/api/customers/{customer_id}/vendors/{vendor_id}/profile')
@router.put('/api/customers/{customer_id}/vendors/{vendor_id}/profile')
def save(customer_id: int, vendor_id: int, data: Profile, user: dict = Depends(require_roles('Admin'))):
    if customer_id != user['customer_id']:
        raise HTTPException(403, 'Not authorized')

    c = get_connection()
    q = c.cursor()
    q.execute('SELECT id FROM customer_vendors WHERE id = %s AND customer_id = %s', (vendor_id, customer_id))
    if not q.fetchone():
        q.close()
        c.close()
        raise HTTPException(404, 'Vendor relationship not found')

    q.execute('''
        INSERT INTO third_party_profiles
            (customer_vendor_id, business_role, description, data_access_level,
             privileged_access, criticality)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (customer_vendor_id) DO UPDATE SET
            business_role = EXCLUDED.business_role,
            description = EXCLUDED.description,
            data_access_level = EXCLUDED.data_access_level,
            privileged_access = EXCLUDED.privileged_access,
            criticality = EXCLUDED.criticality
        RETURNING id
    ''', (vendor_id, data.business_role, data.description, data.data_access_level,
          data.privileged_access, data.criticality))
    pid = q.fetchone()[0]
    c.commit()
    q.close()
    c.close()

    # Refresh risk after profile update
    risk = refresh_profile_risk(pid)
    return {'profile_id': pid, 'risk': risk}


@router.get('/api/customers/{customer_id}/vendors/{vendor_id}/profile')
def get_profile(customer_id: int, vendor_id: int, user: dict = Depends(get_current_user)):
    if customer_id != user['customer_id']:
        raise HTTPException(403, 'Not authorized')

    relationship = _get_vendor_relationship(customer_id, vendor_id)
    if not relationship:
        raise HTTPException(404, 'Vendor relationship not found')

    pid = _get_profile_id_for_relationship(customer_id, vendor_id)

    if not pid:
        return {
            'vendor': relationship,
            'profile': None,
            'technologies': [],
            'services': [],
            'external_assets': [],
            'risk': None,
            'exposures': [],
            'alerts': [],
        }

    # Refresh risk each time GET is called so intelligence stays current
    risk = refresh_profile_risk(pid)

    c = get_connection()
    q = c.cursor()
    q.execute('''
        SELECT id, business_role, description, data_access_level,
               privileged_access, criticality, risk_score, updated_at
        FROM third_party_profiles WHERE id = %s
    ''', (pid,))
    pr = q.fetchone()

    profile = {
        'id': pr[0],
        'business_role': pr[1],
        'description': pr[2],
        'data_access_level': pr[3],
        'privileged_access': pr[4],
        'criticality': pr[5],
        'risk_score': pr[6],
        'updated_at': pr[7],
    }

    # Technologies
    q.execute('''
        SELECT id, technology, version, category, source
        FROM third_party_profile_technologies WHERE profile_id = %s
        ORDER BY id
    ''', (pid,))
    techs = [
        {'id': x[0], 'technology': x[1], 'version': x[2], 'category': x[3], 'source': x[4]}
        for x in q.fetchall()
    ]

    # Services
    q.execute('''
        SELECT id, service_name, service_type, criticality
        FROM third_party_profile_services WHERE profile_id = %s
        ORDER BY id
    ''', (pid,))
    services = [
        {'id': x[0], 'service_name': x[1], 'service_type': x[2], 'criticality': x[3]}
        for x in q.fetchall()
    ]

    # External assets
    q.execute('''
        SELECT id, asset_type, value, exposure_status, last_seen
        FROM third_party_external_assets WHERE profile_id = %s
        ORDER BY id
    ''', (pid,))
    external_assets = [
        {'id': x[0], 'asset_type': x[1], 'value': x[2], 'exposure_status': x[3], 'last_seen': x[4]}
        for x in q.fetchall()
    ]

    # Active exposures for this customer+vendor
    q.execute('''
        SELECT e.id, te.id AS threat_event_id, te.title, te.cve_id, te.severity,
               e.risk_score, e.priority, e.match_type, e.match_confidence,
               e.matched_text, e.soc_guidance, e.risk_factors, e.created_at,
               e.affected_technology, e.evidence, e.recommended_action
        FROM third_party_exposures e
        JOIN threat_events te ON te.id = e.threat_event_id
        WHERE e.customer_id = %s AND e.vendor_id = %s
        ORDER BY e.risk_score DESC, e.created_at DESC
        LIMIT 50
    ''', (customer_id, relationship['vendor_id']))
    exposures = []
    for x in q.fetchall():
        exposures.append({
            'id': x[0],
            'threat_event_id': x[1],
            'title': x[2],
            'cve_id': x[3],
            'severity': x[4],
            'risk_score': x[5],
            'priority': x[6],
            'match_type': x[7],
            'match_confidence': x[8],
            'matched_text': x[9],
            'soc_guidance': x[10],
            'risk_factors': x[11],
            'created_at': x[12],
            'affected_technology': x[13],
            'evidence': x[14],
            'recommended_action': x[15],
        })

    # Third-party SOC alerts for this vendor
    q.execute('''
        SELECT id, alert_type, severity, affected_technology, vendor,
               risk_score, risk_delta, confidence, confidence_reasons,
               evidence, business_relevance, recommended_action, status, created_at
        FROM third_party_alerts
        WHERE customer_id = %s AND customer_vendor_id = %s
        ORDER BY created_at DESC, risk_score DESC
        LIMIT 20
    ''', (customer_id, vendor_id))
    tp_alerts = []
    for x in q.fetchall():
        tp_alerts.append({
            'id': x[0],
            'alert_type': x[1],
            'severity': x[2],
            'affected_technology': x[3],
            'vendor': x[4],
            'risk_score': x[5],
            'risk_delta': x[6],
            'confidence': x[7],
            'confidence_reasons': x[8],
            'evidence': x[9],
            'business_relevance': x[10],
            'recommended_action': x[11],
            'status': x[12],
            'created_at': x[13],
        })

    # Architecture changes (most recent first)
    q.execute('''
        SELECT id, previous_document_id, current_document_id,
               added_technologies, removed_technologies, changed_versions,
               added_services, removed_services,
               risk_before, risk_after, risk_delta, risk_impact, reason, created_at
        FROM architecture_changes
        WHERE customer_id = %s AND customer_vendor_id = %s
        ORDER BY created_at DESC
        LIMIT 20
    ''', (customer_id, vendor_id))
    architecture_changes = []
    for x in q.fetchall():
        architecture_changes.append({
            'id': x[0],
            'previous_document_id': x[1],
            'current_document_id': x[2],
            'added_technologies': x[3],
            'removed_technologies': x[4],
            'changed_versions': x[5],
            'added_services': x[6],
            'removed_services': x[7],
            'risk_before': x[8],
            'risk_after': x[9],
            'risk_delta': x[10],
            'risk_impact': x[11],
            'reason': x[12],
            'created_at': x[13],
        })

    # Architecture history (all documents ever linked to this profile)
    architecture_history = []
    if pid:
        q.execute('''
            SELECT d.id, d.filename, d.file_type, d.uploaded_at, d.extraction_status
            FROM documents d
            WHERE d.id IN (
                SELECT document_id FROM third_party_profiles WHERE id = %s
                UNION
                SELECT previous_document_id FROM architecture_changes WHERE profile_id = %s
                UNION
                SELECT current_document_id FROM architecture_changes WHERE profile_id = %s
            )
            ORDER BY d.uploaded_at DESC
        ''', (pid, pid, pid))
        architecture_history = [
            {'id': x[0], 'filename': x[1], 'file_type': x[2], 'uploaded_at': x[3], 'extraction_status': x[4]}
            for x in q.fetchall()
        ]

    q.close()
    c.close()

    return {
        'vendor': relationship,
        'profile': profile,
        'technologies': techs,
        'services': services,
        'external_assets': external_assets,
        'risk': risk,
        'exposures': exposures,
        'alerts': tp_alerts,
        'third_party_alerts': tp_alerts,
        'architecture_changes': architecture_changes,
        'architecture_history': architecture_history,
    }


@router.get('/api/customers/{customer_id}/vendors/{vendor_id}/architecture')
def get_vendor_architecture(customer_id: int, vendor_id: int, user: dict = Depends(get_current_user)):
    """Return the vendor's architecture document + extracted technologies/services."""
    if customer_id != user['customer_id']:
        raise HTTPException(403, 'Not authorized')

    relationship = _get_vendor_relationship(customer_id, vendor_id)
    if not relationship:
        raise HTTPException(404, 'Vendor relationship not found')

    pid = _get_profile_id_for_relationship(customer_id, vendor_id)

    c = get_connection()
    q = c.cursor()

    # Document info
    document = None
    if pid:
        q.execute('''
            SELECT d.id, d.filename, d.file_type, d.extraction_status, d.uploaded_at
            FROM third_party_profiles p
            JOIN documents d ON d.id = p.document_id
            WHERE p.id = %s
        ''', (pid,))
        doc_row = q.fetchone()
        if doc_row:
            document = {
                'id': doc_row[0],
                'filename': doc_row[1],
                'file_type': doc_row[2],
                'extraction_status': doc_row[3],
                'uploaded_at': doc_row[4],
            }

    # Technologies from profile
    technologies = []
    services = []
    if pid:
        q.execute('''
            SELECT technology, version, category
            FROM third_party_profile_technologies
            WHERE profile_id = %s
            ORDER BY technology
        ''', (pid,))
        technologies = [
            {'name': x[0], 'version': x[1], 'category': x[2]}
            for x in q.fetchall()
        ]

        q.execute('''
            SELECT service_name, service_type, criticality
            FROM third_party_profile_services
            WHERE profile_id = %s
            ORDER BY service_name
        ''', (pid,))
        services = [
            {'name': x[0], 'service_type': x[1], 'criticality': x[2]}
            for x in q.fetchall()
        ]

    q.close()
    c.close()

    return {
        'vendor': relationship,
        'document': document,
        'technologies': technologies,
        'services': services,
    }


@router.delete('/api/customers/{customer_id}/vendors/{vendor_id}/profile')
def delete_profile(customer_id: int, vendor_id: int, user: dict = Depends(require_roles('Admin'))):
    if customer_id != user['customer_id']:
        raise HTTPException(403, 'Not authorized')

    c = get_connection()
    q = c.cursor()

    # Find profile id via the tenant-joined path
    q.execute('''
        SELECT p.id FROM third_party_profiles p
        JOIN customer_vendors cv ON cv.id = p.customer_vendor_id
        WHERE cv.id = %s AND cv.customer_id = %s
    ''', (vendor_id, customer_id))
    r = q.fetchone()
    if not r:
        q.close()
        c.close()
        raise HTTPException(404, 'Profile not found')

    profile_id = r[0]

    # Delete children safely (ON DELETE CASCADE handles this, but be explicit
    # for clarity / auditability)
    q.execute('DELETE FROM third_party_external_assets WHERE profile_id = %s', (profile_id,))
    q.execute('DELETE FROM third_party_profile_services WHERE profile_id = %s', (profile_id,))
    q.execute('DELETE FROM third_party_profile_technologies WHERE profile_id = %s', (profile_id,))

    # Delete the profile itself (cascades if children remain)
    q.execute('DELETE FROM third_party_profiles WHERE id = %s', (profile_id,))

    c.commit()
    q.close()
    c.close()
    return {'deleted': True, 'profile_id': profile_id}


# ---------------------------------------------------------------------------
# Profile children endpoints
# ---------------------------------------------------------------------------

@router.get('/api/profiles/{profile_id}/technologies')
def technologies(profile_id: int, user: dict = Depends(get_current_user)):
    _profile(profile_id, user)
    c = get_connection()
    q = c.cursor()
    q.execute('SELECT id, technology, version, category, source FROM third_party_profile_technologies WHERE profile_id = %s', (profile_id,))
    r = q.fetchall()
    q.close()
    c.close()
    return [{'id': x[0], 'technology': x[1], 'version': x[2], 'category': x[3], 'source': x[4]} for x in r]


@router.post('/api/profiles/{profile_id}/technologies')
def add_technology(profile_id: int, data: Item, user: dict = Depends(require_roles('Admin'))):
    _profile(profile_id, user)
    c = get_connection()
    q = c.cursor()
    q.execute('''
        INSERT INTO third_party_profile_technologies(profile_id, technology, version, category, source)
        VALUES (%s, %s, %s, %s, %s) RETURNING id
    ''', (profile_id, data.technology, data.version, data.category, data.source))
    i = q.fetchone()[0]
    c.commit()
    q.close()
    c.close()
    # Technology changes affect risk -> refresh
    risk = refresh_profile_risk(profile_id)
    return {'id': i, 'risk': risk}


@router.delete('/api/profiles/{profile_id}/technologies/{technology_id}')
def remove_technology(profile_id: int, technology_id: int, user: dict = Depends(require_roles('Admin'))):
    _profile(profile_id, user)
    c = get_connection()
    q = c.cursor()
    q.execute('DELETE FROM third_party_profile_technologies WHERE id = %s AND profile_id = %s', (technology_id, profile_id))
    c.commit()
    q.close()
    c.close()
    risk = refresh_profile_risk(profile_id)
    return {'deleted': True, 'risk': risk}


@router.get('/api/profiles/{profile_id}/services')
def services(profile_id: int, user: dict = Depends(get_current_user)):
    _profile(profile_id, user)
    c = get_connection()
    q = c.cursor()
    q.execute('SELECT id, service_name, service_type, criticality FROM third_party_profile_services WHERE profile_id = %s', (profile_id,))
    r = q.fetchall()
    q.close()
    c.close()
    return [{'id': x[0], 'service_name': x[1], 'service_type': x[2], 'criticality': x[3]} for x in r]


@router.post('/api/profiles/{profile_id}/services')
def add_service(profile_id: int, data: Item, user: dict = Depends(require_roles('Admin'))):
    _profile(profile_id, user)
    c = get_connection()
    q = c.cursor()
    q.execute('''
        INSERT INTO third_party_profile_services(profile_id, service_name, service_type, criticality)
        VALUES (%s, %s, %s, %s) RETURNING id
    ''', (profile_id, data.service_name, data.service_type, data.criticality or 'MEDIUM'))
    i = q.fetchone()[0]
    c.commit()
    q.close()
    c.close()
    return {'id': i}


@router.get('/api/profiles/{profile_id}/external-assets')
def external_assets(profile_id: int, user: dict = Depends(get_current_user)):
    _profile(profile_id, user)
    c = get_connection()
    q = c.cursor()
    q.execute('''SELECT id, asset_type, value, exposure_status, last_seen
                 FROM third_party_external_assets WHERE profile_id = %s''', (profile_id,))
    r = q.fetchall()
    q.close()
    c.close()
    return [{'id': x[0], 'asset_type': x[1], 'value': x[2], 'exposure_status': x[3], 'last_seen': x[4]} for x in r]


@router.post('/api/profiles/{profile_id}/external-assets')
def add_external_asset(profile_id: int, data: Item, user: dict = Depends(require_roles('Admin'))):
    _profile(profile_id, user)
    c = get_connection()
    q = c.cursor()
    q.execute('''
        INSERT INTO third_party_external_assets(profile_id, asset_type, value, exposure_status, last_seen)
        VALUES (%s, %s, %s, %s, %s) RETURNING id
    ''', (profile_id, data.asset_type, data.value, data.exposure_status or 'UNKNOWN', data.last_seen))
    i = q.fetchone()[0]
    c.commit()
    q.close()
    c.close()
    # Exposure changes affect risk -> refresh
    risk = refresh_profile_risk(profile_id)
    return {'id': i, 'risk': risk}