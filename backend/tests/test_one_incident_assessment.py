import time
import psycopg2
from app.ai.assessment_agent import generate_assessment
from app.database.connection import get_connection


def get_or_create_incident():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM third_party_incidents")
    count = cur.fetchone()[0]

    if count > 0:
        cur.execute(
            """
            SELECT id, customer_id, incident_type, victim, group_name
            FROM third_party_incidents
            ORDER BY id ASC
            LIMIT 1
            """
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
        return row

    cur.execute(
        """
        INSERT INTO third_party_incidents (
            customer_id,
            incident_type,
            victim,
            group_name,
            disclosure_date,
            source_name,
            source_url,
            raw_payload
        ) VALUES (%s, %s, %s, %s, NOW(), %s, %s, %s)
        """,
        (
            1,
            "ransomware",
            "Test Victim",
            "Test Group",
            "test-source",
            "https://example.com/incident",
            '{}'
        )
    )
    conn.commit()
    cur.execute(
        """
        SELECT id, customer_id, incident_type, victim, group_name
        FROM third_party_incidents
        ORDER BY id DESC
        LIMIT 1
        """
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row


incident_row = get_or_create_incident()
assert incident_row is not None, "No third_party_incidents row available"
incident_id, customer_id, incident_type, incident_victim, group_name = incident_row

start = time.time()
generate_assessment(
    event_id=None,
    title="Ransomware incident assessment test",
    severity="HIGH",
    customer_id=customer_id,
    incident_id=incident_id,
    incident_type=incident_type,
    incident_victim=incident_victim,
)

conn = get_connection()
cur = conn.cursor()
cur.execute(
    """
    SELECT id, third_party_incident_id, vendor, intel_source, intel_type, threat_summary, business_relevance, created_at
    FROM assessments
    WHERE third_party_incident_id = %s
    ORDER BY id DESC
    LIMIT 1
    """,
    (incident_id,)
)
row = cur.fetchone()
cur.close()
conn.close()

assert row is not None, "No assessment row found for incident"
assessment_id, incident_fk, vendor_value, intel_source, intel_type, threat_summary, business_relevance, created_at = row
assert created_at is not None, "Assessment created_at is missing"
assert intel_source == "Ransomware.live", f"Unexpected intel_source: {intel_source}"
assert intel_type == "ThirdPartyIncident", f"Unexpected intel_type: {intel_type}"
assert isinstance(vendor_value, str) and len(vendor_value.strip()) > 0, f"Unexpected vendor value: {vendor_value!r}"
assert isinstance(threat_summary, str) and len(threat_summary.strip()) > 0, f"Threat summary empty: {threat_summary!r}"
assert isinstance(business_relevance, str) and len(business_relevance.strip()) > 0, f"Business relevance empty: {business_relevance!r}"

print("ASSESSMENT_ROW")
print((assessment_id, incident_fk, vendor_value, intel_source, intel_type, threat_summary, business_relevance, created_at))
print(f"Took {time.time() - start:.1f}s")
