from app.database.connection import get_connection


def get_cves():

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            id,
            cve_id,
            title,
            description,
            severity,
            cvss_score,
            published_date AS published_at,
            source_url
        FROM cve_events
        ORDER BY published_date DESC NULLS LAST, id DESC;
    """)

    cves = cur.fetchall()

    cur.close()
    conn.close()

    return cves



def _get_alert_columns(cur):
    cur.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'alerts'
        """
    )
    return {row[0] for row in cur.fetchall()}


def get_alerts(customer_id):

    conn = get_connection()
    cur = conn.cursor()

    columns = _get_alert_columns(cur)

    select_fields = [
        "a.id",
        "c.name AS customer",
    ]

    field_names = [
        "id",
        "customer",
    ]

    if "title" in columns:
        select_fields.append("COALESCE(a.title, e.title) AS alert_title")
    else:
        select_fields.append("e.title AS alert_title")
    field_names.append("title")

    select_fields.append("e.title AS event")
    field_names.append("event")

    if "risk_score" in columns:
        select_fields.append("a.risk_score")
        field_names.append("risk_score")

    if "confidence_score" in columns:
        select_fields.append("a.confidence_score")
        field_names.append("confidence_score")

    select_fields.extend([
        "a.risk_level",
        "a.status",
    ])
    field_names.extend(["risk_level", "status"])

    if "created_at" in columns:
        select_fields.append("a.created_at")
        field_names.append("created_at")

    if "updated_at" in columns:
        select_fields.append("a.updated_at")
        field_names.append("updated_at")

    if "escalation_recommendation" in columns:
        select_fields.append("a.escalation_recommendation")
        field_names.append("escalation_recommendation")

    cur.execute(f"""
        SELECT {', '.join(select_fields)}
        FROM alerts a
        JOIN customers c
            ON a.customer_id = c.id
        LEFT JOIN cve_events e
            ON a.event_id = e.id
        WHERE a.customer_id = %s
        ORDER BY a.id DESC;
    """, (customer_id,))

    rows = cur.fetchall()

    cur.close()
    conn.close()

    alerts = []
    for row in rows:
        alert = dict(zip(field_names, row))
        if "updated_at" not in alert:
            alert["updated_at"] = None
        if "risk_score" not in alert:
            alert["risk_score"] = None
        if "confidence_score" not in alert:
            alert["confidence_score"] = None
        if "created_at" not in alert:
            alert["created_at"] = None
        if "escalation_recommendation" not in alert:
            alert["escalation_recommendation"] = None
        alerts.append(alert)

    return alerts


def get_alert_by_id(alert_id, customer_id):
    conn = get_connection()
    cur = conn.cursor()

    columns = _get_alert_columns(cur)

    select_fields = [
        "a.id",
    ]
    field_names = ["id"]

    if "title" in columns:
        select_fields.append("COALESCE(a.title, e.title) AS title")
    else:
        select_fields.append("e.title AS title")
    field_names.append("title")

    select_fields.extend([
        "a.customer_id",
        "c.name AS customer",
        "a.event_id",
        "e.title AS event_title",
        "e.cvss_score",
        "a.risk_level",
        "a.status",
    ])
    field_names.extend([
        "customer_id",
        "customer",
        "event_id",
        "event_title",
        "cvss_score",
        "risk_level",
        "status",
    ])

    optional_fields = [
        ("asset_id", "a.asset_id"),
        ("asset_technology", "a.asset_technology"),
        ("asset_vendor", "a.asset_vendor"),
        ("asset_version", "a.asset_version"),
        ("asset_criticality", "a.asset_criticality"),
        ("asset_internet_exposed", "a.asset_internet_exposed"),
        ("asset_sensitive_data", "a.asset_sensitive_data"),
        ("risk_score", "a.risk_score"),
        ("confidence_score", "a.confidence_score"),
        ("evidence", "a.evidence"),
        ("ai_summary", "a.ai_summary"),
        ("business_impact", "a.business_impact"),
        ("recommendation", "a.recommendation"),
        ("remediation_steps", "a.remediation_steps"),
        ("created_at", "a.created_at"),
        ("updated_at", "a.updated_at"),
        ("escalation_recommendation", "a.escalation_recommendation"),
    ]

    for name, field in optional_fields:
        if name in columns:
            select_fields.append(field)
            field_names.append(name)

    cur.execute(f"""
        SELECT {', '.join(select_fields)}
        FROM alerts a
        JOIN customers c
            ON a.customer_id = c.id
        LEFT JOIN cve_events e
            ON a.event_id = e.id
        WHERE a.id = %s AND a.customer_id = %s;
    """, (alert_id, customer_id))

    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return None

    row_data = dict(zip(field_names, row))

    return {
        "id": row_data.get("id"),
        "title": row_data.get("title"),
        "customer_id": row_data.get("customer_id"),
        "customer": row_data.get("customer"),
        "vulnerability": {
            "title": row_data.get("event_title"),
            "cve": row_data.get("event_title"),
            "cvss": row_data.get("cvss_score"),
        },
        "asset": {
            "id": row_data.get("asset_id"),
            "technology": row_data.get("asset_technology"),
            "vendor": row_data.get("asset_vendor"),
            "version": row_data.get("asset_version"),
            "criticality": row_data.get("asset_criticality"),
            "internet_exposed": row_data.get("asset_internet_exposed"),
            "sensitive_data": row_data.get("asset_sensitive_data"),
        },
        "risk_score": row_data.get("risk_score"),
        "confidence_score": row_data.get("confidence_score"),
        "risk_level": row_data.get("risk_level"),
        "status": row_data.get("status"),
        "analysis": {
            "evidence": row_data.get("evidence") or [],
            "summary": row_data.get("ai_summary"),
            "business_impact": row_data.get("business_impact"),
        },
        "recommendation": row_data.get("recommendation"),
        "remediation_steps": row_data.get("remediation_steps") or [],
        "created_at": row_data.get("created_at"),
        "updated_at": row_data.get("updated_at"),
    }


def update_alert_status(alert_id, status, customer_id):
    conn = get_connection()
    cur = conn.cursor()

    columns = _get_alert_columns(cur)
    set_clause = "status = %s"
    if "updated_at" in columns:
        set_clause = "status = %s, updated_at = CURRENT_TIMESTAMP"

    cur.execute(
        f"""
        UPDATE alerts
        SET {set_clause}
        WHERE id = %s AND customer_id = %s
        RETURNING id;
        """,
        (status, alert_id, customer_id),
    )

    updated = cur.fetchone()
    if not updated:
        cur.close()
        conn.close()
        return None

    conn.commit()
    cur.close()
    conn.close()

    return get_alert_by_id(alert_id, customer_id)


def get_customer_vendors():

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            id,
            customer_id,
            vendor,
            technology,
            criticality
        FROM customer_vendors;
    """)

    vendors = cur.fetchall()

    cur.close()
    conn.close()

    return vendors



def get_customers():

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            id,
            name
        FROM customers;
    """)

    customers = cur.fetchall()

    cur.close()
    conn.close()

    return customers


def get_all_customers():
    """Return all customers — intended for Admin-only endpoints."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, name, COALESCE(industry, '') AS industry
        FROM customers
        ORDER BY name
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [{"id": r[0], "name": r[1], "industry": r[2]} for r in rows]


def get_high_risk_cves():

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            id,
            title,
            severity,
            cvss_score,
            published_date AS published_at
        FROM cve_events
        WHERE severity IN ('HIGH','CRITICAL')
        ORDER BY id DESC
        LIMIT 10;
    """)

    rows = cur.fetchall()

    cves = []

    for row in rows:

        cves.append(
            {
                "id": row[0],
                "title": row[1],
                "severity": row[2],
                "cvss_score": row[3],
                "published_at": row[4]
            }
        )

    cur.close()
    conn.close()

    return cves

def create_customer(name: str, industry: str = None) -> dict:
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO customers (name, industry) VALUES (%s, %s) RETURNING id, name, industry",
            (name, industry)
        )
        row = cur.fetchone()
        conn.commit()
        return {"id": row[0], "name": row[1], "industry": row[2] or ""}
    finally:
        cur.close()
        conn.close()

def update_customer(customer_id: int, name: str, industry: str = None) -> dict:
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "UPDATE customers SET name = %s, industry = COALESCE(%s, industry) WHERE id = %s RETURNING id, name, industry",
            (name, industry, customer_id)
        )
        row = cur.fetchone()
        conn.commit()
        if row:
            return {"id": row[0], "name": row[1], "industry": row[2] or ""}
        return None
    finally:
        cur.close()
        conn.close()

def delete_customer(customer_id: int) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("BEGIN;")
        # Delete NO ACTION dependencies explicitly to preserve global catalogs
        cur.execute("DELETE FROM notification_recipients WHERE customer_id = %s", (customer_id,))
        cur.execute("DELETE FROM threat_correlations WHERE customer_id = %s", (customer_id,))
        cur.execute("DELETE FROM third_party_incidents WHERE customer_id = %s", (customer_id,))
        cur.execute("DELETE FROM knowledge_chunks WHERE customer_id = %s", (customer_id,))
        cur.execute("DELETE FROM assets WHERE customer_id = %s", (customer_id,))
        cur.execute("DELETE FROM documents WHERE customer_id = %s", (customer_id,))
        cur.execute("DELETE FROM assessments WHERE customer_id = %s", (customer_id,))
        cur.execute("DELETE FROM alerts WHERE customer_id = %s", (customer_id,))
        
        # customer_vendors references customers, and third_party_profiles cascades from customer_vendors
        cur.execute("DELETE FROM customer_vendors WHERE customer_id = %s", (customer_id,))
        
        # Finally delete the customer row
        cur.execute("DELETE FROM customers WHERE id = %s", (customer_id,))
        deleted = cur.rowcount > 0
        
        cur.execute("COMMIT;")
        return deleted
    except Exception as e:
        cur.execute("ROLLBACK;")
        raise e
    finally:
        cur.close()
        conn.close()
