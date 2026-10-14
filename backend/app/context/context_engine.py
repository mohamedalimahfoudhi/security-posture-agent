from app.database.connection import get_connection


def find_relevant_assets(vulnerability):

    conn = get_connection()
    cur = conn.cursor()


    text = (
        vulnerability["title"] + " " +
        str(vulnerability.get("description", ""))
    ).lower()


    cur.execute("""
        SELECT
            id,
            customer_id,
            vendor,
            technology,
            version,
            internet_exposed,
            sensitive_data,
            confidence
        FROM assets;
    """)


    assets = cur.fetchall()


    matches = []


    for asset in assets:

        asset_id = asset[0]
        customer_id = asset[1]
        vendor_name = asset[2] or ""
        technology = asset[3] or ""
        version = asset[4] or ""
        internet_exposed = asset[5]
        sensitive_data = asset[6]
        confidence = asset[7]

        vendor_norm = vendor_name.lower()
        technology_norm = technology.lower()
        version_norm = version.lower()

        if not vendor_norm and not technology_norm:
            continue

        if (
            vendor_norm in text
            or
            technology_norm in text
            or
            version_norm in text
        ):
            matches.append({
                "id": asset_id,
                "customer_id": customer_id,
                "vendor": vendor_name,
                "technology": technology,
                "version": version,
                "criticality": None,
                "internet_exposed": internet_exposed,
                "sensitive_data": sensitive_data,
                "confidence": confidence,
            })


    cur.close()
    conn.close()


    return matches