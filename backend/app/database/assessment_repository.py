from app.database.connection import get_connection
import json


def get_assets_for_customer(customer_id):
    """Get all assets for a customer for correlation"""
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT id, technology, vendor, version, category, 
               internet_exposed, sensitive_data, confidence
        FROM assets
        WHERE customer_id = %s
    """, (customer_id,))
    
    assets = cur.fetchall()
    cur.close()
    conn.close()
    
    return [
        {
            "id": asset[0],
            "technology": asset[1],
            "vendor": asset[2],
            "version": asset[3],
            "category": asset[4],
            "internet_exposed": asset[5],
            "sensitive_data": asset[6],
            "confidence": asset[7]
        }
        for asset in assets
    ]


def check_asset_match(cve_title, cve_technology, customer_id):
    """Check if CVE matches any extracted assets for the customer"""
    assets = get_assets_for_customer(customer_id)
    
    matches = []
    cve_title_lower = cve_title.lower()
    cve_technology_lower = (cve_technology or "").lower()
    
    for asset in assets:
        asset_technology_lower = (asset["technology"] or "").lower()
        asset_vendor_lower = (asset["vendor"] or "").lower()
        
        # Check for technology match
        if asset_technology_lower and (
            asset_technology_lower in cve_title_lower or
            asset_technology_lower in cve_technology_lower or
            cve_technology_lower in asset_technology_lower
        ):
            matches.append({
                "asset": asset,
                "match_type": "technology",
                "confidence": asset["confidence"]
            })
            continue
        
        # Check for vendor match
        if asset_vendor_lower and asset_vendor_lower in cve_title_lower:
            matches.append({
                "asset": asset,
                "match_type": "vendor",
                "confidence": asset["confidence"] - 10  # Lower confidence for vendor-only match
            })
    
    # Return best match (highest confidence)
    if matches:
        best_match = max(matches, key=lambda x: x["confidence"])
        return best_match
    
    return None


def insert_assessment(data):

    conn = get_connection()
    cur = conn.cursor()


    # Check if an assessment already exists

    cur.execute(
        """
        SELECT evidence, asset_id
        FROM assessments
        WHERE customer_id = %s
        AND event_id = %s
        """,
        (
            data["customer_id"],
            data["event_id"]
        )
    )


    existing_assessment = cur.fetchone()

    if existing_assessment:

        print(
            "[AI ASSESSMENT] Already exists - skipping"
        )

        evidence_json = existing_assessment[0]
        existing_asset_id = existing_assessment[1]
        asset = None
        asset_match_confidence = None

        if evidence_json:
            try:
                if isinstance(evidence_json, str):
                    evidence = json.loads(evidence_json)
                else:
                    evidence = evidence_json

                if isinstance(evidence, dict):
                    asset = {
                        "id": evidence.get("asset_id"),
                        "technology": evidence.get("asset_technology"),
                        "vendor": evidence.get("asset_vendor"),
                        "version": evidence.get("asset_version"),
                        "internet_exposed": evidence.get("internet_exposed"),
                        "sensitive_data": evidence.get("asset_sensitive_data"),
                        "confidence": evidence.get("confidence") or evidence.get("confidence_score")
                    }
                    asset_match_confidence = asset.get("confidence")
                elif isinstance(evidence, list) and evidence and isinstance(evidence[0], dict):
                    evidence = evidence[0]
                    asset = {
                        "id": evidence.get("asset_id"),
                        "technology": evidence.get("asset_technology"),
                        "vendor": evidence.get("asset_vendor"),
                        "version": evidence.get("asset_version"),
                        "internet_exposed": evidence.get("internet_exposed"),
                        "sensitive_data": evidence.get("asset_sensitive_data"),
                        "confidence": evidence.get("confidence") or evidence.get("confidence_score")
                    }
                    asset_match_confidence = asset.get("confidence")
            except Exception:
                asset = None
                asset_match_confidence = None

        if not asset and existing_asset_id:
            cur.execute(
                """
                SELECT id, technology, vendor, version, criticality, internet_exposed, sensitive_data, confidence
                FROM assets
                WHERE id = %s
                AND customer_id = %s
                """,
                (existing_asset_id, data["customer_id"])
            )
            asset_row = cur.fetchone()
            if asset_row:
                asset = {
                    "id": asset_row[0],
                    "technology": asset_row[1],
                    "vendor": asset_row[2],
                    "version": asset_row[3],
                    "criticality": asset_row[4],
                    "internet_exposed": asset_row[5],
                    "sensitive_data": asset_row[6],
                    "confidence": asset_row[7],
                }
                asset_match_confidence = asset.get("confidence")

        if not asset:
            cve_title = data.get("cve_title", "")
            cve_technology = data.get("cve_technology", "")
            asset_match = check_asset_match(cve_title, cve_technology, data["customer_id"])
            asset = asset_match["asset"] if asset_match else None
            asset_match_confidence = asset_match["confidence"] if asset_match else None

        cur.close()
        conn.close()

        return {
            "existing": True,
            "asset": asset,
            "asset_match_confidence": asset_match_confidence
        }



    # Check if there's a matching asset before creating assessment
    cve_title = data.get("cve_title", "")
    cve_technology = data.get("cve_technology", "")
    asset_match = check_asset_match(cve_title, cve_technology, data["customer_id"])
    
    if not asset_match:
        print("[AI ASSESSMENT] No matching asset found - skipping assessment")
        cur.close()
        conn.close()
        return None
    
    asset = asset_match["asset"]
    print(f"[AI ASSESSMENT] Asset match found: {asset['technology']} (confidence: {asset_match['confidence']}%)")

    cur.execute(
        """
        INSERT INTO assessments
        (
            customer_id,
            event_id,
            asset_id,
            vendor,
            technology,
            threat_summary,
            severity,
            risk_score,
            exploitation_risk,
            recommendations,
            confidence,
            evidence
        )

        VALUES
        (
            %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
        )
        """,
        (
            data["customer_id"],
            data["event_id"],
            asset["id"],
            data["vendor"],
            data["technology"],
            data["assessment"]["threat_summary"],
            data["assessment"]["severity"],
            data["assessment"]["risk_score"],
            data["assessment"]["exploitation_risk"],
            json.dumps(
                data["assessment"]["recommendations"]
            ),
            asset_match["confidence"],
            json.dumps({
                "source": "asset_correlation",
                "asset_id": asset["id"],
                "match_type": asset_match["match_type"],
                "asset_technology": asset["technology"],
                "asset_vendor": asset["vendor"],
                "asset_version": asset["version"],
                "internet_exposed": asset["internet_exposed"],
                "sensitive_data": asset["sensitive_data"]
            })
        )
    )


    conn.commit()


    print(
        "[AI ASSESSMENT] Saved successfully with asset correlation"
    )

    cur.close()
    conn.close()

    return {
        "assessment": data,
        "asset": asset,
        "asset_match_confidence": asset_match["confidence"]
    }




def get_assessments(customer_id):

    conn = get_connection()
    cur = conn.cursor()


    cur.execute(
        """
        SELECT

            a.id,

            c.name AS customer,

            ast.vendor,

            ast.technology,

            e.title AS vulnerability,

            e.cve_id AS threat_source,

            a.ai_summary AS threat_summary,

            a.severity,

            a.risk_score,

            a.recommendation,

            a.confidence_score AS confidence,

            a.business_impact AS business_relevance,

            a.created_at,

            a.affected_third_party,

            a.ransomware_group,

            a.hunting_guidance,

            (
                SELECT json_agg(
                    json_build_object(
                        'technique_id', at.technique_id,
                        'name', tk.name,
                        'similarity_score', at.similarity_score
                    )
                    ORDER BY at.similarity_score DESC
                )
                FROM assessment_techniques at
                LEFT JOIN attack_techniques tk ON at.technique_id = tk.technique_id
                WHERE at.assessment_id = a.id
            ) AS assessment_techniques


        FROM assessments a


        JOIN customers c

            ON a.customer_id = c.id


        LEFT JOIN cve_events e

            ON a.event_id = e.id


        LEFT JOIN assets ast

            ON a.asset_id = ast.id

        WHERE a.customer_id = %s

        ORDER BY a.created_at DESC;

        """,
        (customer_id,)
    )


    rows = cur.fetchall()

    cur.close()
    conn.close()



    assessments = []



    for row in rows:


        assessments.append(

            {

                "id": row[0],

                "customer": row[1],

                "vendor": row[2] or 'Unknown',

                "technology": row[3] or 'Unknown',

                "vulnerability": row[4],

                "threat_source": row[5],

                "threat_summary": row[6],

                "severity": row[7],

                "risk_score": row[8],

                "recommendations": [row[9]] if row[9] else [],

                "confidence": row[10],

                "business_relevance": row[11],

                "created_at": row[12],

                "affected_third_party": row[13],

                "ransomware_group": row[14],

                "hunting_guidance": row[15],

                "assessment_techniques": row[16]

            }

        )


    return assessments