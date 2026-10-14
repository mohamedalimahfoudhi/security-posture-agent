from app.database.connection import get_connection


def normalize(text):

    if not text:
        return ""

    return text.lower().strip()



# Technology aliases improve matching accuracy
TECH_ALIASES = {

    "apache": [
        "apache",
        "httpd",
        "apache http server"
    ],

    "postgresql": [
        "postgresql",
        "postgres",
        "psql"
    ],

    "openssl": [
        "openssl",
        "open ssl"
    ],

    "ubuntu": [
        "ubuntu",
        "linux"
    ],

    "wazuh": [
        "wazuh"
    ],

    "opnsense": [
        "opnsense",
        "pfsense"
    ]

}



def get_assets(customer_id):

    conn = get_connection()

    cur = conn.cursor()


    cur.execute(
        """
        SELECT
            id,
            technology,
            version,
            criticality,
            internet_exposed,
            sensitive_data,
            vendor

        FROM assets

        WHERE customer_id = %s
        """,
        (customer_id,)
    )

    assets = cur.fetchall()

    cur.close()
    conn.close()

    return assets


def calculate_confidence(
        technology,
        version,
        cve_text
):

    score = 0

    tech = normalize(technology)

    # Technology matching
    aliases = TECH_ALIASES.get(
        tech,
        [tech]
    )

    for alias in aliases:
        if alias in cve_text:
            score += 60
            break

    # Version matching
    if version:
        if normalize(version) in cve_text:
            score += 30

    # Cap score
    if score > 100:
        score = 100

    return score


def calculate_business_risk(asset, confidence):

    risk = confidence

    if asset["internet_exposed"]:
        risk += 15

    if asset["criticality"] == "CRITICAL":
        risk += 20
    elif asset["criticality"] == "HIGH":
        risk += 10

    if asset["sensitive_data"]:
        risk += 15

    if risk > 100:
        risk = 100

    if risk >= 85:
        priority = "CRITICAL"
    elif risk >= 70:
        priority = "HIGH"
    elif risk >= 40:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return risk, priority


def match_cve_to_assets(
        customer_id,
        cve_title
):

    print("\n[CORRELATION ENGINE STARTED]")

    print("\nCVE:")
    print(cve_title)

    assets = get_assets(customer_id)

    print(
        "\nAssets found:",
        len(assets)
    )

    matches = []

    cve_text = normalize(cve_title)

    for asset in assets:

        asset_id, technology, version, criticality, exposed, sensitive, vendor = asset

        confidence = calculate_confidence(
            technology,
            version,
            cve_text
        )

        if confidence > 0:

            asset_result = {
                "id": asset_id,
                "technology": technology,
                "vendor": vendor,
                "version": version,
                "criticality": criticality,
                "internet_exposed": exposed,
                "sensitive_data": sensitive,
                "confidence": confidence
            }



            risk, priority = calculate_business_risk(
                asset_result,
                confidence
            )



            asset_result["risk_score"] = risk

            asset_result["priority"] = priority



            matches.append(asset_result)



            print(
                "\n[MATCH FOUND]"
            )

            print(asset_result)



    if not matches:

        print(
            "\n[NO MATCH FOUND]"
        )



    print(
        "\n[CORRELATION COMPLETE]"
    )



    return matches





def generate_context(matches):


    if not matches:

        return "No affected customer assets detected."



    context = []



    for asset in matches:


        text = f"""

Affected Technology:
{asset['technology']}

Version:
{asset['version']}

Criticality:
{asset['criticality']}

Internet Exposed:
{asset['internet_exposed']}

Sensitive Data:
{asset['sensitive_data']}

Correlation Confidence:
{asset['confidence']}%

Risk Score:
{asset['risk_score']}

Priority:
{asset['priority']}

"""


        context.append(text)



    return "\n".join(context)






if __name__ == "__main__":


    customer_id = 1


    cve_title = (
        "Apache HTTP Server "
        "2.4.49 Remote Code Execution Vulnerability"
    )



    matches = match_cve_to_assets(
        customer_id,
        cve_title
    )



    print(
        "\n========== GENERATED CONTEXT =========="
    )


    print(
        generate_context(matches)
    )