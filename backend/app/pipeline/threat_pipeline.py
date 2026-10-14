from app.ingestion.nvd_client import fetch_recent_cves
from app.ingestion.cve_processor import process_cve
from app.risk.risk_engine import calculate_risk
from app.ai.analyzer import analyze_cve


def run_pipeline():

    print("Starting AI-TIP pipeline...")

    # Step 1: Get recent CVEs from NVD
    cves = fetch_recent_cves()

    print(f"CVEs received: {len(cves)}")

    alerts = []


    # Step 2: Process every CVE
    for raw_cve in cves:

        cve = process_cve(raw_cve)

        print(
            "\nProcessing:",
            cve["cve"],
            "CVSS:",
            cve["cvss"]
        )


        # Step 3: Calculate risk
        risk = calculate_risk(cve["cvss"])

        print("Risk:", risk)


        # Debug priority value
        print("DEBUG PRIORITY:", repr(risk["priority"]))


        # Step 4: Only analyze HIGH and CRITICAL vulnerabilities
        if risk["priority"] != "CRITICAL" and risk["priority"] != "HIGH":
            print("Skipping - not critical/high")
            continue


        print("Sending to AI...")


        # Step 5: AI analysis
        analysis = analyze_cve(cve)


        # Step 6: Create alert
        alert = {
            "cve": cve["cve"],
            "risk": risk,
            "analysis": analysis
        }


        alerts.append(alert)


    print(
        f"\nGenerated alerts: {len(alerts)}"
    )

    return alerts