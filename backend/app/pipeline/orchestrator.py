from app.database.repository import get_high_risk_cves
from app.context.context_engine import find_relevant_assets
from app.assessment.analyzer import create_assessment
from app.database.assessment_repository import insert_assessment
from app.risk.vulnerability_applicability import assess_vulnerability_applicability


def run_pipeline():

    print("Starting AI-TIP pipeline...")

    cves = get_high_risk_cves()

    print(f"Found {len(cves)} CVEs")


    for cve in cves:

        print("\n" + "="*50)
        print("Processing:")
        print(cve["title"])


        matches = find_relevant_assets(cve)


        if not matches:
            print("No affected assets found")
            continue


        print("Affected assets:")
        print(matches)


        assessments = create_assessment(
            cve,
            matches
        )


        for assessment in assessments:

            result = insert_assessment(assessment)
            if not result:
                continue

            if result.get("existing"):
                print("Assessment already exists; skipping insert")
            else:
                print("Assessment saved")

            risk_score = assessment.get("assessment", {}).get("risk_score", 0)
            if risk_score >= 70 and result.get("asset"):
                alert_response = assess_vulnerability_applicability(
                    customer_id=assessment["customer_id"],
                    vulnerability_title=cve["title"],
                    assets=[result["asset"]]
                )
                alert_id = alert_response.get("alert", {}).get("id")
                if alert_id:
                    print(f"Alert created for assessment: {alert_id}")
                else:
                    print("No alert was created for this assessment")


    print("\nPipeline completed")


if __name__ == "__main__":
    run_pipeline()