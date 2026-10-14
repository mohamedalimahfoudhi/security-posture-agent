from app.ai.analyzer import analyze_cve


def create_assessment(cve, matches):

    results = []

    for match in matches:

        context = {
            "cve": cve["title"],
            "description": cve.get("description", ""),
            "severity": cve["severity"],
            "cvss": cve["cvss_score"],
            "vendor": match["vendor"],
            "technology": match["technology"],
            "criticality": match["criticality"]
        }

        analysis = analyze_cve(context)

        results.append({
            "event_id": cve["id"],
            "customer_id": match["customer_id"],
            "vendor": match["vendor"],
            "technology": match["technology"],
            "cve_title": cve["title"],
            "cve_technology": cve.get("cve_id") or cve.get("source", ""),
            "assessment": analysis
        })

    return results