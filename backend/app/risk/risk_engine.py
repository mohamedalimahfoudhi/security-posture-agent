def calculate_risk(cvss):

    if cvss is None:
        return {
            "risk_score": 0,
            "priority": "UNKNOWN"
        }


    if cvss >= 9:
        priority = "CRITICAL"

    elif cvss >= 7:
        priority = "HIGH"

    elif cvss >= 4:
        priority = "MEDIUM"

    else:
        priority = "LOW"


    return {
        "risk_score": cvss * 10,
        "priority": priority
    }