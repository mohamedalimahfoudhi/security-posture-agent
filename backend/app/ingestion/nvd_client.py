import requests
from datetime import datetime, timedelta, timezone


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_recent_cves(days=7):

    end_date = datetime.now(timezone.utc)

    start_date = end_date - timedelta(days=days)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 10
    }

    response = requests.get(
        NVD_URL,
        params=params
    )

    response.raise_for_status()

    data = response.json()

    return data["vulnerabilities"]


if __name__ == "__main__":

    cves = fetch_recent_cves()

    for cve in cves:
        print(cve["cve"]["id"])