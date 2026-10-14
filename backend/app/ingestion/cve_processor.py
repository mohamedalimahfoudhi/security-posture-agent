def process_cve(raw_cve):

    cve_id = raw_cve["cve"]["id"]

    description = raw_cve["cve"]["descriptions"][0]["value"]


    return {
        "cve": cve_id,
        "cvss": extract_cvss(raw_cve),
        "product": extract_product(description),
        "description": description
    }



def extract_cvss(raw_cve):

    try:
        return raw_cve["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]

    except:
        return None



def extract_product(description):

    words = description.split()

    return words[0:3]