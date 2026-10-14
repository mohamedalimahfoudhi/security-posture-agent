import psycopg2
from app.correlation.asset_cve_matcher import normalize, calculate_confidence, calculate_business_risk, get_assets


def normalize_vendor_name(vendor_name):
    """
    Normalize vendor name by removing common suffixes and lowercasing.
    E.g. "Microsoft Corporation" -> "microsoft",
         "Cisco Systems Inc" -> "cisco systems",
         "OpenSSL LLC" -> "openssl"
    """
    if not vendor_name:
        return ""
    
    text = normalize(vendor_name)
    
    # Remove common suffixes
    common_suffixes = [
        " corporation",
        " inc",
        " inc.",
        " incorporated",
        " limited",
        " ltd",
        " ltd.",
        " llc",
        " llc.",
        " systems",
        " company",
        " co.",
        " group",
        " private limited",
        " pvt ltd",
        " plc",
        " s.a.",
        " gmbh",
        " ag",
    ]
    
    for suffix in common_suffixes:
        if text.endswith(suffix):
            text = text[:-len(suffix)].strip()
            break
    
    return text


def get_customer_vendors(customer_id):
    """Fetch vendors associated with a customer."""
    try:
        from app.database.connection import get_connection
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT vendor FROM customer_vendors WHERE customer_id = %s
        """, (customer_id,))
        vendors = [row[0] for row in cur.fetchall()]
        cur.close()
        conn.close()
        return vendors
    except Exception:
        return []


def match_incident_to_assets(customer_id, incident):
    print("\n[INCIDENT CORRELATION STARTED]")
    print("\nIncident:")
    print(incident)

    assets = get_assets(customer_id)
    print("\nAssets found:", len(assets))

    matches = []
    
    # Use victim name ONLY for primary matching (strongest signal)
    victim_text = normalize(incident.get("victim") or "")
    
    # Build full incident text for secondary context matching
    incident_full_text = normalize(
        " ".join([
            incident.get("victim") or "",
            incident.get("group_name") or "",
            incident.get("incident_type") or "",
            incident.get("title") or "",
            incident.get("summary") or ""
        ])
    )

    # Also fetch customer-specific vendors
    customer_vendors = get_customer_vendors(customer_id)
    customer_vendors_normalized = [normalize_vendor_name(v) for v in customer_vendors]
    print(f"Customer vendors: {len(customer_vendors)}")

    for asset in assets:
        asset_id, technology, version, criticality, exposed, sensitive, vendor = asset
        confidence = calculate_confidence(technology, version, incident_full_text)

        if vendor:
            # Try both strict and loose vendor matching - BUT CHECK VICTIM FIRST
            vendor_name_strict = normalize(vendor)
            vendor_name_loose = normalize_vendor_name(vendor)
            
            # STRONGEST MATCH: vendor name appears IN THE VICTIM NAME
            if vendor_name_strict and vendor_name_strict in victim_text:
                confidence = min(100, confidence + 35)  # High boost for victim match
            elif vendor_name_loose and vendor_name_loose in victim_text:
                confidence = min(100, confidence + 25)  # Good boost for normalized victim match
            # WEAKER MATCH: vendor appears elsewhere in incident (title/summary)
            elif vendor_name_strict and vendor_name_strict in incident_full_text:
                confidence = min(100, confidence + 10)  # Low boost for incidental mentions
            elif vendor_name_loose and vendor_name_loose in incident_full_text:
                confidence = min(100, confidence + 5)   # Very low boost

        # Check customer_vendors: only boost if THIS asset's vendor is a known customer vendor
        if vendor and customer_vendors_normalized:
            vendor_normalized_loose = normalize_vendor_name(vendor)
            for cv_normalized in customer_vendors_normalized:
                if cv_normalized and cv_normalized == vendor_normalized_loose:
                    # This asset's vendor is a known customer vendor
                    # Boost more if it appears in victim name (strong signal)
                    if vendor_normalized_loose in victim_text:
                        confidence = min(100, confidence + 30)
                    else:
                        confidence = min(100, confidence + 10)
                    break

        if confidence > 0:
            asset_result = {
                "technology": technology,
                "vendor": vendor,
                "version": version,
                "criticality": criticality,
                "internet_exposed": exposed,
                "sensitive_data": sensitive,
                "confidence": confidence,
            }
            risk, priority = calculate_business_risk(asset_result, confidence)
            asset_result["risk_score"] = risk
            asset_result["priority"] = priority
            matches.append(asset_result)

    # Sort by confidence descending so best matches are first
    matches.sort(key=lambda x: x["confidence"], reverse=True)
    
    # Filter out low-confidence noise (require at least 15% confidence)
    matches = [m for m in matches if m["confidence"] >= 15]

    if not matches:
        print("\n[NO INCIDENT MATCH FOUND]")

    print("\n[INCIDENT CORRELATION COMPLETE]")
    return matches
