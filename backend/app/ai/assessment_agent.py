import json
import logging
import math
import requests
import ast

from app.correlation.asset_cve_matcher import match_cve_to_assets
from app.correlation.asset_cve_matcher_incident import match_incident_to_assets
from app.correlation.hunting_guidance_templates import build_hunting_guidance_json
from app.ai.ollama_client import ask_mistral, OLLAMA_MODEL, OLLAMA_TIMEOUT
from app.database.connection import get_connection

logger = logging.getLogger(__name__)

_OLLAMA_EMBED_URL = "http://localhost:11434/api/embeddings"
_EMBED_MODEL = "nomic-embed-text"
_TECHNIQUE_SIMILARITY_THRESHOLD = 0.65
_TECHNIQUE_TOP_K = 3


def _get_embedding(text: str):
    """Call Ollama nomic-embed-text. Returns 768-dim list or raises."""
    r = requests.post(
        _OLLAMA_EMBED_URL,
        json={"model": _EMBED_MODEL, "prompt": text},
        timeout=30
    )
    r.raise_for_status()
    return r.json()["embedding"]


def _cosine_similarity(v1, v2):
    dot = sum(a * b for a, b in zip(v1, v2))
    n1 = math.sqrt(sum(a * a for a in v1))
    n2 = math.sqrt(sum(b * b for b in v2))
    return dot / (n1 * n2) if n1 and n2 else 0.0


def tag_assessment_techniques(assessment_id: int, threat_summary: str, cur):
    """
    Embed threat_summary, score against all attack_techniques, write top-K
    matches above threshold into assessment_techniques using the supplied
    cursor (caller owns the transaction/commit).

    Silently skips (with a warning) if Ollama is unreachable, so a network
    hiccup does NOT roll back the parent assessment.
    """
    if not threat_summary or not threat_summary.strip():
        logger.warning("[TECHNIQUE TAGGER] Empty threat_summary for assessment %s — skipping", assessment_id)
        return

    try:
        emb = _get_embedding(threat_summary)
    except Exception as exc:
        logger.warning("[TECHNIQUE TAGGER] Embedding call failed for assessment %s: %s", assessment_id, exc)
        return

    cur.execute("SELECT technique_id, embedding FROM attack_techniques")
    techniques = cur.fetchall()

    if not techniques:
        logger.warning("[TECHNIQUE TAGGER] attack_techniques table is empty — skipping")
        return

    scores = []
    for tech_id, tech_emb in techniques:
        s = _cosine_similarity(emb, tech_emb)
        scores.append((s, tech_id))

    scores.sort(reverse=True)
    top_k = [item for item in scores if item[0] >= _TECHNIQUE_SIMILARITY_THRESHOLD][:_TECHNIQUE_TOP_K]

    for score, tech_id in top_k:
        cur.execute(
            """
            INSERT INTO assessment_techniques (assessment_id, technique_id, similarity_score)
            VALUES (%s, %s, %s)
            ON CONFLICT (assessment_id, technique_id)
            DO UPDATE SET similarity_score = EXCLUDED.similarity_score
            """,
            (assessment_id, tech_id, score)
        )

    logger.info(
        "[TECHNIQUE TAGGER] assessment %s: %d match(es) above %.2f (best: %s=%.4f)",
        assessment_id,
        len(top_k),
        _TECHNIQUE_SIMILARITY_THRESHOLD,
        top_k[0][1] if top_k else "none",
        top_k[0][0] if top_k else 0.0
    )


def calculate_score(
        severity,
        correlation_risk
):

    score = correlation_risk


    if severity == "CRITICAL":
        score += 20

    elif severity == "HIGH":
        score += 10


    return min(score, 100)




def generate_assessment(
        event_id,
        title,
        severity,
        customer_id=1,
        incident_id=None,
        incident_type=None,
        incident_victim=None
):


    logger.info("[AI ASSESSMENT ENGINE] Started")


    conn = get_connection()
    cur = conn.cursor()



    # Prevent duplicate assessments

    if incident_id is not None:

        cur.execute(
            """
            SELECT id
            FROM assessments
            WHERE customer_id=%s
            AND third_party_incident_id IS NOT DISTINCT FROM %s
            """,
            (customer_id, incident_id)
        )

    else:

        cur.execute(
            """
            SELECT id
            FROM assessments
            WHERE customer_id=%s
            AND event_id=%s
            """,
            (customer_id, event_id)
        )


    if cur.fetchone():

        logger.info(f"[AI ASSESSMENT ENGINE] Assessment already exists for customer {customer_id}, event {event_id}")

        cur.close()
        conn.close()

        return



    #
    # Fetch full incident details for incident path (victim, group, sector from raw_payload)
    # Used for breach-appropriate prompt and affected_third_party / ransomware_group fields.
    #

    incident_victim_name = incident_victim  # passed-in fallback
    incident_group_name = None
    incident_sector = None
    incident_country = None
    incident_description = None

    if incident_id is not None:
        cur.execute(
            """
            SELECT victim, group_name, raw_payload
            FROM third_party_incidents
            WHERE id = %s
            """,
            (incident_id,)
        )
        inc_row = cur.fetchone()
        if inc_row:
            incident_victim_name = inc_row[0] or incident_victim
            incident_group_name = inc_row[1]
            raw_payload = inc_row[2] or {}
            incident_sector = raw_payload.get("activity") or None
            incident_country = raw_payload.get("country") or None
            incident_description = raw_payload.get("description") or None

    #
    # Use correlation engine
    #

    if incident_id is not None:

        matches = match_incident_to_assets(
            customer_id,
            {
                "victim": incident_victim_name or title,
                "group_name": incident_group_name or "",
                "incident_type": incident_type or "breach",
                "title": title,
                "summary": title,
            }
        )

    else:

        matches = match_cve_to_assets(
            customer_id,
            title
        )



    if matches:


        asset = matches[0]


        technology = asset["technology"]

        version = asset["version"]

        criticality = asset["criticality"]

        vendor = asset.get("vendor") or "Unknown"

        internet_exposed = asset["internet_exposed"]

        sensitive_data = asset["sensitive_data"]

        correlation_confidence = asset["confidence"]

        correlation_risk = asset["risk_score"]

        priority = asset["priority"]



    else:


        technology = "Unknown"

        version = None

        criticality = "MEDIUM"

        vendor = "Unknown"

        internet_exposed = False

        sensitive_data = False

        correlation_confidence = 0

        correlation_risk = 0

        priority = "LOW"




    #
    # AI Context — branch on incident vs CVE path
    #

    if incident_id is not None:
        # --- BREACH / RANSOMWARE INCIDENT PROMPT ---
        # Build context strings from incident detail; omit any field that is None/empty.
        group_line = f"Ransomware group: {incident_group_name}" if incident_group_name else "Ransomware group: Unknown"
        sector_line = f"Victim sector: {incident_sector}" if incident_sector else ""
        country_line = f"Victim country: {incident_country}" if incident_country else ""
        desc_line = f"Victim description: {incident_description[:300]}" if incident_description else ""
        asset_line = (
            f"Matched internal asset: {technology} ({vendor}) — criticality={criticality}, "
            f"internet_exposed={internet_exposed}, sensitive_data={sensitive_data}"
            if technology != "Unknown"
            else "No internal asset match found for this victim."
        )

        prompt = f"""You are AI-TIP, a Cyber Threat Intelligence analyst for a Security Operations Centre.

A third-party breach or ransomware incident has been reported. Assess its relevance to our customer.

INCIDENT DETAILS
Victim organisation: {incident_victim_name}
{group_line}
Incident type: {incident_type or 'ransomware'}
{sector_line}
{country_line}
{desc_line}

CUSTOMER ASSET CONTEXT
{asset_line}
Correlation confidence: {correlation_confidence}%

TASK
Provide a breach relevance assessment. Focus on:
1. What this incident means for our customer (supply chain risk, shared infrastructure, data exposure)
2. Whether this third party has access to our customer's systems, data, or supply chain
3. Recommended breach-specific actions: verify if this vendor has access to customer data, 
   assess whether customer data or credentials may be exposed, consider vendor contact/escalation,
   review any shared integrations or APIs. Do NOT give vulnerability patch advice.
4. SOC actions specific to a third-party breach (e.g. revoke credentials, audit access logs,
   notify affected customers if relevant)
5. Confidence in this assessment (0-100)

Return a JSON object with exactly these keys and formats:
- "threat_summary": a single string of 1-2 sentences of plain prose describing what happened and why it matters to the customer. This MUST be a plain string, NOT a nested object or dict.
- "exploitability": a single word (High, Medium, or Low)
- "business_impact": a single word (High, Medium, or Low)
- "recommended_remediation": a JSON array of 2-3 short action strings specific to THIS incident (e.g. <action 1>, <action 2>). These are PLACEHOLDERS showing the format only. Do NOT copy these example values. Generate your own actual recommendations based on the specific incident details.
- "confidence": an integer 0-100

Return JSON only. Do not wrap in markdown. Do not add extra keys.
"""

    else:
        # --- CVE / VULNERABILITY PROMPT (unchanged) ---
        prompt = f"""

You are AI-TIP, a Cyber Threat Intelligence analyst.

Analyze this vulnerability using customer environment context.


Threat:
{title}


Severity:
{severity}


Affected Asset:

Technology:
{technology}

Version:
{version}

Business Criticality:
{criticality}

Internet Exposed:
{internet_exposed}

Sensitive Data:
{sensitive_data}


Correlation Confidence:
{correlation_confidence}%


Context Risk Score:
{correlation_risk}



Provide:

- Threat summary
- Exploitation risk
- Business impact
- Recommended remediation
- SOC actions
- Confidence score (0-100, how confident you are in this assessment)

Return JSON with these exact keys: threat_summary, exploitability,
business_impact, recommended_remediation, confidence

Return JSON only.

"""



    try:
        ai_response = ask_mistral(prompt, model=OLLAMA_MODEL or "mistral", timeout=OLLAMA_TIMEOUT or 30)
        if isinstance(ai_response, dict):
            ai_result = ai_response.get("response", ai_response)
        else:
            ai_result = ai_response

        if isinstance(ai_result, (dict, list)):
            ai_result = json.dumps(ai_result)
        else:
            ai_result = str(ai_result)

        try:
            ai_data = json.loads(ai_result)

            # ---- threat_summary extraction ----
            # The small model frequently returns threat_summary as a nested dict
            # instead of a prose string. Resolution priority:
            #  1. If it's already a non-empty string → use it directly.
            #  2. If it's a dict → look inside it for prose:
            #     a. 'description' key (seen in assessment 244)
            #     b. Any string value longer than 30 chars
            #     c. Synthesise from 'impact'/'risk'/'relevance' short-value keys
            #     d. json.dumps the nested dict (readable, not the outer blob)
            #  3. If threat_summary key is absent → search outer ai_data alt-keys
            #     ('description', 'summary', 'assessment', 'analysis')
            #  4. Last resort: store ai_result (full raw response)
            raw_ts = ai_data.get("threat_summary")

            if isinstance(raw_ts, dict):
                # Case 2: nested dict — extract from inside it
                extracted = None
                # 2a: named prose key
                for prose_key in ("description", "summary", "text", "assessment", "analysis"):
                    candidate = raw_ts.get(prose_key)
                    if candidate and isinstance(candidate, str) and len(candidate) > 30:
                        extracted = candidate
                        break
                if extracted is None:
                    # 2b: any string value long enough to be prose
                    for v in raw_ts.values():
                        if isinstance(v, str) and len(v) > 30:
                            extracted = v
                            break
                if extracted is None:
                    # 2c: synthesise from short label-value keys (impact/risk/relevance)
                    parts = []
                    for label_key in ("impact", "risk", "relevance", "potential_exposure"):
                        val = raw_ts.get(label_key)
                        if val:
                            parts.append(f"{label_key}: {val}")
                    if parts:
                        victim_hint = (
                            f" for third party {incident_victim_name}"
                            if incident_id is not None and incident_victim_name
                            else ""
                        )
                        extracted = (
                            f"Third-party incident assessment{victim_hint}. "
                            + "; ".join(parts) + "."
                        )
                # 2d: compact JSON of the nested dict (not the full outer blob)
                raw_ts = extracted if extracted else json.dumps(raw_ts)

            elif not raw_ts:
                # Case 3: key absent — check outer-level alt keys
                for alt_key in ("description", "summary", "assessment", "analysis"):
                    if ai_data.get(alt_key) and isinstance(ai_data[alt_key], str):
                        raw_ts = ai_data[alt_key]
                        break
                else:
                    # Case 4: nothing useful anywhere — store the raw response
                    raw_ts = ai_result

            threat_summary = str(raw_ts)

            business_impact = str(ai_data.get("business_impact", "MEDIUM"))
            exploitation_risk = str(ai_data.get("exploitability", "MEDIUM"))

            # recommended_remediation fallback is incident-path-aware
            _default_rec = (
                "Verify whether this vendor has access to customer data; audit access logs; "
                "revoke any shared credentials; consider vendor contact to assess breach scope."
                if incident_id is not None
                else "Patch affected technology"
            )
            
            # Handle recommendations - AI may return JSON array, stringified list, or plain string
            raw_rec = ai_data.get("recommended_remediation", _default_rec)
            
            if isinstance(raw_rec, list):
                # Already a proper list
                ai_recommendations = raw_rec
            elif isinstance(raw_rec, str):
                # Try to parse as JSON array first
                try:
                    parsed = json.loads(raw_rec)
                    if isinstance(parsed, list):
                        ai_recommendations = parsed
                    else:
                        ai_recommendations = [str(parsed)]
                except json.JSONDecodeError:
                    # Try to parse as Python stringified list (e.g. "['action1', 'action2']")
                    try:
                        parsed = ast.literal_eval(raw_rec)
                        if isinstance(parsed, list):
                            ai_recommendations = parsed
                        else:
                            ai_recommendations = [str(parsed)]
                    except (ValueError, SyntaxError):
                        # Plain string - split by semicolons or wrap as single item
                        if ';' in raw_rec:
                            ai_recommendations = [r.strip() for r in raw_rec.split(';') if r.strip()]
                        else:
                            ai_recommendations = [raw_rec]
            else:
                # Unexpected type - convert to string and wrap
                ai_recommendations = [str(raw_rec)]
            confidence = str(ai_data.get("confidence", "85"))
        except (json.JSONDecodeError, TypeError):
            threat_summary = ai_result
            business_impact = "MEDIUM"
            exploitation_risk = "MEDIUM"
            _default_rec = (
                "Verify whether this vendor has access to customer data; audit access logs; "
                "revoke any shared credentials; consider vendor contact to assess breach scope."
                if incident_id is not None
                else "Patch affected technology"
            )
            ai_recommendations = [_default_rec]
            confidence = "85"
    except Exception as exc:
        logger.warning(f"[AI ASSESSMENT] Ollama request failed, using fallback assessment: {exc}")
        threat_summary = title
        business_impact = "MEDIUM"
        exploitation_risk = "MEDIUM"
        _default_rec = (
            "Review the third-party breach, assess whether vendor has access to customer data, "
            "revoke shared credentials, and monitor for follow-on activity."
            if incident_id is not None
            else "Review the incident, patch affected systems, and monitor for follow-on activity"
        )
        ai_recommendations = [_default_rec]
        confidence = "60"



    final_score = calculate_score(
        severity,
        correlation_risk
    )



    evidence = {

        "source": "Ransomware.live" if incident_id is not None else "NVD",

        "event": title,

        "technology": technology,

        "version": version,

        "vendor": vendor,

        "criticality": criticality,

        "internet_exposed": internet_exposed,

        "sensitive_data": sensitive_data,

        "correlation_confidence": correlation_confidence,

        "correlation_risk": correlation_risk

    }



    recommendations = ai_recommendations

    business_relevance = (

        f"{technology} {version} "

        f"is classified as {criticality}. "

        f"Internet exposure={internet_exposed}. "

        f"Sensitive data={sensitive_data}. "

        "Risk calculated using asset correlation."

    )



    cur.execute(
        """
        INSERT INTO assessments
        (
            customer_id,
            event_id,
            technology,
            vendor,
            threat_summary,
            severity,
            risk_score,
            exploitation_risk,
            recommendations,
            intel_source,
            intel_type,
            confidence,
            business_relevance,
            evidence,
            third_party_incident_id,
            affected_third_party,
            ransomware_group
        )
        VALUES
        (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        RETURNING id
        """,
        (
            customer_id,
            event_id,
            technology,
            vendor,
            threat_summary,
            severity,
            final_score,
            exploitation_risk,
            json.dumps(recommendations),
            "Ransomware.live" if incident_id is not None else "NVD",
            "ThirdPartyIncident" if incident_id is not None else "Vulnerability",
            str(confidence),
            str(business_relevance),
            json.dumps(json.loads(json.dumps(evidence))),
            incident_id,
            incident_victim_name if incident_id is not None else None,
            incident_group_name if incident_id is not None else None,
        )
    )

    new_assessment_id = cur.fetchone()[0]

    # Tag MITRE ATT&CK techniques in the same transaction
    tag_assessment_techniques(new_assessment_id, threat_summary, cur)

    # Build hunting_guidance from matched techniques
    cur.execute("""
        SELECT at.technique_id, atk.name as technique_name
        FROM assessment_techniques at
        JOIN attack_techniques atk ON at.technique_id = atk.technique_id
        WHERE at.assessment_id = %s
    """, (new_assessment_id,))
    
    matched_techniques = []
    for row in cur.fetchall():
        technique_id, technique_name = row
        matched_techniques.append({
            "technique_id": technique_id,
            "technique_name": technique_name
        })
    
    hunting_guidance = build_hunting_guidance_json(matched_techniques) if matched_techniques else None

    # Update assessment with hunting_guidance
    cur.execute("""
        UPDATE assessments
        SET hunting_guidance = %s
        WHERE id = %s
    """, (hunting_guidance, new_assessment_id))



    conn.commit()



    logger.info(f"[AI ASSESSMENT CREATED] Risk: {final_score}")



    cur.close()
    conn.close()

    # Trigger automatic alert generation for high-risk, real-asset matches
    if final_score >= 70 and matches and matches[0].get("technology") != "Unknown":
        logger.info("[AI ASSESSMENT ENGINE] High risk detected. Creating alert...")
        from app.risk.vulnerability_applicability import assess_vulnerability_applicability
        
        # We pass the same assets array that matched
        # (vulnerability_applicability handles pulling out the top match)
        assess_vulnerability_applicability(
            customer_id=customer_id,
            vulnerability_title=title,
            assets=matches
        )




if __name__ == "__main__":


    generate_assessment(
        53,
        "Apache HTTP Server 2.4.49 Remote Code Execution Vulnerability",
        "CRITICAL"
    )