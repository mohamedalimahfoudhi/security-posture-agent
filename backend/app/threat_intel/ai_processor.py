import json
import logging
import re
from typing import Any, Dict, List, Optional

from app.ai.ollama_client import ask_mistral_with_fallback

logger = logging.getLogger(__name__)

# Maximum time to wait for Ollama enrichment before giving up
# Use a bounded timeout to prevent scheduler hanging
AI_ENRICHMENT_TIMEOUT = 10  # seconds

THREAT_INTEL_ANALYSIS_PROMPT = """
You are a SOC analyst and Cyber Threat Intelligence expert.

Analyze the article below and produce a structured intelligence summary in JSON only.

Input:
Article title:
{title}

Article content:
{content}

Output JSON must include these exact fields:
{{
  "summary": "2-4 sentence SOC analyst summary explaining what happened and why it matters",
  "threat_type": "",
  "severity": "",
  "vendors": [],
  "products": [],
  "cves": [],
  "malware": [],
  "threat_actors": [],
  "mitre_techniques": [],
  "attack_scenario": "",
  "technical_impact": "",
  "exploitation_context": "",
  "affected_technologies": [],
  "customer_relevance": "",
  "recommendation": "",
  "confidence": 0
}}

Use the following guidance:
- "summary" must be a meaningful 2-4 sentence SOC analyst briefing.
- Explain what happened, who is affected, and why it matters.
- If article content is limited, summarize based on the title and available content.
- Avoid vague phrases like "the article reports" or "this is a cybersecurity issue." Be specific.
- "threat_type" should describe the primary threat category or actor method.
- "severity" should be LOW, MEDIUM, HIGH, or CRITICAL.
- Use exact lists for "vendors", "products", "cves", "malware", "threat_actors", "mitre_techniques", and "affected_technologies".
- "attack_scenario" should describe the likely adversary behavior or exploitation path.
- "technical_impact" should explain the systems, data, or operational effects of the threat.
- "exploitation_context" should describe how the threat is being exploited or delivered.
- "customer_relevance" should explain why this threat matters for customers and which assets or teams are at risk.
- If a field is not present, return an empty list or blank string; do not invent details.
- "recommendation" must be actionable SOC guidance with concrete defender actions such as patch affected systems, investigate authentication or network logs, block malicious domains/IPs, isolate affected hosts, update security controls, or monitor affected vendors/products.
- Use strong verbs like patch, investigate, review, block, isolate, scan, validate, monitor, or contain.
- If no direct mitigation is described, provide specific monitoring or investigation guidance tied to the threat and the affected environment.
- Avoid generic language like "users should", "this article", or "for more information." Recommendations should address what defenders should do.
- "confidence" should be a number between 0 and 100.
- The summary and recommendation must never be empty.

Answer only with valid JSON. Do not include markdown, explanations, or extra text outside the JSON object.
"""

THREAT_INTEL_RETRY_INSTRUCTIONS = """
The previous output did not provide a usable summary or recommendation.
Retry the same structured intelligence extraction using the title and available content.
Ensure the "summary" field is 2-4 sentences and the "recommendation" field contains actionable SOC guidance.
If no direct mitigation is available, provide monitoring or investigation guidance tied to the threat.
Use the title to infer context if the article content is limited.
Return only valid JSON and nothing else.
"""


def _extract_json_object(text: str) -> Dict[str, Any]:
    if isinstance(text, dict):
        return text

    if not isinstance(text, str):
        raise ValueError("AI response is not a string")

    cleaned = text.strip()

    # If the model returns markdown code fences, strip them.
    if cleaned.startswith("```") and cleaned.endswith("```"):
        cleaned = cleaned[3:-3].strip()

    # Remove any surrounding markdown fences or prefixes.
    cleaned = re.sub(r"^```json\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^```\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned, flags=re.IGNORECASE)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        # Try to find the first JSON object in the response.
        json_start = cleaned.find("{")
        json_end = cleaned.rfind("}")
        if json_start == -1 or json_end == -1 or json_end <= json_start:
            raise ValueError("Unable to find JSON object in AI response")

        candidate = cleaned[json_start:json_end + 1]
        # Normalize common malformed text characters.
        candidate = candidate.replace("\n", " ")
        try:
            return json.loads(candidate)
        except json.JSONDecodeError as exc:
            # Attempt to fix trailing commas.
            candidate = re.sub(r",\s*([}\]])", r"\1", candidate)
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                raise ValueError(f"Unable to parse JSON from AI response: {exc}") from exc


def _ensure_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return []
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except json.JSONDecodeError:
            pass
        # fallback: comma-separated text
        return [item.strip() for item in re.split(r"[,;\n]", value) if item.strip()]
    return [str(value).strip()]


def _normalize_confidence(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except Exception:
        return 0.0


def _normalize_severity(value: Any) -> str:
    if not value:
        return ""
    severity = str(value).strip().upper()
    if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return severity
    if severity.startswith("CRIT"):
        return "CRITICAL"
    if severity.startswith("HIGH"):
        return "HIGH"
    if severity.startswith("MED"):
        return "MEDIUM"
    if severity.startswith("LOW"):
        return "LOW"
    return ""


def _extract_cves(value: Any) -> List[str]:
    items = _ensure_list(value)
    cves: List[str] = []
    for item in items:
        for match in re.findall(r"CVE-\d{4}-\d{4,7}", item.upper()):
            if match not in cves:
                cves.append(match)
    return cves


class ThreatIntelAIProcessor:
    def analyze_article(self, title: str, content: Optional[str]) -> Dict[str, Any]:
        prompt = THREAT_INTEL_ANALYSIS_PROMPT.format(
            title=title or "",
            content=content or ""
        )

        logger.info("[THREAT INTEL AI] Sending article for analysis")
        
        try:
            # Initial AI request with bounded timeout
            response = ask_mistral_with_fallback(prompt, timeout=AI_ENRICHMENT_TIMEOUT)
            raw_response = response.get("response") if isinstance(response, dict) else response

            parsed = _extract_json_object(raw_response)
            normalized = self._normalize_output(parsed)
            weak_recommendation = self._is_generic_recommendation(normalized["recommendation"], title)

            # At most ONE retry if summary is empty or recommendation is weak
            if not normalized["summary"] or weak_recommendation:
                logger.warning("[THREAT INTEL AI] Empty or weak summary/recommendation detected; retrying with stronger guidance (attempt 2 of 2)")
                retry_prompt = self._build_retry_prompt(title, content)
                try:
                    response = ask_mistral_with_fallback(retry_prompt, timeout=AI_ENRICHMENT_TIMEOUT)
                    raw_response = response.get("response") if isinstance(response, dict) else response
                    parsed = _extract_json_object(raw_response)
                    normalized = self._normalize_output(parsed)
                    weak_recommendation = self._is_generic_recommendation(normalized["recommendation"], title)
                except Exception as retry_error:
                    logger.warning(f"[THREAT INTEL AI] Retry attempt failed: {retry_error}")
                    logger.warning("[THREAT INTEL AI] AI enrichment exhausted; using deterministic fallback")
                    return self._generate_fallback_enrichment(title, content)

            # After retry, use fallback for any remaining weak/empty fields
            if not normalized["summary"]:
                logger.warning("[THREAT INTEL AI] Summary still empty after retry; using fallback summary")
                normalized["summary"] = self._generate_fallback_summary(title, content)

            if not normalized["recommendation"] or weak_recommendation:
                logger.warning("[THREAT INTEL AI] Recommendation empty or weak after retry; using fallback recommendation")
                normalized["recommendation"] = self._generate_fallback_recommendation(
                    normalized["threat_type"],
                    normalized["severity"],
                    normalized["vendors"],
                    normalized["summary"]
                )

            return normalized
            
        except Exception as e:
            logger.error(f"[THREAT INTEL AI] AI enrichment attempt failed for article '{title[:50]}...': {e}")
            logger.warning("[THREAT INTEL AI] AI enrichment exhausted; using deterministic fallback")
            
            # Return a safe fallback structure when AI fails completely
            return self._generate_fallback_enrichment(title, content)

    def _build_retry_prompt(self, title: str, content: Optional[str]) -> str:
        return (
            THREAT_INTEL_ANALYSIS_PROMPT.format(
                title=title or "",
                content=content or ""
            )
            + "\n\n"
            + THREAT_INTEL_RETRY_INSTRUCTIONS
        )

    def _generate_fallback_summary(self, title: str, content: Optional[str]) -> str:
        title_text = title.strip() if title else ""
        content_text = " ".join((content or "").split())
        summary_parts: List[str] = []

        if title_text:
            summary_parts.append(f"{title_text}.")

        if content_text:
            sentences = re.split(r'(?<=[.!?])\s+', content_text)
            for sentence in sentences:
                cleaned = sentence.strip()
                if cleaned and cleaned != title_text and len(summary_parts) < 3:
                    summary_parts.append(cleaned)
                if len(summary_parts) >= 3:
                    break

        if len(summary_parts) == 0:
            return "This article describes a cybersecurity incident or threat intelligence item relevant to defenders."

        if len(summary_parts) == 1:
            return f"{summary_parts[0]} The article highlights the risk and the key defender action needed."

        summary = " ".join(summary_parts)
        if summary.count('.') < 2:
            summary = summary.rstrip('.') + '. The report explains the likely impact and recommended action.'

        return summary.strip()

    def _is_generic_recommendation(self, recommendation: str, title: str) -> bool:
        if not recommendation:
            return True
        normalized = recommendation.strip().lower()
        if not normalized:
            return True

        # Reject placeholder/template text
        placeholder_patterns = [
            "2-4 sentence",
            "soc analyst summary",
            "explaining what happened",
            "why it matters",
            "answer only with valid json",
            "do not include markdown",
            "use the following guidance"
        ]
        if any(pattern in normalized for pattern in placeholder_patterns):
            return True

        action_verbs = [
            "patch",
            "investigate",
            "review",
            "block",
            "isolate",
            "scan",
            "validate",
            "monitor",
            "contain",
            "update",
            "audit",
            "assess",
            "verify",
            "disconnect",
            "quarantine",
            "remediate"
        ]

        if not any(verb in normalized for verb in action_verbs):
            return True

        generic_phrases = [
            "as appropriate",
            "stay informed",
            "for more information",
            "for further",
            "this article",
            "users should",
            "customers should",
            "no action",
            "consider",
            "monitor the situation",
            "review this report",
            "follow up",
            "should be cautious",
            "should continue to monitor",
            "should continue",
            "should be aware"
        ]
        if any(phrase in normalized for phrase in generic_phrases):
            return True

        title_text = title.strip().lower()
        if title_text and normalized == title_text:
            return True
        if len(normalized) < 20:
            return True
        return False

    def _generate_fallback_recommendation(
        self,
        threat_type: str,
        severity: str,
        vendors: List[str],
        summary: str
    ) -> str:
        threat_type = threat_type.strip().lower()
        severity_text = (severity or "LOW").strip().upper()
        vendor_text = ", ".join(vendors) if vendors else "affected vendors or products"

        if not threat_type:
            if severity_text in {"HIGH", "CRITICAL"}:
                return "Investigate this incident immediately, review relevant logs, and isolate any affected systems."
            return "Monitor the threat, review authentication and network logs, and validate whether any affected vendors or products are impacted."

        if "phishing" in threat_type:
            return "Review email and authentication logs for suspicious access attempts, block related phishing domains, and strengthen phishing awareness controls."
        if "ransomware" in threat_type or "extortion" in threat_type:
            return "Isolate affected systems, verify backups, review logs for lateral movement, and block any discovered command-and-control infrastructure."
        if "malware" in threat_type or "backdoor" in threat_type or "loader" in threat_type:
            return "Scan endpoints for the malware family, review persistence mechanisms, and block related command-and-control infrastructure."
        if "vulnerability" in threat_type or "exploit" in threat_type:
            return f"Patch affected systems, review vulnerability exposure for {vendor_text}, and monitor for exploitation attempts."
        if "data breach" in threat_type or "leak" in threat_type:
            return "Review access logs, validate whether sensitive data was exposed, and monitor for signs of credential misuse."
        if "policy" in threat_type or "compliance" in threat_type:
            return "Review policy controls for the affected environment and update security policies to reduce risk."
        if "threat" in threat_type or "attack" in threat_type or "incident" in threat_type:
            return "Investigate indicators of compromise, review relevant security logs, and apply containment measures to affected systems."

        if severity_text in {"HIGH", "CRITICAL"}:
            return f"Prioritize this threat, investigate logs, and implement containment or mitigation for {vendor_text}."

        return f"Monitor this threat, review logs for suspicious activity, and verify whether the described vendors or products are impacted."

    def _generate_fallback_enrichment(self, title: str, content: Optional[str]) -> Dict[str, Any]:
        """Generate a safe fallback enrichment structure when AI is unavailable.
        
        This ensures collection can continue even when Ollama times out or fails.
        The fallback uses basic metadata from the source article without fabricating
        AI-generated analysis.
        """
        title_text = title.strip() if title else "Unknown Threat"
        
        return {
            "summary": self._generate_fallback_summary(title, content),
            "threat_type": "",
            "severity": "",
            "vendors": [],
            "products": [],
            "cves": [],
            "malware": [],
            "threat_actors": [],
            "mitre_techniques": [],
            "attack_scenario": "",
            "technical_impact": "",
            "exploitation_context": "",
            "affected_technologies": [],
            "customer_relevance": "",
            "recommendation": self._generate_fallback_recommendation("", "", [], ""),
            "confidence": 0.0,
        }

    def _normalize_output(self, raw_output: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "summary": str(raw_output.get("summary") or raw_output.get("threat_summary") or "").strip(),
            "threat_type": str(raw_output.get("threat_type") or "").strip(),
            "severity": _normalize_severity(raw_output.get("severity") or raw_output.get("severity_level") or ""),
            "vendors": _ensure_list(raw_output.get("vendors") or raw_output.get("vendor")),
            "products": _ensure_list(raw_output.get("products") or raw_output.get("product")),
            "cves": _extract_cves(raw_output.get("cves") or raw_output.get("cve")),
            "malware": _ensure_list(raw_output.get("malware") or raw_output.get("malware_families") or raw_output.get("malware_family")),
            "threat_actors": _ensure_list(raw_output.get("threat_actors") or raw_output.get("threat_actor") or raw_output.get("actors")),
            "mitre_techniques": _ensure_list(raw_output.get("mitre_techniques") or raw_output.get("techniques") or raw_output.get("mitre")),
            "attack_scenario": str(raw_output.get("attack_scenario") or raw_output.get("attack_scenarios") or "").strip(),
            "technical_impact": str(raw_output.get("technical_impact") or raw_output.get("impact_analysis") or "").strip(),
            "exploitation_context": str(raw_output.get("exploitation_context") or raw_output.get("exploit_context") or "").strip(),
            "affected_technologies": _ensure_list(raw_output.get("affected_technologies") or raw_output.get("affected_technology") or raw_output.get("technologies") or raw_output.get("platforms")),
            "customer_relevance": str(raw_output.get("customer_relevance") or raw_output.get("customer_context") or "").strip(),
            "recommendation": str(raw_output.get("recommendation") or raw_output.get("recommendations") or "").strip(),
            "confidence": _normalize_confidence(raw_output.get("confidence") or raw_output.get("confidence_score") or raw_output.get("confidence_percent")),
        }
