from .ollama_client import ask_mistral
from .prompts import SYSTEM_PROMPT
import json
import re


def _extract_json(text):
    # Try to find the first JSON object in text
    try:
        start = text.index('{')
        end = text.rindex('}')
        candidate = text[start:end+1]
        return json.loads(candidate)
    except Exception:
        raise


def analyze_cve(context):

    # Accept either a dict containing 'prompt' or a raw string/context
    if isinstance(context, dict) and 'prompt' in context:
        context_text = context.get('prompt')
    else:
        context_text = context

    prompt = f"""
{SYSTEM_PROMPT}

Analyze this cybersecurity vulnerability or question.

User input:
{context_text}

If the user asked a general question (non-CVE), provide the structured JSON fields and also include a brief human-readable summary in the "notes" field.

Return JSON only.
"""

    response = ask_mistral(prompt)

    def _ensure_notes(d):
        try:
            if isinstance(d, dict) and ( 'notes' not in d or not d.get('notes') ):
                summary = d.get('threat_summary') or ''
                severity = d.get('severity') or ''
                score = d.get('risk_score')
                parts = []
                if summary:
                    parts.append(summary)
                if severity:
                    parts.append(f"Severity: {severity}")
                if score is not None:
                    parts.append(f"Risk score: {score}")
                d['notes'] = '. '.join(parts) if parts else ''
        except Exception:
            pass
        return d

    try:
        # Primary path: model returns clean JSON
        parsed = json.loads(response["response"])
        return _ensure_notes(parsed)

    except (json.JSONDecodeError, TypeError):
        # Try to extract JSON object from the raw response text as a fallback
        try:
            raw = response.get('response') if isinstance(response, dict) else response
            if isinstance(raw, dict):
                return _ensure_notes(raw)
            parsed = _extract_json(raw)
            return _ensure_notes(parsed)
        except Exception:
            return {
                "error": "Invalid JSON from AI",
                "raw_response": response
            }