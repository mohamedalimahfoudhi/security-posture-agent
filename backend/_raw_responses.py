"""Capture raw LLM responses for article 1014 across models (read-only)."""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

from app.database.connection import get_connection
from app.threat_intel.ai_processor import THREAT_INTEL_ANALYSIS_PROMPT
from app.ai.ollama_client import ask_mistral

# Get article 1014
conn = get_connection()
cur = conn.cursor()
cur.execute("SELECT title, content FROM threat_articles WHERE id = 1014")
title, content = cur.fetchone()
cur.close()
conn.close()

prompt = THREAT_INTEL_ANALYSIS_PROMPT.format(title=title or "", content=content or "")

for model in ["qwen2.5:0.5b", "phi3:mini", "mistral:latest"]:
    print("=" * 70)
    print(f"MODEL: {model}")
    print("=" * 70)
    try:
        res = ask_mistral(prompt, model=model, timeout=120)
        raw = res["response"]
        print("RAW RESPONSE:")
        print(raw)
        print("---")
        try:
            parsed = json.loads(raw)
            print("JSON PARSE: OK")
            print("  severity:", parsed.get("severity"))
            print("  summary:", (parsed.get("summary") or "")[:120])
            print("  threat_type:", parsed.get("threat_type"))
            print("  confidence:", parsed.get("confidence"))
        except Exception as e:
            print("JSON PARSE FAILED:", e)
    except Exception as e:
        print("MODEL CALL FAILED:", type(e).__name__, str(e)[:200])
    print()
