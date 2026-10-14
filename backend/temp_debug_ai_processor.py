import sys
import json

sys.path.insert(0, r'C:\Users\mahfo\Projects\third-party-cyber-posture-agent\backend')
from app.database.connection import get_connection
from app.threat_intel.ai_processor import ThreatIntelAIProcessor

conn = get_connection()
cur = conn.cursor()
cur.execute('SELECT id, title, content FROM threat_articles WHERE processed = false ORDER BY published_date DESC NULLS LAST, created_at DESC LIMIT 1')
row = cur.fetchone()
cur.close()
conn.close()

if not row:
    raise SystemExit('No unprocessed article found')
article_id, title, content = row
print('article_id:', article_id)
print('title:', title)
print('content preview:', (content or '')[:500].replace('\n', '\\n'))

processor = ThreatIntelAIProcessor()

try:
    response = processor.ai_processor.ask_mistral_with_fallback(processor.THREAT_INTEL_ANALYSIS_PROMPT.format(title=title or '', content=content or ''))
    print('raw response type:', type(response))
    print('raw response keys:', list(response.keys()) if isinstance(response, dict) else 'n/a')
    print('raw response body:', response.get('response') if isinstance(response, dict) else response)
except Exception as e:
    print('ask_mistral_with_fallback exception:', repr(e))
    import traceback
    traceback.print_exc()

try:
    result = processor.analyze_article(title, content)
    print('analyze_article result:', json.dumps(result, indent=2))
except Exception as e:
    print('analyze_article exception:', repr(e))
    import traceback
    traceback.print_exc()
