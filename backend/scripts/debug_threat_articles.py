import sys
sys.path.insert(0, '.')
from app.threat_intel.service import ThreatIntelService

service = ThreatIntelService()
try:
    result = service.list_articles(page=1, limit=1)
    print(result)
except Exception as e:
    import traceback
    traceback.print_exc()
