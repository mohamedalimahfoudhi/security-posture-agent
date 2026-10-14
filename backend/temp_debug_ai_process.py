import sys
import traceback

sys.path.insert(0, r'C:\Users\mahfo\Projects\third-party-cyber-posture-agent\backend')
from app.threat_intel.service import ThreatIntelService

service = ThreatIntelService()

try:
    print('Starting process_unprocessed_articles debug...')
    result = service.process_unprocessed_articles(limit=5)
    print('Result:', result)
except Exception as e:
    print('process_unprocessed_articles raised exception:', repr(e))
    traceback.print_exc()
