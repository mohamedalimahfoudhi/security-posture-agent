import py_compile
import traceback

files = [
    'app/threat_intel/sources/hibp.py',
    'app/threat_intel/sources/leakcheck.py',
    'app/threat_intel/sources/databreach.py',
    'app/threat_intel/service.py',
    'app/threat_intel/router.py',
    'app/threat_intel/scheduler.py',
    'tests/test_data_breach_intelligence.py',
    'app/ai/graph_rag.py',
    'app/correlation/third_party_alert_engine.py',
    'app/correlation/third_party_correlation.py',
]

with open('_syntax_result.txt', 'w') as out:
    ok = True
    for f in files:
        try:
            py_compile.compile(f, doraise=True)
            out.write(f"OK   {f}\n")
        except Exception as e:
            ok = False
            out.write(f"FAIL {f}: {e}\n")
    out.write(f"\n{'ALL COMPILE OK' if ok else 'COMPILE ERRORS PRESENT'}\n")
