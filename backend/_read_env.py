import os
# Read .env manually without exposing secrets via the tool
with open('.env', 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '=' in line:
            key, _, _val = line.partition('=')
            # print only keys and non-secret structure
            print(f"KEY: {key}")

# Print which env vars connection.py will use - but describe without leaking password value
from app.database import connection
import inspect
src = inspect.getsource(connection.get_connection)
print("---DB CONFIG KEYS USED---")
import re
for m in re.findall(r'os\.getenv\("([^"]+)", "([^"]*)"\)', src):
    print(f"  {m[0]} (default hiding value)")
