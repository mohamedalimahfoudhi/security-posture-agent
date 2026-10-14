import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6IkFkbWluIiwiY3VzdG9tZXJfaWQiOjEsImV4cCI6MTc4NTYzNjIxM30.0CSYOjCyrosWjh3hagvD9CjMfRI3l-JsULjjxKsP0VE"

paths = ["/", "/api/threat-intel/articles?page=1&limit=1", "/api/threat-intel/correlations?page=1&limit=1"]

for path in paths:
    url = BASE_URL + path
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {TOKEN}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print("PATH", path)
            print("STATUS", resp.status)
            print(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print("PATH", path)
        print("HTTP ERROR", e.code)
        print(e.read().decode("utf-8"))
    except Exception as e:
        print("PATH", path)
        print("ERROR", repr(e))
