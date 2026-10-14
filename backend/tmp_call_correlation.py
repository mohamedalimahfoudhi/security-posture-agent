import json
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6IkFkbWluIiwiY3VzdG9tZXJfaWQiOjEsImV4cCI6MTc4NTYzNDAyMX0.3XJDp1Abx810VV4fim6nhXkYGsIXbseGNHbeDFtxTXc"}

response = client.post("/api/threat-intel/correlate", headers=headers)
print('status', response.status_code)
try:
    print(response.json())
except Exception:
    print(response.text)
