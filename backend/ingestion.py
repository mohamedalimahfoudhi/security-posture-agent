import psycopg2
import requests
import json
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

OLLAMA_URL = "http://localhost:11434/api/embeddings"
EMBED_MODEL = "nomic-embed-text"

def get_embedding(text: str):
    response = requests.post(
        OLLAMA_URL,
        json={"model": EMBED_MODEL, "prompt": text},
        timeout=30
    )
    response.raise_for_status()
    return response.json().get("embedding")

def ingest():
    conn = psycopg2.connect(
        dbname=os.getenv("DB_NAME", "ai_tip"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        connect_timeout=10
    )
    cur = conn.cursor()

    # 1. Assessments
    cur.execute("""
        SELECT a.id, a.customer_id, a.risk_score, a.severity, e.title
        FROM assessments a
        JOIN cve_events e ON a.event_id = e.id
    """)
    assessments = cur.fetchall()
    
    for aid, cid, risk, sev, title in assessments:
        content = f"Vulnerability Assessment for {title}: Severity is {sev}, calculated risk score is {risk}."
        emb = get_embedding(content)
        cur.execute("""
            INSERT INTO knowledge_chunks (source_type, source_id, customer_id, content_text, embedding)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (source_type, source_id) 
            DO UPDATE SET content_text = EXCLUDED.content_text, embedding = EXCLUDED.embedding
        """, ("assessment", aid, cid, content, json.dumps(emb)))
    conn.commit()
    logger.info(f"Ingested {len(assessments)} assessments.")

    # 2. Alerts
    cur.execute("""
        SELECT id, customer_id, title, risk_level, risk_score, ai_summary, business_impact, recommendation
        FROM alerts
    """)
    alerts = cur.fetchall()
    for row in alerts:
        aid, cid, title, risk_lvl, risk_score, summary, impact, rec = row
        content = f"Security Alert: {title}. Risk level {risk_lvl} ({risk_score}). Summary: {summary}. Business impact: {impact}. Recommendation: {rec}."
        emb = get_embedding(content)
        cur.execute("""
            INSERT INTO knowledge_chunks (source_type, source_id, customer_id, content_text, embedding)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (source_type, source_id) 
            DO UPDATE SET content_text = EXCLUDED.content_text, embedding = EXCLUDED.embedding
        """, ("alert", aid, cid, content, json.dumps(emb)))
    conn.commit()
    logger.info(f"Ingested {len(alerts)} alerts.")

    # 3. Third-party incidents
    cur.execute("""
        SELECT id, customer_id, incident_type, victim, group_name, disclosure_date
        FROM third_party_incidents
        ORDER BY id DESC LIMIT 30
    """)
    incidents = cur.fetchall()
    for row in incidents:
        iid, cid, itype, victim, group, ddate = row
        content = f"Third-Party Incident affecting {victim} on {ddate}: {itype}. Threat actor: {group}."
        emb = get_embedding(content)
        cur.execute("""
            INSERT INTO knowledge_chunks (source_type, source_id, customer_id, content_text, embedding)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (source_type, source_id) 
            DO UPDATE SET content_text = EXCLUDED.content_text, embedding = EXCLUDED.embedding
        """, ("incident", iid, cid, content, json.dumps(emb)))
        conn.commit()
    logger.info(f"Ingested {len(incidents)} incidents.")

    conn.commit()
    cur.close()
    conn.close()

if __name__ == "__main__":
    ingest()
