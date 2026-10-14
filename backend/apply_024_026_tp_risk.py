"""
Migration 024-026: Third-Party Risk Correlation Layer (database foundation).

Applies in order:
  024  extend customer_vendors with business context columns
  025  create threat_events unified abstraction
  026  create third_party_exposures neutral model

Then backfills threat_events from existing cve_events and threat_articles so the
new abstraction is immediately populated from current data. This is purely
additive: existing tables, assets, vendor_id mappings, assessments, and APIs
are untouched.

Run (after apply_018_020_vendor_identity.py):
  python apply_024_026_tp_risk.py
"""
import os
import sys
import json

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from app.database.connection import get_connection

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
MIGRATIONS_DIR = os.path.join(BACKEND_DIR, "migrations")


def read_sql(filename):
    path = os.path.join(MIGRATIONS_DIR, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Migration file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def apply_sql(conn, cur, filename):
    sql = read_sql(filename)
    print(f"  Applying {filename} ...")
    cur.execute(sql)
    conn.commit()
    print(f"  Applied {filename}")


def table_exists(cur, name):
    cur.execute(
        "SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=%s",
        (name,),
    )
    return cur.fetchone() is not None


def column_exists(cur, table, col):
    cur.execute(
        "SELECT 1 FROM information_schema.columns WHERE table_name=%s AND column_name=%s",
        (table, col),
    )
    return cur.fetchone() is not None


def seed_threat_events_from_cve_events(conn, cur):
    """Backfill threat_events rows from cve_events (source_type='cve')."""
    if not table_exists(cur, "cve_events"):
        print("  [SKIP] cve_events table not present")
        return 0
    if not column_exists(cur, "threat_events", "source_id"):
        print("  [SKIP] threat_events.source_id not present")
        return 0

    cur.execute("""
        SELECT e.id, e.title, e.description, e.cve_id, e.cvss_score, e.severity,
               e.published_date, e.source_url
        FROM cve_events e
        WHERE NOT EXISTS (
            SELECT 1 FROM threat_events te
            WHERE te.source_type = 'cve' AND te.source_id = e.id
        )
    """)
    rows = cur.fetchall()
    inserted = 0
    for r in rows:
        (eid, title, desc, cve_id, cvss, severity, published, url) = r
        cur.execute("""
            INSERT INTO threat_events
                (source_type, source_id, title, description, cve_id, cvss_score,
                 severity, confidence, published_date, source_url, raw_metadata,
                 correlated, correlation_count)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, FALSE, 0)
        """, (
            "cve", eid, title or cve_id or "CVE Event", desc, cve_id, cvss,
            severity or "UNKNOWN", 0.0, published, url,
            json.dumps({"source": "cve_events", "source_id": eid}),
        ))
        inserted += 1
    conn.commit()
    return inserted


def seed_threat_events_from_articles(conn, cur):
    """Backfill threat_events rows from processed threat_articles (source_type='threat_article')."""
    if not table_exists(cur, "threat_articles"):
        print("  [SKIP] threat_articles table not present")
        return 0
    if not column_exists(cur, "threat_articles", "vendors"):
        print("  [SKIP] threat_articles.vendors not present")
        return 0

    cur.execute("""
        SELECT a.id, a.title, a.summary, a.severity, a.confidence,
               a.published_date, a.url, a.vendors, a.products, a.cves,
               a.affected_technologies, a.metadata
        FROM threat_articles a
        WHERE a.processed = TRUE
          AND NOT EXISTS (
            SELECT 1 FROM threat_events te
            WHERE te.source_type = 'threat_article' AND te.source_id = a.id
          )
    """)
    rows = cur.fetchall()
    inserted = 0
    for r in rows:
        (aid, title, summary, severity, conf, published, url, vendors, products,
         cves, affected_tech, metadata) = r

        def to_list(value):
            if not value:
                return []
            if isinstance(value, list):
                return value
            if isinstance(value, str):
                try:
                    parsed = json.loads(value)
                    return parsed if isinstance(parsed, list) else [value]
                except (json.JSONDecodeError, TypeError):
                    return [value]
            return []

        vendor_list = to_list(vendors)
        product_list = to_list(products)
        cve_list = to_list(cves)
        tech_list = to_list(affected_tech)

        # First CVE id from the cves array -> cve_id
        cve_id = None
        for c in cve_list:
            s = str(c).strip()
            if s.upper().startswith("CVE-"):
                cve_id = s
                break

        # Build raw_metadata preserving MITRE technique IDs if present
        raw_meta = {"source": "threat_articles", "source_id": aid, "metadata": metadata}
        if isinstance(metadata, dict) and metadata.get("mitre_techniques"):
            raw_meta["mitre_techniques"] = metadata["mitre_techniques"]
        
        cur.execute("""
            INSERT INTO threat_events
                (source_type, source_id, title, description, cve_id, cvss_score,
                 severity, confidence, affected_vendors, affected_products,
                 affected_technologies, published_date, source_url, raw_metadata,
                 correlated, correlation_count)
            VALUES (%s, %s, %s, %s, %s, NULL, %s, %s, %s, %s, %s, %s, %s, %s, FALSE, 0)
        """,
                (
                    "threat_article", aid, title or "Threat Article", summary or "",
                    cve_id, severity or "UNKNOWN", float(conf or 0.0),
                    vendor_list, product_list, tech_list, published, url,
                    json.dumps(raw_meta),
                ))
        inserted += 1
    conn.commit()
    return inserted


def main():
    conn = get_connection()
    cur = conn.cursor()
    try:
        print("=== Third-Party Risk Correlation Layer (DB foundation) 024-026 ===")

        print("\n[1/3] Applying migrations")
        apply_sql(conn, cur, "024_extend_customer_vendors.sql")
        apply_sql(conn, cur, "025_create_threat_events.sql")
        apply_sql(conn, cur, "026_create_third_party_exposures.sql")

        print("\n[2/3] Backfilling threat_events from cve_events")
        n_cve = seed_threat_events_from_cve_events(conn, cur)
        print(f"  Inserted {n_cve} cve threat_events")

        print("\n[3/3] Backfilling threat_events from processed threat_articles")
        n_articles = seed_threat_events_from_articles(conn, cur)
        print(f"  Inserted {n_articles} threat_article events")

        # Summary
        cur.execute("SELECT COUNT(*) FROM threat_events")
        total_events = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM threat_events WHERE source_type='cve'")
        cve_events = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM threat_events WHERE source_type='threat_article'")
        article_events = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM customer_vendors")
        cv_total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM third_party_exposures")
        exposures = cur.fetchone()[0]

        print("\n=== SUMMARY ===")
        print(f"  threat_events total:          {total_events}")
        print(f"    - cve:                       {cve_events}")
        print(f"    - threat_article:            {article_events}")
        print(f"  customer_vendors rows:         {cv_total} (business columns added)")
        print(f"  third_party_exposures rows:    {exposures} (empty until correlation engine runs)")

        print("\n=== SAMPLE threat_events ===")
        cur.execute("""
            SELECT id, source_type, source_id, title, severity, cve_id, correlated
            FROM threat_events ORDER BY id LIMIT 10
        """)
        for r in cur.fetchall():
            print(f"  #{r[0]} {r[1]:14s} src={r[2]} sev={r[4]} cve={r[5]} correlated={r[6]} :: {(r[3] or '')[:60]}")

        print("\nThird-Party Risk correlation DB foundation complete.")
        print("NOTE: third_party_exposures is empty until the correlation engine populates it.")
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    main()
