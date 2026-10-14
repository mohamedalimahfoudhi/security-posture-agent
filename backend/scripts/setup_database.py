#!/usr/bin/env python3
"""Create and validate a reproducible AI-TIP development database.

Run from the repository root on Windows or any supported platform:
    python backend/scripts/setup_database.py
    python backend/scripts/setup_database.py --reset --yes

The script reads ``backend/.env`` (or environment variables) and never embeds a
machine-specific host, database, user, password, or external service secret.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import psycopg2
from psycopg2 import sql
from psycopg2.extras import Json
from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_FILE = ROOT / "database" / "ai_tip_schema.sql"
EXPECTED_TABLES = {
    "customers", "users", "vendors", "vendor_aliases", "customer_vendors",
    "documents", "assets", "cve_events", "assessments", "alerts",
    "attack_techniques", "assessment_techniques", "knowledge_chunks",
    "threat_articles", "threat_correlations", "threat_events",
    "third_party_exposures", "third_party_profiles",
    "third_party_profile_technologies", "third_party_profile_services",
    "third_party_external_assets", "third_party_architectures",
    "architecture_technologies", "architecture_services", "architecture_changes",
    "third_party_alerts", "third_party_incidents", "weekly_digest_summaries",
    "alert_email_notifications", "chat_messages", "notification_recipients",
    "notification_drafts",
}


class SetupError(RuntimeError):
    """Raised when setup cannot safely create a usable database."""


class DatabaseSetup:
    def __init__(self, reset: bool, assume_yes: bool):
        load_dotenv(ROOT / "backend" / ".env")
        self.reset = reset
        self.assume_yes = assume_yes
        self.host = os.getenv("DB_HOST", "localhost")
        self.port = os.getenv("DB_PORT", "5432")
        self.name = os.getenv("DB_NAME", "ai_tip")
        self.user = os.getenv("DB_USER", "postgres")
        self.password = os.getenv("DB_PASSWORD")
        if not self.password:
            raise SetupError("DB_PASSWORD is required in backend/.env or the environment.")
        if not SCHEMA_FILE.exists():
            raise SetupError(f"Authoritative schema file is missing: {SCHEMA_FILE}")

    def _connect(self, database: str):
        return psycopg2.connect(
            host=self.host, port=self.port, database=database, user=self.user,
            password=self.password, connect_timeout=10,
        )

    @staticmethod
    def _result(label: str, passed: bool, detail: str = ""):
        state = "PASS" if passed else "FAIL"
        print(f"{label:.<34} {state}" + (f" ({detail})" if detail else ""))

    def _database_exists(self) -> bool:
        with self._connect("postgres") as conn, conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (self.name,))
            return cur.fetchone() is not None

    def _create_database(self):
        conn = self._connect("postgres")
        conn.autocommit = True
        try:
            with conn.cursor() as cur:
                cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(self.name)))
        finally:
            conn.close()

    def _drop_database(self):
        if not self.assume_yes:
            answer = input(
                f"WARNING: This will permanently delete database '{self.name}'. Continue? [y/N] "
            )
            if answer.strip().lower() not in {"y", "yes"}:
                raise SetupError("Reset cancelled.")
        conn = self._connect("postgres")
        conn.autocommit = True
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = %s AND pid <> pg_backend_pid()",
                    (self.name,),
                )
                cur.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(self.name)))
        finally:
            conn.close()

    def _load_schema(self):
        # The schema is a reviewed snapshot, not a pg_dump: it deliberately
        # contains no psql meta-commands or ownership statements.
        schema = SCHEMA_FILE.read_text(encoding="utf-8")
        with self._connect(self.name) as conn, conn.cursor() as cur:
            cur.execute(schema)
            cur.execute(
                "CREATE TABLE IF NOT EXISTS public.schema_migrations "
                "(version VARCHAR(64) PRIMARY KEY, applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)"
            )
            cur.execute(
                "INSERT INTO public.schema_migrations(version) VALUES (%s) ON CONFLICT DO NOTHING",
                ("schema_snapshot_2026_09_15",),
            )

    def _seed_demo_data(self):
        """Insert small, explicitly development-only data required by main UI flows."""
        try:
            from passlib.context import CryptContext
        except ImportError as exc:  # pragma: no cover - reported clearly to handoff users
            raise SetupError("passlib is required; install backend/requirements.txt first.") from exc

        pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
        with self._connect(self.name) as conn, conn.cursor() as cur:
            cur.execute("SELECT id FROM customers WHERE name = 'Demo Customer'")
            customer = cur.fetchone()
            if customer:
                customer_id = customer[0]
            else:
                cur.execute(
                    "INSERT INTO customers(name, industry) VALUES ('Demo Customer', 'Technology') RETURNING id"
                )
                customer_id = cur.fetchone()[0]

            vendor_ids = {}
            for name, category, score in (
                ("Microsoft", "Identity", 78),
                ("Amazon Web Services", "Cloud", 72),
            ):
                cur.execute(
                    "INSERT INTO vendors(name, category, base_risk_score) VALUES (%s, %s, %s) "
                    "ON CONFLICT(name) DO UPDATE SET category=EXCLUDED.category "
                    "RETURNING id",
                    (name, category, score),
                )
                vendor_ids[name] = cur.fetchone()[0]

            relationships = {}
            for name, role, criticality in (
                ("Microsoft", "Identity Provider", "CRITICAL"),
                ("Amazon Web Services", "Cloud Hosting", "HIGH"),
            ):
                cur.execute(
                    """INSERT INTO customer_vendors
                       (customer_id, vendor_id, vendor, relationship_type, data_sensitivity,
                        criticality, base_risk_score)
                       VALUES (%s, %s, %s, %s, 'HIGH', %s, %s)
                       ON CONFLICT(customer_id, vendor_id) DO UPDATE
                       SET vendor=EXCLUDED.vendor RETURNING id""",
                    (customer_id, vendor_ids[name], name, role, criticality,
                     85 if criticality == "CRITICAL" else 72),
                )
                relationships[name] = cur.fetchone()[0]

            profiles = {}
            for name, role, criticality, privileged in (
                ("Microsoft", "Identity Provider", "CRITICAL", True),
                ("Amazon Web Services", "Cloud Hosting", "HIGH", False),
            ):
                cur.execute(
                    """INSERT INTO third_party_profiles
                       (customer_vendor_id, business_role, description, data_access_level,
                        privileged_access, criticality, risk_score)
                       VALUES (%s, %s, %s, 'HIGH', %s, %s, 0)
                       ON CONFLICT(customer_vendor_id) DO UPDATE
                       SET business_role=EXCLUDED.business_role, criticality=EXCLUDED.criticality
                       RETURNING id""",
                    (relationships[name], role, f"DEMO ONLY: {name} relationship", privileged, criticality),
                )
                profiles[name] = cur.fetchone()[0]

            for profile_id, technology, version, category in (
                (profiles["Microsoft"], "Microsoft Exchange", "2019", "Email"),
                (profiles["Microsoft"], "Azure Active Directory", None, "Identity"),
                (profiles["Amazon Web Services"], "Amazon EC2", None, "Compute"),
            ):
                cur.execute(
                    """INSERT INTO third_party_profile_technologies(profile_id, technology, version, category, source)
                       SELECT %s, %s, %s, %s, 'demo_seed'
                       WHERE NOT EXISTS (SELECT 1 FROM third_party_profile_technologies
                                         WHERE profile_id=%s AND technology=%s)""",
                    (profile_id, technology, version, category, profile_id, technology),
                )
            cur.execute(
                """INSERT INTO third_party_profile_services(profile_id, service_name, service_type, criticality)
                   SELECT %s, 'Authentication', 'Identity', 'CRITICAL'
                   WHERE NOT EXISTS (SELECT 1 FROM third_party_profile_services
                                     WHERE profile_id=%s AND service_name='Authentication')""",
                (profiles["Microsoft"], profiles["Microsoft"]),
            )
            cur.execute(
                """INSERT INTO third_party_external_assets(profile_id, asset_type, value, exposure_status)
                   SELECT %s, 'service', 'outlook.office365.com', 'INTERNET_EXPOSED'
                   WHERE NOT EXISTS (SELECT 1 FROM third_party_external_assets
                                     WHERE profile_id=%s AND value='outlook.office365.com')""",
                (profiles["Microsoft"], profiles["Microsoft"]),
            )

            cur.execute(
                """INSERT INTO assets(customer_id, technology, vendor, version, criticality,
                                        internet_exposed, sensitive_data, category, vendor_id)
                   SELECT %s, 'Microsoft Exchange', 'Microsoft', '2019', 'HIGH', TRUE, TRUE, 'Email', %s
                   WHERE NOT EXISTS (SELECT 1 FROM assets WHERE customer_id=%s AND technology='Microsoft Exchange')""",
                (customer_id, vendor_ids["Microsoft"], customer_id),
            )
            cur.execute(
                """INSERT INTO assets(customer_id, technology, vendor, version, criticality,
                                        internet_exposed, sensitive_data, category)
                   SELECT %s, 'nginx', 'NGINX', '1.24', 'HIGH', TRUE, FALSE, 'Web Server'
                   WHERE NOT EXISTS (SELECT 1 FROM assets WHERE customer_id=%s AND technology='nginx')""",
                (customer_id, customer_id),
            )
            cur.execute(
                """INSERT INTO cve_events(cve_id, title, description, cvss_score, severity, source_url)
                   VALUES ('CVE-2024-21410', 'DEMO: Exchange privilege escalation',
                           'DEMO ONLY representative Exchange risk.', 9.8, 'CRITICAL', 'https://example.invalid/demo')
                   ON CONFLICT(cve_id) DO NOTHING"""
            )
            cur.execute("SELECT id FROM cve_events WHERE cve_id='CVE-2024-21410'")
            cve_id = cur.fetchone()[0]
            cur.execute(
                """INSERT INTO threat_events(source_type, source_id, title, description, cve_id,
                                               cvss_score, severity, confidence, affected_vendors,
                                               affected_products, affected_technologies, raw_metadata)
                   SELECT 'demo_seed', %s, 'DEMO: Critical Microsoft Exchange exposure',
                          'DEMO ONLY representative threat event.', 'CVE-2024-21410', 9.8, 'CRITICAL', 0.95,
                          ARRAY['Microsoft'], ARRAY['Exchange'], ARRAY['Microsoft Exchange'], %s
                   WHERE NOT EXISTS (SELECT 1 FROM threat_events
                                     WHERE source_type='demo_seed' AND cve_id='CVE-2024-21410')
                   RETURNING id""",
                (cve_id, Json({"demo": True})),
            )
            event = cur.fetchone()
            if event:
                threat_event_id = event[0]
            else:
                cur.execute("SELECT id FROM threat_events WHERE source_type='demo_seed' AND cve_id='CVE-2024-21410'")
                threat_event_id = cur.fetchone()[0]
            cur.execute(
                """INSERT INTO third_party_exposures
                   (threat_event_id, customer_id, vendor_id, customer_vendor_id, profile_id,
                    affected_technology, match_type, match_confidence, matched_text,
                    base_severity, risk_score, priority, evidence, recommended_action)
                   SELECT %s, %s, %s, %s, %s, 'Microsoft Exchange', 'demo_seed', 95, 'Microsoft Exchange',
                          'CRITICAL', 95, 'CRITICAL', %s, 'Patch Exchange and monitor authentication activity.'
                   WHERE NOT EXISTS (SELECT 1 FROM third_party_exposures
                                     WHERE threat_event_id=%s AND customer_id=%s AND vendor_id=%s)""",
                (threat_event_id, customer_id, vendor_ids["Microsoft"], relationships["Microsoft"],
                 profiles["Microsoft"], Json(["DEMO ONLY: Exchange mapped to Microsoft profile"]),
                 threat_event_id, customer_id, vendor_ids["Microsoft"]),
            )
            cur.execute(
                "INSERT INTO attack_techniques(technique_id, name, description, tactics, embedding) "
                "VALUES ('T1190', 'Exploit Public-Facing Application', 'DEMO technique', 'Initial Access', %s) "
                "ON CONFLICT(technique_id) DO NOTHING",
                (Json([]),),
            )
            cur.execute(
                """INSERT INTO third_party_incidents(customer_id, incident_type, victim, group_name,
                                                        disclosure_date, source_name, source_url, raw_payload)
                   SELECT %s, 'ransomware', 'Demo Supplier', 'DEMO', CURRENT_TIMESTAMP,
                          'demo_seed', 'https://example.invalid/demo', %s
                   WHERE NOT EXISTS (SELECT 1 FROM third_party_incidents
                                     WHERE source_name='demo_seed' AND victim='Demo Supplier'
                                     AND disclosure_date::date=CURRENT_DATE)""",
                (customer_id, Json({"demo": True, "country": "Demo"})),
            )
            for username, email, full_name, role, default_password in (
                ("admin", "admin@example.com", "Demo Administrator", "Admin", "ChangeMe123!"),
                ("analyst", "analyst@example.com", "Demo Analyst", "Analyst", "ChangeMe123!"),
                ("viewer", "viewer@example.com", "Demo Viewer", "Viewer", "ChangeMe123!"),
            ):
                cur.execute(
                    """INSERT INTO users(username, email, hashed_password, full_name, role, customer_id, is_active)
                       VALUES (%s, %s, %s, %s, %s, %s, TRUE)
                       ON CONFLICT(email) DO UPDATE SET username=EXCLUDED.username, full_name=EXCLUDED.full_name,
                         role=EXCLUDED.role, customer_id=EXCLUDED.customer_id, is_active=TRUE""",
                    (username, email, pwd.hash(default_password), full_name, role, customer_id),
                )

    def _align_sequences(self):
        with self._connect(self.name) as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT table_name, column_name
                FROM information_schema.columns
                WHERE table_schema='public' AND column_default LIKE 'nextval(%%'
            """)
            for table, column in cur.fetchall():
                cur.execute("SELECT pg_get_serial_sequence(%s, %s)", (f"public.{table}", column))
                sequence = cur.fetchone()[0]
                if sequence:
                    cur.execute(
                        "SELECT setval(%s, COALESCE((SELECT MAX(" +
                        sql.Identifier(column).as_string(conn) + ") FROM " +
                        sql.Identifier(table).as_string(conn) + "), 1), true)",
                        (sequence,),
                    )

    def _validate(self):
        with self._connect(self.name) as conn, conn.cursor() as cur:
            cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")
            missing = sorted(EXPECTED_TABLES - {row[0] for row in cur.fetchall()})
            if missing:
                raise SetupError("Missing tables: " + ", ".join(missing))
            cur.execute("""SELECT column_name FROM information_schema.columns
                           WHERE table_schema='public' AND table_name='assessments'""")
            assessment_columns = {row[0] for row in cur.fetchall()}
            required_columns = {"third_party_incident_id", "hunting_guidance", "technology", "evidence"}
            if required_columns - assessment_columns:
                raise SetupError("Missing assessment columns: " + ", ".join(sorted(required_columns - assessment_columns)))
            cur.execute("SELECT COUNT(*) FROM customers WHERE name='Demo Customer'")
            if cur.fetchone()[0] != 1:
                raise SetupError("Demo customer seed was not created")
            cur.execute("SELECT COUNT(*) FROM users WHERE email IN ('admin@example.com', 'analyst@example.com', 'viewer@example.com')")
            if cur.fetchone()[0] != 3:
                raise SetupError("Demo users were not created")
            cur.execute("SELECT COUNT(*) FROM customer_vendors WHERE customer_id=(SELECT id FROM customers WHERE name='Demo Customer')")
            if cur.fetchone()[0] < 2:
                raise SetupError("Demo vendor relationships were not created")
            cur.execute("""SELECT COUNT(*) FROM third_party_profiles p
                           LEFT JOIN customer_vendors cv ON cv.id=p.customer_vendor_id
                           WHERE cv.id IS NULL""")
            if cur.fetchone()[0]:
                raise SetupError("Orphan third-party profiles found")
            cur.execute("""SELECT COUNT(*) FROM third_party_exposures e
                           LEFT JOIN customers c ON c.id=e.customer_id
                           LEFT JOIN vendors v ON v.id=e.vendor_id
                           WHERE c.id IS NULL OR v.id IS NULL""")
            if cur.fetchone()[0]:
                raise SetupError("Orphan third-party exposures found")

    def run(self):
        try:
            self._database_exists()
            self._result("PostgreSQL connection", True)
        except Exception as exc:
            self._result("PostgreSQL connection", False, str(exc))
            return False
        exists = self._database_exists()
        if exists and not self.reset:
            raise SetupError(
                f"Database '{self.name}' already exists. Refusing to modify it; use --reset --yes to recreate it."
            )
        if exists:
            self._drop_database()
            self._result("Database reset", True)
        self._create_database()
        self._result("Database creation", True)
        self._load_schema()
        self._result("Schema initialization", True)
        self._seed_demo_data()
        self._result("Demo seed data", True)
        self._align_sequences()
        self._result("Sequence alignment", True)
        self._validate()
        self._result("Foreign-key and integrity checks", True)
        print("\nAI-TIP database ready.")
        return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Safely create the AI-TIP demo database.")
    parser.add_argument("--reset", action="store_true", help="Drop and recreate the configured database.")
    parser.add_argument("--yes", action="store_true", help="Acknowledge the destructive --reset operation.")
    args = parser.parse_args()
    if args.yes and not args.reset:
        parser.error("--yes is only valid with --reset")
    try:
        return 0 if DatabaseSetup(args.reset, args.yes).run() else 1
    except (SetupError, psycopg2.Error) as exc:
        print(f"Setup failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
