"""
Migration 018-020: Vendor identity foundation.

Applies in order:
  018  add vendors table
  019  add vendor_aliases table
  020  add nullable vendor_id columns to customer_vendors and assets

Then seeds the vendors catalog from:
  - technology_patterns.py canonical vendor entries (authoritative)
  - distinct vendor strings already present in customer_vendors / assets /
    assessments / alerts (backfill coverage)

Finally backfills vendor_id on customer_vendors and assets by resolving each
existing vendor string against vendor_aliases.

Purely additive. Existing VARCHAR vendor columns are NOT modified. All reads
by existing APIs/frontend continue to work unchanged.

Run:  python apply_018_020_vendor_identity.py
"""
import os
import sys
import re
import json

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from app.database.connection import get_connection

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
MIGRATIONS_DIR = os.path.join(BACKEND_DIR, "migrations")

# Load canonical vendors + aliases from the technology pattern DB.
sys.path.insert(0, BACKEND_DIR)
from app.ai.technology_patterns import TECHNOLOGY_PATTERNS  # noqa: E402


# ---------------------------------------------------------------------------
# Vendor name normalization (reuses suffix-stripping ideas already in the codebase)
# ---------------------------------------------------------------------------
COMMON_SUFFIXES = [
    " corporation", " inc", " inc.", " incorporated", " limited", " ltd",
    " ltd.", " llc", " llc.", " systems", " company", " co.", " group",
    " private limited", " pvt ltd", " plc", " s.a.", " gmbh", " ag",
]


def normalize_vendor_name(value):
    """Lowercase, strip punctuation, strip common legal suffixes."""
    if not value:
        return ""
    text = str(value).strip().lower()
    text = re.sub(r"[^a-z0-9 .-]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    for suffix in COMMON_SUFFIXES:
        if text.endswith(suffix):
            text = text[: -len(suffix)].strip()
            break
    return text


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


def seed_vendors_from_patterns(conn, cur):
    """Insert a canonical vendor per unique vendor string in the pattern DB.

    Uses the pattern entry's `vendor` as the canonical name, and the
    entry's `name` + `aliases` as alias strings pointing to that vendor.
    """
    inserted = 0
    for entry in TECHNOLOGY_PATTERNS:
        vendor_name = (entry.get("vendor") or "").strip()
        if not vendor_name:
            continue
        category = entry.get("category") or "other"

        # Insert the canonical vendor (ON CONFLICT name -> get existing id)
        cur.execute(
            """
            INSERT INTO vendors (name, category, base_risk_score)
            VALUES (%s, %s, 0)
            ON CONFLICT (name) DO UPDATE SET category = COALESCE(vendors.category, EXCLUDED.category)
            RETURNING id
            """,
            (vendor_name, category),
        )
        row = cur.fetchone()
        vendor_id = row[0]

        # Seed aliases: entry name + explicit aliases + normalized variants
        alias_pool = [entry.get("name")]
        alias_pool += [a for a in entry.get("aliases", []) if a]
        alias_pool.append(vendor_name)
        alias_pool.append(normalize_vendor_name(vendor_name))

        for alias in alias_pool:
            alias = (alias or "").strip()
            if not alias:
                continue
            cur.execute(
                """
                INSERT INTO vendor_aliases (vendor_id, alias)
                VALUES (%s, %s)
                ON CONFLICT (alias) DO NOTHING
                """,
                (vendor_id, alias),
            )
        inserted += 1
    conn.commit()
    return inserted


def seed_extra_vendor_strings(conn, cur):
    """Ensure every distinct vendor string already in the DB maps to a vendor.

    For strings not covered by the pattern DB, create a canonical vendor from
    the raw string itself (so nothing is left unmapped), then add the raw
    string as an alias.
    """
    sources = [
        ("customer_vendors", "vendor"),
        ("assets", "vendor"),
        ("assessments", "vendor"),
        ("alerts", "asset_vendor"),
    ]
    vendor_id_by_normalized = {}
    cur.execute("SELECT id, name FROM vendors")
    for vid, name in cur.fetchall():
        vendor_id_by_normalized[normalize_vendor_name(name)] = vid

    created = 0
    for table, column in sources:
        try:
            cur.execute(
                f"SELECT DISTINCT {column} FROM {table} WHERE {column} IS NOT NULL AND {column} <> ''"
            )
        except Exception as e:
            print(f"  [SKIP] Cannot read {table}.{column}: {e}")
            continue
        for (raw,) in cur.fetchall():
            raw = (raw or "").strip()
            if not raw:
                continue
            norm = normalize_vendor_name(raw)
            if not norm:
                continue

            # Skip "Unknown"/generic placeholders
            if norm in ("unknown", "unknown vendor", "n/a", "none", "null"):
                continue

            if norm in vendor_id_by_normalized:
                vid = vendor_id_by_normalized[norm]
            else:
                cur.execute(
                    """
                    INSERT INTO vendors (name, category, base_risk_score)
                    VALUES (%s, NULL, 0)
                    ON CONFLICT (name) DO NOTHING
                    RETURNING id
                    """,
                    (raw,),
                )
                row = cur.fetchone()
                if row:
                    vid = row[0]
                    vendor_id_by_normalized[norm] = vid
                    created += 1
                else:
                    # name may already exist under a different form; find it
                    cur.execute("SELECT id FROM vendors WHERE name = %s", (raw,))
                    existing = cur.fetchone()
                    if existing:
                        vid = existing[0]
                        vendor_id_by_normalized[norm] = vid
                    else:
                        continue

            # Ensure the raw string + normalized form are aliases
            for alias in (raw, norm):
                cur.execute(
                    """
                    INSERT INTO vendor_aliases (vendor_id, alias)
                    VALUES (%s, %s)
                    ON CONFLICT (alias) DO NOTHING
                    """,
                    (vid, alias),
                )
    conn.commit()
    return created


def build_alias_to_vendor_map(cur):
    """Map normalized + raw alias -> vendor_id for backfill resolution."""
    cur.execute("SELECT alias, vendor_id FROM vendor_aliases")
    alias_map = {}
    for alias, vid in cur.fetchall():
        alias_map[alias.strip().lower()] = vid
        alias_map[normalize_vendor_name(alias)] = vid
    return alias_map


def backfill_vendor_id(conn, cur, table, column, alias_map):
    """Set table.vendor_id by resolving table.column via alias_map."""
    cur.execute(
        f"SELECT id, {column} FROM {table} WHERE {column} IS NOT NULL AND {column} <> '' AND vendor_id IS NULL"
    )
    rows = cur.fetchall()
    updated = 0
    unresolved = 0
    for row_id, raw in rows:
        raw = (raw or "").strip()
        vid = None
        if raw:
            vid = alias_map.get(raw.lower())
            if vid is None:
                vid = alias_map.get(normalize_vendor_name(raw))
        if vid is not None:
            cur.execute(f"UPDATE {table} SET vendor_id = %s WHERE id = %s", (vid, row_id))
            updated += 1
        else:
            unresolved += 1
    conn.commit()
    return updated, unresolved


def main():
    conn = get_connection()
    cur = conn.cursor()
    try:
        print("=== Vendor Identity Migration 018-020 ===")

        print("\n[1/4] Creating tables + vendor_id columns")
        apply_sql(conn, cur, "018_add_vendors_table.sql")
        apply_sql(conn, cur, "019_add_vendor_aliases_table.sql")
        apply_sql(conn, cur, "020_add_vendor_id_columns.sql")

        print("\n[2/4] Seeding vendors + aliases from technology_patterns.py")
        n_pattern_vendors = seed_vendors_from_patterns(conn, cur)
        print(f"  Seeded {n_pattern_vendors} canonical vendors from pattern DB")

        print("\n[3/4] Seeding extra vendor strings from existing DB rows")
        n_extra = seed_extra_vendor_strings(conn, cur)
        print(f"  Created {n_extra} additional vendors from existing data")

        print("\n[4/4] Backfilling vendor_id")
        alias_map = build_alias_to_vendor_map(cur)
        print(f"  alias_map size: {len(alias_map)}")

        for table, column in [("customer_vendors", "vendor"), ("assets", "vendor")]:
            updated, unresolved = backfill_vendor_id(conn, cur, table, column, alias_map)
            print(f"  {table}: updated {updated}, unresolved {unresolved}")

        # Summary
        cur.execute("SELECT COUNT(*) FROM vendors")
        total_vendors = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM vendor_aliases")
        total_aliases = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM customer_vendors WHERE vendor_id IS NOT NULL")
        cv_linked = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM assets WHERE vendor_id IS NOT NULL")
        assets_linked = cur.fetchone()[0]

        print("\n=== SUMMARY ===")
        print(f"  vendors:            {total_vendors}")
        print(f"  vendor_aliases:     {total_aliases}")
        print(f"  customer_vendors linked: {cv_linked}")
        print(f"  assets linked:          {assets_linked}")

        # Print sample resolution for the 3 known customer_vendors
        print("\n=== SAMPLE customer_vendors RESOLUTION ===")
        cur.execute("""
            SELECT cv.id, cv.vendor, v.id AS vendor_id, v.name AS canonical
            FROM customer_vendors cv
            LEFT JOIN vendors v ON cv.vendor_id = v.id
            ORDER BY cv.id
        """)
        for r in cur.fetchall():
            print(f"  cv#{r[0]} '{r[1]}' -> vendor#{r[2]} '{r[3]}'")

        print("\nVendor identity migration complete.")
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    main()
