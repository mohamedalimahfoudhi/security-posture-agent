import json
import logging
import os
import requests
from datetime import datetime, timezone
from psycopg2.extras import Json

from app.ai.assessment_agent import generate_assessment
from app.database.connection import get_connection

logger = logging.getLogger(__name__)

RANSOMWARE_LIVE_URL = "https://api.ransomware.live/v2"


def _parse_datetime(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def _resolve_disclosure_date(item):
    # Real field from ransomware.live recentcyberattacks: 'date' (YYYY-MM-DD)
    # recentvictims also uses 'discovered' and 'attackdate' as fallbacks
    parsed = _parse_datetime(item.get("date") or item.get("discovered") or item.get("attackdate"))
    if parsed is not None:
        return parsed
    return datetime.now(timezone.utc)


def fetch_recent_victims(days=7):
    """Fetch recent ransomware victims from ransomware.live."""
    url = f"{RANSOMWARE_LIVE_URL}/recentvictims"
    params = {"days": days}

    try:
        response = requests.get(url, params=params, timeout=20)
        if response.status_code == 429:
            logger.warning("[INGESTION] Ransomware.live rate limited for recent victims")
            return []
        response.raise_for_status()
        payload = response.json()
        items = payload if isinstance(payload, list) else payload.get("items", [])
        return items
    except requests.exceptions.Timeout:
        logger.warning("[INGESTION] Ransomware.live recent victims request timed out")
        return []
    except requests.exceptions.RequestException as exc:
        logger.warning(f"[INGESTION] Ransomware.live recent victims request failed: {exc}")
        return []
    except Exception as exc:
        logger.warning(f"[INGESTION] Unexpected error while fetching ransomware victims: {exc}")
        return []


def fetch_recent_cyberattacks(days=7):
    """Fetch recent cyber attacks/breaches/incidents from ransomware.live."""
    url = f"{RANSOMWARE_LIVE_URL}/recentcyberattacks"
    params = {"days": days}

    try:
        response = requests.get(url, params=params, timeout=20)
        if response.status_code == 429:
            logger.warning("[INGESTION] Ransomware.live rate limited for recent cyberattacks")
            return []
        response.raise_for_status()
        payload = response.json()
        items = payload if isinstance(payload, list) else payload.get("items", [])
        return items
    except requests.exceptions.Timeout:
        logger.warning("[INGESTION] Ransomware.live recent cyberattacks request timed out")
        return []
    except requests.exceptions.RequestException as exc:
        logger.warning(f"[INGESTION] Ransomware.live recent cyberattacks request failed: {exc}")
        return []
    except Exception as exc:
        logger.warning(f"[INGESTION] Unexpected error while fetching cyberattacks: {exc}")
        return []


def normalize_incident_type(item, default="breach"):
    """Infer an incident_type from a ransomware.live item.

    Only 'ransomware' and 'breach' are produced — 'major_incident' is dropped
    because the ransomware.live API has no field that maps to that category.

    Real field names (confirmed against live API 2026-07-25):
      victim       - organization name
      date         - incident date (YYYY-MM-DD)
      claim_gang   - ransomware group name string, or False if no group claimed
      claim_url    - URL to claim post, or False
      summary      - narrative text
      title        - article title
      url          - news source URL
      link         - ransomware.live permalink
      country      - ISO country code
      domain       - victim domain
      description  - always empty string in practice
    """
    if not isinstance(item, dict):
        return default

    # claim_gang is a group name (string) when a ransomware group has claimed the attack,
    # or False/None when no group is identified (indicating a generic breach/data leak).
    claim_gang = item.get("claim_gang")
    if claim_gang and claim_gang is not False:
        return "ransomware"

    return default  # 'breach'


def build_incident_records(customer_id, days=7):
    """Build incident records from both ransomware.live endpoints."""
    incidents = []

    for item in fetch_recent_victims(days=days):
        if not isinstance(item, dict):
            continue
        victim = item.get("victim") or item.get("name") or item.get("organization")
        if not victim:
            continue
        incident_type = "ransomware"
        disclosure_date = _resolve_disclosure_date(item)
        incidents.append({
            "customer_id": customer_id,
            "incident_type": incident_type,
            "victim": victim,
            "group_name": item.get("claim_gang") or item.get("group"),
            "disclosure_date": disclosure_date,
            "source_name": "ransomware.live",
            "source_url": item.get("url"),
            "raw_payload": item,
        })

    for item in fetch_recent_cyberattacks(days=days):
        if not isinstance(item, dict):
            continue
        victim = item.get("victim") or item.get("name") or item.get("organization")
        if not victim:
            continue
        incident_type = normalize_incident_type(item, default="breach")
        disclosure_date = _resolve_disclosure_date(item)
        incidents.append({
            "customer_id": customer_id,
            "incident_type": incident_type,
            "victim": victim,
            "group_name": item.get("claim_gang") or None,
            "disclosure_date": disclosure_date,
            "source_name": "ransomware.live",
            "source_url": item.get("url"),
            "raw_payload": item,
        })

    return incidents


def ingest_third_party_incidents(customer_id=1, days=7):
    """Persist ransomware.live incidents and create linked assessments."""
    records = build_incident_records(customer_id=customer_id, days=days)

    conn = get_connection()
    cur = conn.cursor()
    processed = []

    try:
        for record in records:
            cur.execute(
                """
                INSERT INTO third_party_incidents (
                    customer_id,
                    incident_type,
                    victim,
                    group_name,
                    disclosure_date,
                    source_name,
                    source_url,
                    raw_payload
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (source_name, victim, disclosure_date) DO NOTHING
                RETURNING id
                """,
                (
                    record["customer_id"],
                    record["incident_type"],
                    record["victim"],
                    record.get("group_name"),
                    record["disclosure_date"],
                    record["source_name"],
                    record.get("source_url"),
                    Json(record["raw_payload"]),
                )
            )

            row = cur.fetchone()
            incident_id = row[0] if row else None

            if incident_id is None:
                cur.execute(
                    """
                    SELECT id
                    FROM third_party_incidents
                    WHERE source_name = %s
                      AND victim = %s
                      AND disclosure_date = %s
                    """,
                    (
                        record["source_name"],
                        record["victim"],
                        record["disclosure_date"],
                    )
                )
                existing = cur.fetchone()
                if existing:
                    incident_id = existing[0]

            if incident_id is not None:
                conn.commit()
                try:
                    generate_assessment(
                        None,
                        f"{record['incident_type']} affecting {record['victim']}",
                        "HIGH",
                        customer_id=customer_id,
                        incident_id=incident_id,
                        incident_type=record["incident_type"],
                        incident_victim=record["victim"],
                    )
                except Exception as exc:
                    logger.warning(f"[INGESTION] Failed to create assessment for incident {incident_id}: {exc}")

                processed.append({"id": incident_id, **record})

        conn.commit()
    except Exception as exc:
        conn.rollback()
        raise exc
    finally:
        cur.close()
        conn.close()

    return processed


if __name__ == "__main__":
    records = build_incident_records(customer_id=1, days=7)
    print(f"Fetched {len(records)} incident records")
    for record in records[:5]:
        print(record)
