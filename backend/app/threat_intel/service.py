from typing import Any, Dict, List, Optional
import json

from app.database.connection import get_connection
from app.threat_intel.ai_processor import ThreatIntelAIProcessor
from app.threat_intel.correlation.service import ThreatIntelCorrelationService
from app.threat_intel.sources.hackernews import HackerNewsSource, SOURCE_NAME as HACKERNEWS_SOURCE_NAME
from app.threat_intel.sources.cve import CVESource, SOURCE_NAME as CVE_SOURCE_NAME
from app.threat_intel.sources.bleepingcomputer import BleepingComputerSource, SOURCE_NAME as BLEEPINGCOMPUTER_SOURCE_NAME
from app.threat_intel.sources.hibp import HIBPSource, SOURCE_NAME as HIBP_SOURCE_NAME
from app.threat_intel.sources.leakcheck import LeakCheckSource, SOURCE_NAME as LEAKCHECK_SOURCE_NAME
from app.threat_intel.sources.databreach import DataBreachSource, SOURCE_NAME as DATABREACH_SOURCE_NAME


class ThreatIntelService:
    def __init__(self):
        self.sources = [
            HackerNewsSource(),
            BleepingComputerSource(),
            CVESource(),
        ]
        # Data-breach sources feed threat_events (source_type='breach_report')
        self.breach_sources = [
            HIBPSource(),
            LeakCheckSource(),
            DataBreachSource(),
        ]
        self.ai_processor = ThreatIntelAIProcessor()
        self.correlation_service = ThreatIntelCorrelationService()

    def collect_hackernews(self) -> Dict[str, int]:
        return self.collect_from_source(HackerNewsSource(), HACKERNEWS_SOURCE_NAME)

    def collect_cve(self) -> Dict[str, int]:
        return self.collect_from_source(CVESource(), CVE_SOURCE_NAME)

    def collect_bleepingcomputer(self) -> Dict[str, int]:
        return self.collect_from_source(BleepingComputerSource(), BLEEPINGCOMPUTER_SOURCE_NAME)

    def collect_data_breaches(self) -> Dict[str, Any]:
        """Collect breach intelligence from all breach sources.

        Breach records are inserted directly into threat_events with
        source_type='breach_report' so the existing ThirdPartyCorrelationEngine
        and ThirdPartyAlertEngine pick them up automatically.

        Deduplication uses a stable source_id (source + source_id) so the same
        real-world breach reported by multiple providers is preserved as
        multiple intelligence sources rather than creating redundant exposures.
        """
        results: Dict[str, Any] = {}
        total_fetched = 0
        total_inserted = 0
        total_duplicates = 0
        total_errors = 0

        for source in self.breach_sources:
            source_name = source.__class__.__name__
            try:
                result = self.collect_breach_from_source(source, source_name)
                results[source_name] = result
                total_fetched += result.get("fetched", 0)
                total_inserted += result.get("inserted", 0)
                total_duplicates += result.get("duplicates", 0)
            except Exception as e:  # noqa: BLE001 - keep collecting other sources
                total_errors += 1
                results[source_name] = {"error": str(e)}

        return {
            "sources": results,
            "total_fetched": total_fetched,
            "total_inserted": total_inserted,
            "total_duplicates": total_duplicates,
            "total_errors": total_errors,
            "last_breach_updated": self.get_last_breach_updated(),
        }

    def collect_breach_from_source(self, source, source_name: str) -> Dict[str, int]:
        """Fetch + normalize + insert breach records from a single breach source."""
        raw_breaches = source.fetch_articles()
        fetched = len(raw_breaches)
        inserted = 0
        duplicates = 0
        skipped = False

        # Detect if source was skipped due to missing configuration
        if fetched == 0 and source_name in ["HIBPSource", "LeakCheckSource"]:
            skipped = True

        conn = get_connection()
        cur = conn.cursor()

        try:
            for raw_breach in raw_breaches:
                try:
                    breach = source.normalize_article(raw_breach)
                except ValueError:
                    duplicates += 1
                    continue

                if self._breach_event_exists(cur, breach.get("source_id")):
                    duplicates += 1
                    continue

                self._insert_breach_event(cur, breach)
                inserted += 1

            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()

        return {
            "source": source_name,
            "fetched": fetched,
            "inserted": inserted,
            "duplicates": duplicates,
            "skipped": skipped,
        }

    def _breach_event_exists(self, cur, source_id: str) -> bool:
        """Check if a breach event with the given stable source_id already exists."""
        if not source_id:
            return False
        cur.execute(
            """
            SELECT 1 FROM threat_events
            WHERE source_type = 'breach_report'
              AND raw_metadata->>'source_id' = %s
            LIMIT 1
            """,
            (source_id,),
        )
        return cur.fetchone() is not None

    def _insert_breach_event(self, cur, breach: Dict[str, Any]) -> None:
        """Insert a normalized breach record into threat_events."""
        raw_metadata = dict(breach.get("raw_metadata") or {})
        raw_metadata["source_id"] = breach.get("source_id")
        raw_metadata["source"] = breach.get("source")

        cur.execute(
            """
            INSERT INTO threat_events
                (source_type, title, description, severity, confidence,
                 affected_vendors, affected_products, affected_technologies,
                 published_date, source_url, raw_metadata,
                 correlated, correlation_count, created_at)
            VALUES
                ('breach_report', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                 FALSE, 0, CURRENT_TIMESTAMP)
            """,
            (
                breach["title"],
                breach.get("content") or breach.get("description") or "",
                breach.get("severity") or "UNKNOWN",
                breach.get("confidence") or 0.0,
                breach.get("affected_vendors") or [],
                breach.get("affected_products") or [],
                breach.get("affected_technologies") or [],
                breach.get("published_date"),
                breach.get("source_url"),
                json.dumps(raw_metadata),
            ),
        )

    def get_last_breach_updated(self) -> Optional[str]:
        """Return the latest breach event collection timestamp."""
        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT MAX(created_at) FROM threat_events WHERE source_type = 'breach_report'"
            )
            value = cur.fetchone()[0]
        finally:
            cur.close()
            conn.close()

        if value is None:
            return None
        return value.isoformat()

    def list_data_breaches(self, customer_id: int, page: int = 1, limit: int = 20) -> Dict[str, Any]:
        """List data breaches relevant to a specific customer (tenant-scoped).

        Returns breach events that have been correlated to the customer's
        third parties via third_party_exposures.
        """
        offset = max((page - 1) * limit, 0)
        conn = get_connection()
        cur = conn.cursor()

        try:
            # Count only breaches correlated to this customer
            cur.execute(
                """
                SELECT COUNT(DISTINCT te.id)
                FROM threat_events te
                JOIN third_party_alerts a ON a.threat_event_id = te.id
                WHERE a.customer_id = %s AND a.alert_type IN ('BREACH', 'SECURITY_INCIDENT')
                """,
                (customer_id,),
            )
            total = cur.fetchone()[0]

            cur.execute(
                """
                SELECT DISTINCT
                    te.id, te.title, te.description, te.severity, te.confidence,
                    te.affected_vendors, te.affected_products, te.affected_technologies,
                    te.published_date, te.source_url, te.raw_metadata,
                    a.customer_vendor_id, a.vendor AS vendor_name,
                    a.risk_score, 'HIGH' as priority, 'alert_engine' as match_type, a.confidence as match_confidence,
                    (a.status != 'OPEN') as acknowledged, a.created_at AS exposure_created_at,
                    a.id AS exposure_id, te.created_at
                FROM threat_events te
                JOIN third_party_alerts a ON a.threat_event_id = te.id
                WHERE a.customer_id = %s AND a.alert_type IN ('BREACH', 'SECURITY_INCIDENT')
                ORDER BY te.published_date DESC NULLS LAST, te.created_at DESC
                LIMIT %s OFFSET %s
                """,
                (customer_id, limit, offset),
            )
            rows = cur.fetchall()

            breaches = []
            for r in rows:
                breaches.append({
                    "id": r[0],
                    "title": r[1],
                    "description": r[2],
                    "severity": r[3],
                    "confidence": r[4],
                    "affected_vendors": r[5] or [],
                    "affected_products": r[6] or [],
                    "affected_technologies": r[7] or [],
                    "published_date": r[8].isoformat() if r[8] else None,
                    "source_url": r[9],
                    "raw_metadata": r[10] or {},
                    "vendor_id": r[11], # Using customer_vendor_id as it maps to the affected vendor
                    "vendor_name": r[12],
                    "risk_score": r[13],
                    "priority": r[14],
                    "match_type": r[15],
                    "match_confidence": r[16],
                    "acknowledged": r[17],
                    "exposure_created_at": r[18].isoformat() if r[18] else None,
                    "exposure_id": r[19],
                })

            return {
                "page": page,
                "limit": limit,
                "total": total,
                "breaches": breaches,
            }
        finally:
            cur.close()
            conn.close()

    def get_data_breach(self, customer_id: int, breach_id: int) -> Optional[Dict[str, Any]]:
        """Return a single breach with customer-specific context (tenant-scoped)."""
        conn = get_connection()
        cur = conn.cursor()

        try:
            cur.execute(
                """
                SELECT DISTINCT
                    te.id, te.title, te.description, te.severity, te.confidence,
                    te.affected_vendors, te.affected_products, te.affected_technologies,
                    te.published_date, te.source_url, te.raw_metadata,
                    a.customer_vendor_id, a.vendor AS vendor_name,
                    a.risk_score, 'HIGH' as priority, 'alert_engine' as match_type, a.confidence as match_confidence,
                    (a.status != 'OPEN') as acknowledged, a.created_at AS exposure_created_at,
                    a.id AS exposure_id
                FROM threat_events te
                JOIN third_party_alerts a ON a.threat_event_id = te.id
                WHERE a.alert_type IN ('BREACH', 'SECURITY_INCIDENT')
                  AND te.id = %s
                  AND a.customer_id = %s
                """,
                (breach_id, customer_id),
            )
            row = cur.fetchone()
            if not row:
                return None

            return {
                "id": row[0],
                "title": row[1],
                "description": row[2],
                "severity": row[3],
                "confidence": row[4],
                "affected_vendors": row[5] or [],
                "affected_products": row[6] or [],
                "affected_technologies": row[7] or [],
                "published_date": row[8].isoformat() if row[8] else None,
                "source_url": row[9],
                "raw_metadata": row[10] or {},
                "vendor_id": row[11], # Using customer_vendor_id
                "vendor_name": row[12],
                "risk_score": row[13],
                "priority": row[14],
                "match_type": row[15],
                "match_confidence": row[16],
                "acknowledged": row[17],
                "exposure_created_at": row[18].isoformat() if row[18] else None,
                "exposure_id": row[19],
            }
        finally:
            cur.close()
            conn.close()

    def get_data_breach_summary(self, customer_id: int) -> Dict[str, Any]:
        """Return breach summary statistics for a customer (tenant-scoped)."""
        conn = get_connection()
        cur = conn.cursor()

        try:
            cur.execute(
                """
                SELECT
                    COUNT(DISTINCT te.id) AS total_breaches,
                    COUNT(DISTINCT te.id) FILTER (WHERE te.severity = 'CRITICAL') AS critical,
                    COUNT(DISTINCT te.id) FILTER (WHERE te.severity = 'HIGH') AS high,
                    COUNT(DISTINCT te.id) FILTER (WHERE te.severity = 'MEDIUM') AS medium,
                    COUNT(DISTINCT te.id) FILTER (WHERE te.severity = 'LOW') AS low,
                    COUNT(DISTINCT a.customer_vendor_id) AS affected_vendors,
                    COUNT(DISTINCT a.id) FILTER (WHERE a.status = 'OPEN') AS unacknowledged_exposures,
                    MAX(te.published_date) AS latest_breach_date
                FROM threat_events te
                JOIN third_party_alerts a ON a.threat_event_id = te.id
                WHERE a.alert_type IN ('BREACH', 'SECURITY_INCIDENT')
                  AND a.customer_id = %s
                """,
                (customer_id,),
            )
            row = cur.fetchone()

            return {
                "total_breaches": row[0] or 0,
                "critical": row[1] or 0,
                "high": row[2] or 0,
                "medium": row[3] or 0,
                "low": row[4] or 0,
                "affected_vendors": row[5] or 0,
                "unacknowledged_exposures": row[6] or 0,
                "latest_breach_date": row[7].isoformat() if row[7] else None,
            }
        finally:
            cur.close()
            conn.close()

    def collect_all_sources(self) -> Dict[str, Any]:
        results = {}
        total_fetched = 0
        total_inserted = 0
        total_duplicates = 0

        for source in self.sources:
            try:
                source_name = source.__class__.__name__
                result = self.collect_from_source(source, source_name)
                results[source_name] = result
                total_fetched += result.get("fetched", 0)
                total_inserted += result.get("inserted", 0)
                total_duplicates += result.get("duplicates", 0)
            except Exception as e:
                results[source_name] = {"error": str(e)}

        return {
            "sources": results,
            "total_fetched": total_fetched,
            "total_inserted": total_inserted,
            "total_duplicates": total_duplicates,
        }

    def get_last_updated(self) -> Optional[str]:
        """Return the latest successful collection timestamp from the database.

        Derived from the max(threat_articles.created_at) so the value survives
        server restarts (i.e. it is not an in-memory variable).
        """
        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute("SELECT MAX(created_at) FROM threat_articles")
            value = cur.fetchone()[0]
        finally:
            cur.close()
            conn.close()

        if value is None:
            return None
        return value.isoformat()

    def refresh_all_sources(self) -> Dict[str, Any]:
        """Collect from all sources with per-source isolation.

        Returns a summary dict with per-source results, total new articles,
        duplicates and errors. One failing source does not stop the others.
        """
        results: Dict[str, Any] = {}
        total_fetched = 0
        total_inserted = 0
        total_duplicates = 0
        total_errors = 0

        for source in self.sources:
            source_name = source.__class__.__name__
            try:
                result = self.collect_from_source(source, source_name)
                results[source_name] = result
                total_fetched += result.get("fetched", 0)
                total_inserted += result.get("inserted", 0)
                total_duplicates += result.get("duplicates", 0)
            except Exception as e:  # noqa: BLE001 - keep collecting other sources
                total_errors += 1
                results[source_name] = {"error": str(e)}

        return {
            "sources": results,
            "total_fetched": total_fetched,
            "total_inserted": total_inserted,
            "total_duplicates": total_duplicates,
            "total_errors": total_errors,
            "last_updated": self.get_last_updated(),
        }

    def collect_from_source(self, source, source_name: str) -> Dict[str, int]:
        raw_articles = source.fetch_articles()
        fetched = len(raw_articles)
        inserted = 0
        duplicates = 0

        conn = get_connection()
        cur = conn.cursor()

        try:
            for raw_article in raw_articles:
                try:
                    article = source.normalize_article(raw_article)
                except ValueError:
                    duplicates += 1
                    continue

                if self._article_exists(cur, article["url"]):
                    duplicates += 1
                    continue

                self._insert_article(cur, article)
                inserted += 1

            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()

        return {
            "source": source_name,
            "fetched": fetched,
            "inserted": inserted,
            "duplicates": duplicates,
        }

    def _article_exists(self, cur, url: str) -> bool:
        cur.execute(
            "SELECT 1 FROM threat_articles WHERE url = %s LIMIT 1",
            (url,),
        )
        return cur.fetchone() is not None

    def _insert_article(self, cur, article: Dict[str, Any]) -> None:
        insert_cols = [
            "title",
            "url",
            "source",
            "published_date",
            "content",
            "threat_type",
            "metadata",
        ]
        placeholders = ["%s"] * len(insert_cols)
        values = [
            article["title"],
            article["url"],
            article["source"],
            article["published_date"],
            article["content"],
            article["threat_type"],
            json.dumps(article["metadata"] or {}),
        ]

        # Persist structured derived fields (CVEs set these directly so the
        # threat_events backfill carries them into affected_* for correlation;
        # other sources leave them empty until AI enrichment populates them).
        available_columns = self._get_article_columns(cur)
        if "vendors" in available_columns:
            insert_cols.append("vendors")
            placeholders.append("%s")
            values.append(json.dumps(article.get("affected_vendors") or []))
        if "products" in available_columns:
            insert_cols.append("products")
            placeholders.append("%s")
            values.append(json.dumps(article.get("affected_products") or []))
        if "affected_technologies" in available_columns:
            insert_cols.append("affected_technologies")
            placeholders.append("%s")
            values.append(json.dumps(article.get("affected_technologies") or []))
        if "cves" in available_columns:
            insert_cols.append("cves")
            placeholders.append("%s")
            values.append(json.dumps([article.get("metadata", {}).get("cve_id")] if article.get("metadata", {}).get("cve_id") else []))

        insert_cols.append("created_at")
        placeholders.append("CURRENT_TIMESTAMP")

        query = (
            f"INSERT INTO threat_articles ({', '.join(insert_cols)}) "
            f"VALUES ({', '.join(placeholders)})"
        )
        cur.execute(query, tuple(values))

    def process_unprocessed_articles(self, limit: int = 20) -> Dict[str, int]:
        import threading
        import time
        
        conn = get_connection()
        cur = conn.cursor()

        try:
            cur.execute(
                "SELECT id, title, content FROM threat_articles WHERE processed = false ORDER BY published_date DESC NULLS LAST, created_at DESC LIMIT %s",
                (limit,),
            )
            rows = cur.fetchall()

            processed = 0
            failed = 0

            for row in rows:
                article_id, title, content = row
                try:
                    # Reconnect if the connection was closed (e.g. by a timeout thread)
                    if conn.closed:
                        conn = get_connection()
                        cur = conn.cursor()

                    ai_result = self._run_with_timeout(
                        self.ai_processor.analyze_article, 
                        title, 
                        content,
                        timeout=90
                    )
                    # Reconnect again if the timeout fallback path closed the connection
                    if conn.closed:
                        conn = get_connection()
                        cur = conn.cursor()

                    self._update_article(cur, article_id, ai_result)
                    processed += 1
                    conn.commit()
                except Exception as e:
                    failed += 1
                    logger.warning(f"[THREAT INTEL SERVICE] Failed to process article {article_id}: {e}")
                    try:
                        if not conn.closed:
                            conn.rollback()
                    except Exception:
                        pass
                    # Get a fresh connection for the next iteration
                    try:
                        if conn.closed:
                            conn = get_connection()
                            cur = conn.cursor()
                    except Exception:
                        pass
                    continue

        except Exception:
            try:
                if not conn.closed:
                    conn.rollback()
            except Exception:
                pass
            raise
        finally:
            try:
                cur.close()
                if not conn.closed:
                    conn.close()
            except Exception:
                pass

        return {
            "processed": processed,
            "failed": failed,
        }
    
    def _run_with_timeout(self, func, *args, timeout=90):
        """Run a function with a timeout to prevent indefinite blocking.
        
        This is a safety net for article-level processing. If the internal
        AI requests timeout or hang, this ensures the article processing
        completes and the scheduler can continue to the next article.
        """
        import threading
        import time
        
        result = [None]
        exception = [None]
        
        def worker():
            try:
                result[0] = func(*args)
            except Exception as e:
                exception[0] = e
        
        thread = threading.Thread(target=worker)
        thread.daemon = True
        thread.start()
        thread.join(timeout=timeout)
        
        if thread.is_alive():
            # Thread is still running - timeout exceeded
            logger.warning(f"[THREAT INTEL SERVICE] Article processing timeout after {timeout}s - using deterministic fallback")
            # Return a fallback result instead of waiting forever
            title = args[0] if args else ""
            content = args[1] if len(args) > 1 else ""
            return self.ai_processor._generate_fallback_enrichment(title, content)
        
        if exception[0]:
            raise exception[0]
        
        return result[0]

    def _get_article_columns(self, cur):
        cur.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'threat_articles'
            """
        )
        return {row[0] for row in cur.fetchall()}

    def list_articles(self, page: int = 1, limit: int = 20) -> Dict[str, Any]:
        offset = max((page - 1) * limit, 0)
        conn = get_connection()
        cur = conn.cursor()

        try:
            cur.execute(
                "SELECT COUNT(*) FROM threat_articles"
            )
            total = cur.fetchone()[0]

            available_columns = self._get_article_columns(cur)
            select_fields = [
                "id",
                "title",
                "url",
                "source",
                "published_date",
                "content",
                "threat_type",
                "metadata",
            ]
            optional_columns = [
                "summary",
                "severity",
                "vendors",
                "products",
                "cves",
                "malware",
                "threat_actors",
                "mitre_techniques",
                "attack_scenario",
                "technical_impact",
                "exploitation_context",
                "affected_technologies",
                "customer_relevance",
                "recommendation",
                "confidence",
                "processed",
                "created_at",
            ]

            for column in optional_columns:
                if column in available_columns:
                    select_fields.append(column)
                else:
                    select_fields.append(f"NULL AS {column}")

            query = f"SELECT {', '.join(select_fields)} FROM threat_articles ORDER BY published_date DESC NULLS LAST, created_at DESC LIMIT %s OFFSET %s"
            cur.execute(query, (limit, offset))
            rows = cur.fetchall()

            articles = []
            for row in rows:
                article = dict(zip([field.split(" AS ")[-1] for field in select_fields], row))
                articles.append({
                    "id": article["id"],
                    "title": article["title"],
                    "url": article["url"],
                    "source": article["source"],
                    "published_date": article["published_date"],
                    "content": article["content"],
                    "threat_type": article["threat_type"],
                    "metadata": article.get("metadata") or {},
                    "summary": article.get("summary"),
                    "severity": article.get("severity"),
                    "vendors": article.get("vendors") or [],
                    "products": article.get("products") or [],
                    "cves": article.get("cves") or [],
                    "malware": article.get("malware") or [],
                    "threat_actors": article.get("threat_actors") or [],
                    "mitre_techniques": article.get("mitre_techniques") or [],
                    "attack_scenario": article.get("attack_scenario") or "",
                    "technical_impact": article.get("technical_impact") or "",
                    "exploitation_context": article.get("exploitation_context") or "",
                    "affected_technologies": article.get("affected_technologies") or [],
                    "customer_relevance": article.get("customer_relevance") or "",
                    "recommendation": article.get("recommendation"),
                    "confidence": article.get("confidence"),
                    "processed": article.get("processed"),
                    "created_at": article.get("created_at"),
                })

            return {
                "page": page,
                "limit": limit,
                "total": total,
                "articles": articles,
            }
        finally:
            cur.close()
            conn.close()

    def _update_article(self, cur, article_id: int, ai_result: Dict[str, Any]) -> None:
        columns = self._get_article_columns(cur)
        set_clauses = []
        values = []

        def add_column(column_name, value):
            if column_name in columns:
                set_clauses.append(f"{column_name} = %s")
                values.append(value)

        add_column("summary", ai_result.get("summary"))
        add_column("severity", ai_result.get("severity"))
        add_column("threat_type", ai_result.get("threat_type"))
        add_column("vendors", json.dumps(ai_result.get("vendors") or []))
        add_column("products", json.dumps(ai_result.get("products") or []))
        add_column("cves", json.dumps(ai_result.get("cves") or []))
        add_column("malware", json.dumps(ai_result.get("malware") or []))
        add_column("threat_actors", json.dumps(ai_result.get("threat_actors") or []))
        add_column("mitre_techniques", json.dumps(ai_result.get("mitre_techniques") or []))
        add_column("attack_scenario", ai_result.get("attack_scenario"))
        add_column("technical_impact", ai_result.get("technical_impact"))
        add_column("exploitation_context", ai_result.get("exploitation_context"))
        add_column("affected_technologies", json.dumps(ai_result.get("affected_technologies") or []))
        add_column("customer_relevance", ai_result.get("customer_relevance"))
        add_column("recommendation", ai_result.get("recommendation"))
        add_column("confidence", ai_result.get("confidence"))
        if "processed" in columns:
            set_clauses.append("processed = true")

        if not set_clauses:
            return

        query = f"UPDATE threat_articles SET {', '.join(set_clauses)} WHERE id = %s"
        values.append(article_id)
        cur.execute(query, tuple(values))

    def correlate_customer_articles(self, customer_id: int, limit: int = 20, force: bool = False) -> Dict[str, int]:
        return self.correlation_service.correlate_customer_articles(
            customer_id=customer_id,
            limit=limit,
            force=force,
        )

    def list_correlations(self, customer_id: int, page: int = 1, limit: int = 20):
        return self.correlation_service.list_correlations(
            customer_id=customer_id,
            page=page,
            limit=limit,
        )
