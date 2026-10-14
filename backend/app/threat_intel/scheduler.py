"""Scheduled automatic refresh for the threat intelligence feed.

Uses APScheduler's AsyncIOScheduler (compatible with the FastAPI async
event loop). A threading.Lock prevents overlapping collection runs: if a
collection is already in progress, a new scheduled/manual run is skipped
and reported as such.
"""
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_REFRESH_INTERVAL_MINUTES = 30

# APScheduler is an optional runtime capability. If it is not installed, the
# scheduler simply does not start (the app still boots and manual/API-driven
# collection via run_collection remains fully functional).
try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    APSCHEDULER_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when apscheduler is absent
    APSCHEDULER_AVAILABLE = False
    logger.warning(
        "APScheduler is not installed. The automatic threat-intel refresh "
        "scheduler will be disabled. Install it with: pip install apscheduler"
    )
    AsyncIOScheduler = None  # type: ignore[assignment]

# Module-level lock so a manual refresh and a scheduled run never overlap.
_collection_lock = threading.Lock()
# True while a collection is in progress (used for the "already running"
# informational message returned to clients).
_collection_in_progress = False

_scheduler: Optional[Any] = None


def create_scheduler() -> Optional[Any]:
    """Create and configure the AsyncIOScheduler (but do not start it).

    Returns None if APScheduler is not installed, so callers can safely
    skip starting the periodic job without crashing the application.
    """
    global _scheduler
    if not APSCHEDULER_AVAILABLE:
        logger.warning(
            "[THREAT INTEL SCHEDULER] APScheduler not available; automatic "
            "refresh scheduler will not be created."
        )
        _scheduler = None
        return None
    if _scheduler is None:
        _scheduler = AsyncIOScheduler(timezone="UTC")
    return _scheduler


def start_scheduler(collect_all_fn):
    """Start the scheduler and register the periodic collection job.

    The periodic job first fires after _REFRESH_INTERVAL_MINUTES, matching
    the requirement that startup remains fast (no immediate collection).

    Returns the scheduler instance, or None if APScheduler is unavailable.
    """
    scheduler = create_scheduler()

    # If APScheduler is not installed, do not start anything.
    if scheduler is None:
        return None

    # Guard against double-starting when reloading.
    if getattr(scheduler, "_threat_intel_started", False):
        return scheduler

    scheduler.add_job(
        collect_all_fn,
        trigger="interval",
        minutes=_REFRESH_INTERVAL_MINUTES,
        id="threat_intel_auto_collect",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        misfire_grace_time=300,
    )

    scheduler._threat_intel_started = True
    scheduler.start()
    logger.info(
        "[THREAT INTEL SCHEDULER] Started. Auto-collect interval=%d minutes.",
        _REFRESH_INTERVAL_MINUTES,
    )
    return scheduler


def shutdown_scheduler() -> None:
    """Shut down the scheduler (used on FastAPI shutdown)."""
    global _scheduler
    if _scheduler is not None:
        try:
            _scheduler.shutdown(wait=False)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("[THREAT INTEL SCHEDULER] Shutdown error: %s", exc)
        _scheduler = None


def is_collection_running() -> bool:
    """Return True if a collection is currently in progress."""
    return _collection_in_progress


def run_collection(service) -> Dict[str, Any]:
    """Run a full multi-source collection with overlap protection.

    Logs start/end/source/new/duplicates/errors for every run. If one source
    fails, the remaining sources are still collected. Returns a summary dict
    suitable for the API response.

    Collects both the regular threat-intel sources (HackerNews, BleepingComputer,
    CVE) and the data-breach intelligence sources (HIBP, LeakCheck, DataBreach.com).
    Breach sources feed threat_events and are picked up by the existing
    third-party correlation + alert engine.
    """
    global _collection_in_progress

    if not _collection_lock.acquire(blocking=False):
        logger.info("[THREAT INTEL COLLECT] Collection already in progress; skipping this run.")
        return {
            "status": "already_running",
            "message": "A threat feed collection is already in progress. Please wait for it to finish.",
            "started_at": None,
            "last_updated": service.get_last_updated(),
        }

    _collection_in_progress = True
    started_at = datetime.now(timezone.utc)
    logger.info("[THREAT INTEL COLLECT] ===== Collection started at %s =====", started_at.isoformat())

    source_results: Dict[str, Any] = {}
    total_fetched = 0
    total_inserted = 0
    total_duplicates = 0
    total_errors = 0

    try:
        # Collect regular threat-intel sources (HackerNews, BleepingComputer, CVE).
        for source in service.sources:
            source_name = source.__class__.__name__
            source_start = datetime.now(timezone.utc)
            try:
                result = service.collect_from_source(source, source_name)
                source_results[source_name] = result
                total_fetched += result.get("fetched", 0)
                total_inserted += result.get("inserted", 0)
                total_duplicates += result.get("duplicates", 0)
                source_end = datetime.now(timezone.utc)
                logger.info(
                    "[THREAT INTEL COLLECT] Source=%s start=%s end=%s new=%s duplicates=%s",
                    source_name,
                    source_start.isoformat(),
                    source_end.isoformat(),
                    result.get("inserted", 0),
                    result.get("duplicates", 0),
                )
            except Exception as exc:  # noqa: BLE001 - one source must not stop the rest
                total_errors += 1
                source_end = datetime.now(timezone.utc)
                source_results[source_name] = {"error": str(exc)}
                logger.error(
                    "[THREAT INTEL COLLECT] Source=%s FAILED start=%s end=%s error=%r",
                    source_name,
                    source_start.isoformat(),
                    source_end.isoformat(),
                    exc,
                )

        # Collect data-breach intelligence sources (HIBP, LeakCheck, DataBreach.com).
        # These feed threat_events (source_type='breach_report') and are picked up
        # by the existing third-party correlation + alert engine. Each breach source
        # is isolated so a single failure never stops the others or the regular feed.
        breach_sources = getattr(service, "breach_sources", None) or []
        for breach_source in breach_sources:
            source_name = breach_source.__class__.__name__
            source_start = datetime.now(timezone.utc)
            try:
                result = service.collect_breach_from_source(breach_source, source_name)
                source_results[source_name] = result
                total_fetched += result.get("fetched", 0)
                total_inserted += result.get("inserted", 0)
                total_duplicates += result.get("duplicates", 0)
                source_end = datetime.now(timezone.utc)
                
                # Check if source was skipped (empty result due to missing config)
                if result.get("fetched", 0) == 0 and result.get("skipped", False):
                    logger.info(
                        "[THREAT INTEL COLLECT] BreachSource=%s SKIPPED reason=API key not configured",
                        source_name,
                    )
                else:
                    logger.info(
                        "[THREAT INTEL COLLECT] BreachSource=%s start=%s end=%s new=%s duplicates=%s",
                        source_name,
                        source_start.isoformat(),
                        source_end.isoformat(),
                        result.get("inserted", 0),
                        result.get("duplicates", 0),
                    )
            except Exception as exc:  # noqa: BLE001 - one breach source must not stop the rest
                total_errors += 1
                source_end = datetime.now(timezone.utc)
                source_results[source_name] = {"error": str(exc)}
                logger.error(
                    "[THREAT INTEL COLLECT] BreachSource=%s FAILED start=%s end=%s error=%r",
                    source_name,
                    source_start.isoformat(),
                    source_end.isoformat(),
                    exc,
                )
    finally:
        _collection_in_progress = False
        _collection_lock.release()

    ended_at = datetime.now(timezone.utc)
    logger.info(
        "[THREAT INTEL COLLECT] ===== Collection ended at %s (fetched=%d new=%d duplicates=%d errors=%d) =====",
        ended_at.isoformat(),
        total_fetched,
        total_inserted,
        total_duplicates,
        total_errors,
    )

    # Automatic AI enrichment: analyze any newly inserted (unprocessed)
    # articles so severity, threat_type, summary, confidence, mitre_techniques
    # etc. are populated immediately after collection. Already-processed
    # articles are skipped by process_unprocessed_articles(), so this is safe
    # to run on every refresh and does not reprocess old articles.
    enrichment = {
        "processed": 0,
        "failed": 0,
        "skipped": 0,
        "error": None,
    }
    try:
        logger.info("[THREAT INTEL ENRICH] Starting AI enrichment of unprocessed articles")
        enrichment_result = service.process_unprocessed_articles(limit=1)
        enrichment["processed"] = enrichment_result.get("processed", 0)
        enrichment["failed"] = enrichment_result.get("failed", 0)
        logger.info(
            "[THREAT INTEL ENRICH] Enrichment complete: processed=%d failed=%d",
            enrichment["processed"],
            enrichment["failed"],
        )
    except Exception as exc:  # noqa: BLE001 - enrichment must not break collection reporting
        enrichment["error"] = str(exc)
        logger.error("[THREAT INTEL ENRICH] Enrichment failed: %r", exc)

    # ── Continuous third-party pipeline ─────────────────────────────────────
    # After collection + enrichment, automatically run:
    #   threat_events → ThirdPartyCorrelationEngine → exposures
    #   → ThirdPartyAlertEngine → third_party_alerts → email notifications
    #
    # This makes the pipeline truly continuous: new intelligence is correlated
    # and alerted without any manual trigger. Idempotency is preserved by the
    # existing engines (they skip already-correlated events / existing alerts).
    pipeline = {
        "correlation": {"events_processed": 0, "exposures_created": 0, "error": None},
        "alerts": {"alerts_created": 0, "error": None},
        "external_monitoring": {"changes_detected": 0, "error": None},
    }
    try:
        logger.info("[THIRD-PARTY PIPELINE] Starting correlation of unprocessed threat events")
        from app.correlation.third_party_correlation import ThirdPartyCorrelationEngine
        corr_result = ThirdPartyCorrelationEngine().correlate_unprocessed_events(limit=100)
        pipeline["correlation"]["events_processed"] = corr_result.get("events_processed", 0)
        pipeline["correlation"]["exposures_created"] = corr_result.get("exposures_created", 0)
        logger.info(
            "[THIRD-PARTY PIPELINE] Correlation complete: events=%d exposures=%d",
            corr_result.get("events_processed", 0),
            corr_result.get("exposures_created", 0),
        )
    except Exception as exc:  # noqa: BLE001 - one stage must not stop the rest
        pipeline["correlation"]["error"] = str(exc)
        logger.error("[THIRD-PARTY PIPELINE] Correlation failed: %r", exc)

    try:
        logger.info("[THIRD-PARTY PIPELINE] Starting alert engine")
        from app.correlation.third_party_alert_engine import run_alert_engine
        alert_result = run_alert_engine(limit=100)
        pipeline["alerts"]["alerts_created"] = alert_result.get("total_created", 0)
        logger.info(
            "[THIRD-PARTY PIPELINE] Alert engine complete: alerts=%d",
            alert_result.get("total_created", 0),
        )
    except Exception as exc:  # noqa: BLE001
        pipeline["alerts"]["error"] = str(exc)
        logger.error("[THIRD-PARTY PIPELINE] Alert engine failed: %r", exc)

    try:
        logger.info("[THIRD-PARTY PIPELINE] Starting external asset monitoring")
        from app.risk.external_asset_monitor import run_external_asset_monitoring
        ext_result = run_external_asset_monitoring()
        pipeline["external_monitoring"]["changes_detected"] = ext_result.get("changes_detected", 0)
        logger.info(
            "[THIRD-PARTY PIPELINE] External monitoring complete: changes=%d",
            ext_result.get("changes_detected", 0),
        )
    except Exception as exc:  # noqa: BLE001
        pipeline["external_monitoring"]["error"] = str(exc)
        logger.error("[THIRD-PARTY PIPELINE] External monitoring failed: %r", exc)

    return {
        "status": "success",
        "message": "Threat feed collection completed.",
        "started_at": started_at.isoformat(),
        "completed_at": ended_at.isoformat(),
        "total_fetched": total_fetched,
        "total_inserted": total_inserted,
        "total_duplicates": total_duplicates,
        "total_errors": total_errors,
        "enriched": enrichment,
        "third_party_pipeline": pipeline,
        "sources": source_results,
        "last_updated": service.get_last_updated(),
    }

