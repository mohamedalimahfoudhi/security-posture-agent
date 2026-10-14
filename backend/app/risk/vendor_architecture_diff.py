"""
Vendor Architecture Diff Engine.

Compares two architecture document footprints (previous vs current) and
produces a structured diff of technology additions, removals, and version
changes, plus service additions/removals.

Used by the architecture change detection pipeline to:
- Detect what changed when a new architecture document is uploaded
- Update the third-party profile
- Recalculate risk
- Re-run threat correlation for newly discovered technologies
"""
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


def _normalize_tech(tech: str) -> str:
    """Normalize a technology name for comparison."""
    return (tech or "").strip().lower()


def _normalize_version(version: Optional[str]) -> str:
    """Normalize a version string for comparison."""
    v = (version or "").strip()
    if not v or v.lower() in ("unknown", "n/a", "none", "null"):
        return "unknown"
    return v


def _tech_key(tech: Dict[str, Any]) -> str:
    """Build a comparison key for a technology (name only, not version)."""
    return _normalize_tech(tech.get("technology") or "")


def _tech_version(tech: Dict[str, Any]) -> str:
    """Get the normalized version of a technology."""
    return _normalize_version(tech.get("version"))


def compare_architectures(
    previous_technologies: List[Dict[str, Any]],
    current_technologies: List[Dict[str, Any]],
    previous_services: Optional[List[Dict[str, Any]]] = None,
    current_services: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Compare two architecture footprints and return a structured diff.

    Args:
        previous_technologies: List of {technology, version, category} from the old doc
        current_technologies: List of {technology, version, category} from the new doc
        previous_services: Optional list of {service_name, service_type} from old doc
        current_services: Optional list of {service_name, service_type} from new doc

    Returns:
        {
            "added_technologies": [{technology, version, category}],
            "removed_technologies": [{technology, version, category}],
            "changed_versions": [{technology, from_version, to_version}],
            "unchanged_technologies": [{technology, version, category}],
            "added_services": [{service_name, service_type}],
            "removed_services": [{service_name, service_type}],
        }
    """
    # Build maps keyed by normalized technology name
    prev_map: Dict[str, Dict[str, Any]] = {}
    for t in previous_technologies or []:
        key = _tech_key(t)
        if key:
            prev_map.setdefault(key, t)

    curr_map: Dict[str, Dict[str, Any]] = {}
    for t in current_technologies or []:
        key = _tech_key(t)
        if key:
            curr_map.setdefault(key, t)

    added = []
    removed = []
    changed = []
    unchanged = []

    # Detect additions + version changes
    for key, curr_tech in curr_map.items():
        if key not in prev_map:
            added.append({
                "technology": curr_tech.get("technology"),
                "version": curr_tech.get("version"),
                "category": curr_tech.get("category"),
            })
        else:
            prev_tech = prev_map[key]
            prev_ver = _tech_version(prev_tech)
            curr_ver = _tech_version(curr_tech)
            if prev_ver != curr_ver:
                changed.append({
                    "technology": curr_tech.get("technology"),
                    "from_version": prev_ver,
                    "to_version": curr_ver,
                })
            else:
                unchanged.append({
                    "technology": curr_tech.get("technology"),
                    "version": curr_tech.get("version"),
                    "category": curr_tech.get("category"),
                })

    # Detect removals
    for key, prev_tech in prev_map.items():
        if key not in curr_map:
            removed.append({
                "technology": prev_tech.get("technology"),
                "version": prev_tech.get("version"),
                "category": prev_tech.get("category"),
            })

    # Service diff
    prev_svc = {(_normalize_tech(s.get("service_name") or "")): s for s in (previous_services or []) if s.get("service_name")}
    curr_svc = {(_normalize_tech(s.get("service_name") or "")): s for s in (current_services or []) if s.get("service_name")}

    added_services = [
        {"service_name": s.get("service_name"), "service_type": s.get("service_type")}
        for key, s in curr_svc.items() if key not in prev_svc
    ]
    removed_services = [
        {"service_name": s.get("service_name"), "service_type": s.get("service_type")}
        for key, s in prev_svc.items() if key not in curr_svc
    ]

    result = {
        "added_technologies": added,
        "removed_technologies": removed,
        "changed_versions": changed,
        "unchanged_technologies": unchanged,
        "added_services": added_services,
        "removed_services": removed_services,
    }

    logger.info(
        "Architecture diff: +%d added, -%d removed, %d version changes, %d unchanged, +%d services, -%d services",
        len(added), len(removed), len(changed), len(unchanged),
        len(added_services), len(removed_services),
    )
    return result


def has_changes(diff: Dict[str, Any]) -> bool:
    """Return True if the diff contains any meaningful changes."""
    return bool(
        diff.get("added_technologies")
        or diff.get("removed_technologies")
        or diff.get("changed_versions")
        or diff.get("added_services")
        or diff.get("removed_services")
    )