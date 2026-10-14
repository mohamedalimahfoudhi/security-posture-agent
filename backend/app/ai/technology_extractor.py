from app.ai.ollama_client import ask_mistral_with_fallback, OLLAMA_MODEL
from app.ai.technology_patterns import TECHNOLOGY_PATTERNS, get_aliases, get_technology_by_name, KNOWN_CATEGORIES
import json
import re
import time
import logging

logger = logging.getLogger(__name__)

# Chunk size for large document processing
CHUNK_SIZE = 6000
CHUNK_OVERLAP = 500

# Mapping from old-style category names (LLM may still return them)
CATEGORY_ALIASES = {
    "os": "operating_system",
    "security_tool": "security_tools",
    "networking": "network_devices",
    "cloud": "cloud_provider",
}


def _normalize_category(cat: str) -> str:
    """Map legacy category names to current assets schema."""
    if not cat:
        return "other"
    mapped = CATEGORY_ALIASES.get(cat.lower(), cat.lower())
    # Ensure it's one of the known categories
    if mapped in KNOWN_CATEGORIES:
        return mapped
    return "other"


class TechnologyExtractor:
    """Extract technology information from document text using hybrid regex + AI"""
    
    def __init__(self):
        self.extraction_prompt = """
You are a cybersecurity architecture analyst. A regex engine has already extracted common technologies.
Your task is to FIND technologies MISSED by regex and add contextual information.

CRITICAL: Return ONLY a valid JSON object. No explanations. No markdown. No extra text.

Required JSON format:
{
  "assets": [
    {
      "technology": "Apache HTTP Server",
      "vendor": "Apache Software Foundation",
      "version": "2.4.49",
      "category": "web_server",
      "criticality": "high",
      "confidence": 85
    }
  ]
}

Focus on:
- Technologies that are NOT obviously named (no version number or well-known brand)
- Ambiguous technologies that need context
- Custom or in-house technologies
- Relationships between technologies
- Security controls, encryption standards, protocols
- Any technology the regex might have missed

Technology-to-Vendor Reference (use these exact mappings when applicable):
- Apache HTTP Server -> Apache Software Foundation
- Apache Tomcat -> Apache Software Foundation
- NGINX -> F5 Networks (formerly NGINX Inc)
- Microsoft IIS -> Microsoft Corporation
- PostgreSQL -> PostgreSQL Global Development Group
- MySQL -> Oracle Corporation
- MariaDB -> MariaDB Foundation
- MongoDB -> MongoDB Inc
- Redis -> Redis Ltd
- Elasticsearch -> Elastic
- OpenSSL -> The OpenSSL Project
- OpenSSH -> OpenBSD Project
- Linux -> Various (use specific distro vendor if known: Canonical/Ubuntu, Red Hat, Debian Project, etc.)
- Windows Server -> Microsoft Corporation
- Docker -> Docker Inc
- Kubernetes -> Cloud Native Computing Foundation
- VMware -> VMware Inc
- Cisco IOS -> Cisco Systems
- Juniper Junos -> Juniper Networks
- Palo Alto Networks -> Palo Alto Networks
- Splunk -> Splunk Inc
- Wazuh -> Wazuh Inc
- OPNsense -> Deciso
- pfSense -> Netgate

Rules:
- technology: The name of the technology (e.g., "Apache HTTP Server", "PostgreSQL", "OpenSSL").
- vendor: The company/organization that develops the technology. Use the reference above for well-known technologies. NEVER leave vendor empty or null - if unknown, use "Unknown Vendor".
- version: The version number (use null if not found).
- category: One of operating_system|web_server|database|cloud_provider|security_tools|container|devops|monitoring|network_devices|programming_language|framework|other.
- criticality: high|medium|low (default to medium if unclear).
- confidence: 60-90 based on confidence (lower than regex = 90-100).
- Do not include any explanations, markdown or extra text. Return ONLY the JSON object.

Document text:
"""

    # ------------------------------------------------------------------
    # Regex-based extraction
    # ------------------------------------------------------------------
    def _extract_with_regex(self, text: str) -> list:
        """Detect technologies using the technology_patterns database.

        Returns a list of asset dicts marked with extraction_source="regex".
        """
        regex_assets = []
        seen_in_text = set()

        for entry in TECHNOLOGY_PATTERNS:
            name = entry.get("name")
            vendor = entry.get("vendor")
            category = entry.get("category", "other")
            patterns = entry.get("patterns", [])
            version_re = entry.get("version_re")

            matched = False
            version = None

            for pattern in patterns:
                if not matched and re.search(pattern, text, re.IGNORECASE):
                    matched = True

            if not matched:
                continue

            # Extract version if a version_re is available
            if version_re:
                m = re.search(version_re, text, re.IGNORECASE)
                if m and m.group(1):
                    version = m.group(1).strip()

            # Deduplicate within regex pass (same canonical technology)
            if name in seen_in_text:
                continue
            seen_in_text.add(name)

            regex_assets.append({
                "technology": name,
                "vendor": vendor,
                "version": version,
                "category": _normalize_category(category),
                "criticality": "MEDIUM",
                "confidence": 95,
                "extraction_source": "regex",
            })

        logger.info(f"[REGEX EXTRACTION] Detected {len(regex_assets)} technologies via regex")
        return regex_assets

    # ------------------------------------------------------------------
    # Chunking for large documents
    # ------------------------------------------------------------------
    def _chunk_text(self, text: str) -> list:
        """Split long text into overlapping chunks for full coverage."""
        if len(text) <= CHUNK_SIZE:
            return [text]
        chunks = []
        start = 0
        while start < len(text):
            end = start + CHUNK_SIZE
            chunks.append(text[start:end])
            if end >= len(text):
                break
            start = max(0, end - CHUNK_OVERLAP)
        logger.info(f"[CHUNKING] Split {len(text)} chars into {len(chunks)} chunks (size={CHUNK_SIZE}, overlap={CHUNK_OVERLAP})")
        return chunks

# ------------------------------------------------------------------
    # Normalization & merge
    # ------------------------------------------------------------------
    def _normalize_assets(self, assets: list) -> list:
        """Canonicalize technology names using aliases and normalize categories.

        Also rebases the vendor to the canonical vendor from the pattern DB
        whenever the technology is known. This makes the vendor deterministic
        across extraction runs (the LLM may otherwise return slightly different
        vendor strings for the same technology, which would break the
        (technology, vendor, version) dedup key used at asset insertion).
        """
        alias_map = get_aliases()
        normalized = []
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            tech_name = asset.get("technology")
            if not tech_name:
                continue
            canonical = alias_map.get(str(tech_name).strip().lower(), tech_name)
            asset["technology"] = canonical

            # Rebase vendor to the canonical pattern-DB vendor when known.
            # This ensures the same technology always yields the same vendor
            # string regardless of what the LLM returned, so the dedup key
            # (technology, vendor, version) is stable across re-uploads.
            pattern_entry = get_technology_by_name(canonical)
            if pattern_entry:
                canonical_vendor = pattern_entry.get("vendor")
                if canonical_vendor and not self._is_unknown_vendor(canonical_vendor):
                    asset["vendor"] = canonical_vendor

            asset["category"] = _normalize_category(asset.get("category"))
            normalized.append(asset)
        return normalized

    @staticmethod
    def _is_unknown_vendor(vendor) -> bool:
        """Return True if vendor is missing or a generic 'unknown' placeholder."""
        if not vendor:
            return True
        return str(vendor).strip().lower() in ("unknown", "unknown vendor", "n/a", "none", "null")

    def _merge_asset(self, existing: dict, incoming: dict) -> None:
        """Merge an incoming asset into an existing one (same technology).

        - Regex data is authoritative for vendor/version (regex is seeded first).
        - Missing version/vendor on one side is filled from the other.
        - Highest confidence wins.
        - Keep the regex extraction_source when present.
        """
        # Fill missing version from the better source
        if not existing.get("version") and incoming.get("version"):
            existing["version"] = incoming["version"]
        # Fill missing vendor from a known vendor (not "Unknown Vendor")
        if self._is_unknown_vendor(existing.get("vendor")) and not self._is_unknown_vendor(incoming.get("vendor")):
            existing["vendor"] = incoming["vendor"]

        # Highest confidence wins
        try:
            existing_conf = float(existing.get("confidence", 0) or 0)
            incoming_conf = float(incoming.get("confidence", 0) or 0)
        except (TypeError, ValueError):
            existing_conf = incoming_conf = 0
        if incoming_conf > existing_conf:
            existing["confidence"] = incoming["confidence"]
            # Prefer regex source when confidence ties/exceeds
            if incoming.get("extraction_source") == "regex":
                existing["extraction_source"] = "regex"

        # Enrich optional fields if the existing entry lacks them
        for key in ("criticality", "internet_exposed", "sensitive_data"):
            if not existing.get(key) and incoming.get(key):
                existing[key] = incoming[key]

    def _merge_results(self, regex_assets: list, llm_assets: list) -> list:
        """Merge regex + LLM results with dedup.

        Dedup is keyed on TECHNOLOGY (and version) rather than vendor, so the
        same technology detected by regex (known vendor) and LLM ("Unknown
        Vendor") collapses into a single asset instead of creating duplicates.

        - Regex is seeded first and is authoritative for vendor/version.
        - Two instances of the same technology with DIFFERENT concrete versions
          are preserved as separate assets (e.g. Nginx 1.21 proxy + Nginx 1.24 LB).
        """
        # technology_lower -> list of assets (usually 1, may be >1 if versions differ)
        merged: dict = {}
        duplicates_removed = 0

        # Seed with regex assets (authoritative)
        for asset in regex_assets:
            tech = str(asset.get("technology") or "").strip().lower()
            if not tech:
                continue
            merged.setdefault(tech, []).append(dict(asset))

        for asset in llm_assets:
            tech = str(asset.get("technology") or "").strip().lower()
            if not tech:
                continue
            llm_version = (asset.get("version") or "").strip().lower()
            placed = False

            if tech in merged:
                for existing in merged[tech]:
                    ex_version = (existing.get("version") or "").strip().lower()
                    # Merge if same version, or either side has no version
                    if ex_version == llm_version or not ex_version or not llm_version:
                        self._merge_asset(existing, asset)
                        duplicates_removed += 1
                        placed = True
                        break
                if not placed:
                    # Different concrete version -> keep as separate asset
                    merged[tech].append(dict(asset))
            else:
                merged[tech] = [dict(asset)]

        result = []
        for assets_for_tech in merged.values():
            result.extend(assets_for_tech)

        logger.info(f"[MERGE] Merged {len(regex_assets)} regex + {len(llm_assets)} llm -> {len(result)} unique (removed {duplicates_removed} duplicates)")
        return result

    # ------------------------------------------------------------------
    # LLM extraction (kept from original)
    # ------------------------------------------------------------------
    def _extract_with_llm(self, text: str, model_used: str = OLLAMA_MODEL) -> list:
        """Run LLM extraction on a single text chunk. Returns cleaned assets."""
        prompt = self.extraction_prompt + text
        logger.info(f"[LLM EXTRACTION] Calling AI model (Mistral via Ollama)...")

        ai_result = ask_mistral_with_fallback(prompt)
        response = ai_result["response"]
        model_used = ai_result["model"]

        logger.info(f"[LLM EXTRACTION] Raw response received, length={len(response)} chars")
        logger.info(f"[LLM EXTRACTION] Full raw response: {response}")

        # ---- Parse JSON response (multiple strategies) ----
        result = None

        # Strategy 1: direct JSON
        try:
            result = json.loads(response)
            logger.info(f"[JSON PARSING] ✓ Direct JSON parsing successful")
        except json.JSONDecodeError:
            logger.info(f"[JSON PARSING] ✗ Direct JSON parsing failed, trying regex extraction")

        # Strategy 2: regex JSON object
        if result is None:
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                try:
                    result = json.loads(json_match.group(0))
                    logger.info(f"[JSON PARSING] ✓ JSON extracted using regex")
                except json.JSONDecodeError:
                    logger.info(f"[JSON PARSING] ✗ Regex JSON object extraction failed")

        # Strategy 3: array
        if result is None:
            array_match = re.search(r'\[[\s\S]*\]', response)
            if array_match:
                try:
                    parsed_array = json.loads(array_match.group(0))
                    result = {"assets": parsed_array}
                    logger.info(f"[JSON PARSING] ✓ Array extracted using regex")
                except json.JSONDecodeError:
                    logger.info(f"[JSON PARSING] ✗ Array extraction failed")

        # Strategy 4: markdown code block
        if result is None:
            markdown_match = re.search(r'```json\s*([\s\S]*?)\s*```', response)
            if markdown_match:
                try:
                    result = json.loads(markdown_match.group(1))
                    logger.info(f"[JSON PARSING] ✓ JSON extracted from markdown code block")
                except json.JSONDecodeError:
                    logger.info(f"[JSON PARSING] ✗ Markdown extraction failed")

        if result is None:
            logger.warning(f"[JSON PARSING] Could not extract valid JSON from LLM response")
            return []

        # Handle different response formats
        assets = []
        if isinstance(result, dict) and "assets" in result:
            assets = result["assets"]
        elif isinstance(result, list):
            assets = result

        # Clean up assets into standard shape
        cleaned_assets = []
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            cleaned_asset = {
                'technology': asset.get('technology'),
                'vendor': asset.get('vendor'),
                'version': asset.get('version'),
                'criticality': asset.get('criticality', 'MEDIUM'),
                'internet_exposed': asset.get('internet_exposed', False),
                'sensitive_data': asset.get('sensitive_data', False),
                'category': _normalize_category(asset.get('category', 'other')),
                'operating_system': asset.get('operating_system'),
                'database': asset.get('database'),
                'cloud_provider': asset.get('cloud_provider'),
                'web_server': asset.get('web_server'),
                'firewall': asset.get('firewall'),
                'virtualization': asset.get('virtualization'),
                'programming_language': asset.get('programming_language'),
                'framework': asset.get('framework'),
                'security_tools': asset.get('security_tools'),
                'network_devices': asset.get('network_devices'),
                'confidence': asset.get('confidence', 80),
                'extraction_source': 'llm',
            }
            if cleaned_asset['technology']:
                cleaned_assets.append(cleaned_asset)

        logger.info(f"[LLM EXTRACTION] Parsed {len(cleaned_assets)} technologies from LLM response")
        return cleaned_assets

    # ------------------------------------------------------------------
    # Main hybrid pipeline
    # ------------------------------------------------------------------
    def extract_from_text(self, text: str, filename: str = "") -> dict:
        """Extract technologies from text using hybrid regex + AI.

        Flow: regex extraction → LLM extraction (chunked) → merge → normalize → dedup.

        Returns:
            dict: On success: {"assets": [...], "model": str, "duration": float}
                  On failure: {"status": "failed", "reason": str, "model": str}
        """
        logger.info(f"[AI EXTRACTION] ========================================")
        logger.info(f"[AI EXTRACTION] Starting hybrid extraction from {filename}")
        start_time = time.time()
        model_used = OLLAMA_MODEL

        try:
            original_length = len(text)
            logger.info(f"[AI EXTRACTION] Input text length: {len(text)} characters")

            # ---- Step 1: Regex extraction on full text ----
            logger.info(f"[AI EXTRACTION] ========================================")
            logger.info(f"[REGEX EXTRACTION] Starting regex technology detection")
            regex_assets = self._extract_with_regex(text)
            logger.info(f"[REGEX EXTRACTION] Regex detected {len(regex_assets)} technologies")

            # ---- Step 2: LLM extraction with chunking for large docs ----
            logger.info(f"[AI EXTRACTION] ========================================")
            logger.info(f"[LLM EXTRACTION] Starting LLM extraction (chunked)")
            llm_assets = []
            chunks = self._chunk_text(text)
            llm_failed = False

            for idx, chunk in enumerate(chunks, 1):
                logger.info(f"[LLM EXTRACTION] Processing chunk {idx}/{len(chunks)} ({len(chunk)} chars)")
                try:
                    llm_assets.extend(self._extract_with_llm(chunk, model_used))
                except Exception as e:
                    logger.error(f"[LLM EXTRACTION] ✗ Chunk {idx} failed: {e}")
                    llm_failed = True
                    # If this is a timeout/connectivity issue, stop trying more chunks
                    if "connect" in str(e).lower() or "timeout" in str(e).lower():
                        logger.error(f"[LLM EXTRACTION] Ollama unavailable, stopping LLM chunk processing")
                        break
                    continue

            logger.info(f"[LLM EXTRACTION] LLM detected {len(llm_assets)} technologies across {len(chunks)} chunks")

            # If LLM completely failed and regex found nothing, return failure
            if llm_failed and not regex_assets and not llm_assets:
                total_time = time.time() - start_time
                return {
                    "status": "failed",
                    "reason": "AI extraction failed and no technologies detected via regex",
                    "model": model_used,
                }

            # ---- Step 3: Merge, normalize, dedup ----
            logger.info(f"[AI EXTRACTION] ========================================")
            logger.info(f"[MERGE] Merging regex and LLM results")
            merged_assets = self._merge_results(regex_assets, llm_assets)
            merged_assets = self._normalize_assets(merged_assets)

            if len(merged_assets) == 0:
                total_time = time.time() - start_time
                return {
                    "status": "failed",
                    "reason": "No technologies detected in document",
                    "model": model_used,
                }

            total_time = time.time() - start_time
            logger.info(f"[AI EXTRACTION] ========================================")
            logger.info(f"[AI EXTRACTION] Hybrid extraction complete")
            logger.info(f"[AI EXTRACTION] Regex detections: {len(regex_assets)}")
            logger.info(f"[AI EXTRACTION] LLM detections: {len(llm_assets)}")
            logger.info(f"[AI EXTRACTION] Final merged count: {len(merged_assets)}")
            logger.info(f"[AI EXTRACTION] Model used: {model_used}")
            logger.info(f"[AI EXTRACTION] Duration: {total_time:.2f}s")
            logger.info(f"[AI EXTRACTION] ========================================")
            return {
                "assets": merged_assets,
                "model": model_used,
                "duration": round(total_time, 2),
            }

        except Exception as e:
            logger.error(f"[AI EXTRACTION] ✗ Failed: {e}")
            import traceback
            logger.error(f"[AI EXTRACTION] Traceback: {traceback.format_exc()}")
            return {
                "status": "failed",
                "reason": f"Unexpected extraction error: {str(e)}",
                "model": OLLAMA_MODEL,
            }
