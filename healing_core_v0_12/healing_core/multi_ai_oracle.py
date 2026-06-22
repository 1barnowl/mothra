"""
healing_core.multi_ai_oracle
─────────────────────────────
MultiAIOracle — guide mandate:
  "asking all available AI services to fix code"
  "web search for solution / redirect to related module"

Architecture:
  ┌──────────────────────────────────────────────────┐
  │  MultiAIOracle                                   │
  │  ├── AnthropicBackend   (claude-sonnet-4-6)      │
  │  ├── WebSearchBackend   (DuckDuckGo instant API) │
  │  ├── LocalKnowledge     (KnowledgeCore lookup)   │
  │  └── OsFaultBackend     (OsFaultCatalog hints)   │
  └──────────────────────────────────────────────────┘

Each backend returns a CandidateFix.  The oracle:
  1. Queries all enabled backends concurrently (ThreadPoolExecutor)
  2. Scores each candidate by source confidence + content heuristics
  3. Returns the ranked list to the caller (RobustExceptionHandler)

Backends are independently toggleable and gracefully fall back on
any network / key error — the oracle always returns a result if
ANY backend has a suggestion.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Incident

log = logging.getLogger("healing_core.multi_ai_oracle")


# ── Candidate ──────────────────────────────────────────────────────────────────

@dataclass
class CandidateFix:
    """A fix suggestion from one oracle backend."""
    source:       str           # "anthropic" | "web_search" | "local_knowledge" | "os_catalog"
    name:         str           # short snake_case identifier
    description:  str
    command:      str  = ""     # shell command or Python snippet
    confidence:   float = 0.5   # 0–1
    raw:          str  = ""     # original backend response
    latency_ms:   float = 0.0


# ── Backends ───────────────────────────────────────────────────────────────────

class AnthropicBackend:
    """Calls Anthropic API for a structured fix JSON."""

    SOURCE = "anthropic"
    CONF   = 0.85

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514",
                 timeout: float = 12.0) -> None:
        self._key     = api_key
        self._model   = model
        self._timeout = timeout
        self._cache: Dict[str, CandidateFix] = {}

    @property
    def enabled(self) -> bool:
        return bool(self._key)

    def query(self, incident: "Incident") -> Optional[CandidateFix]:
        if not self.enabled:
            return None

        cache_key = f"{incident.event.error_type}:{incident.category.name}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            log.debug("multi_ai | anthropic cache hit for %s", cache_key)
            return cached

        import platform
        os_name = platform.system()
        prompt = (
            f"You are a senior reliability engineer.\n"
            f"A production system has this fault:\n"
            f"  error_type : {incident.event.error_type}\n"
            f"  category   : {incident.category.name}\n"
            f"  actor      : {incident.event.actor}\n"
            f"  subsystem  : {incident.event.subsystem}\n"
            f"  message    : {incident.event.message[:400]}\n"
            f"  os         : {os_name}\n\n"
            f"Respond with ONLY a JSON object (no markdown) with these keys:\n"
            f"  name        : short snake_case fix name\n"
            f"  command     : exact shell command or Python one-liner (safe to run)\n"
            f"  description : one sentence explaining what the command does\n"
            f"  confidence  : float 0.0-1.0 how confident you are this will fix it\n"
            f"\nBe conservative — prefer restarts, flushes, and config resets over "
            f"destructive commands.  If no safe command exists, set command to empty string."
        )

        payload = json.dumps({
            "model":      self._model,
            "max_tokens": 300,
            "messages":   [{"role": "user", "content": prompt}],
        }).encode()

        t0 = time.monotonic()
        try:
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data    = payload,
                headers = {
                    "Content-Type":      "application/json",
                    "x-api-key":         self._key,
                    "anthropic-version": "2023-06-01",
                },
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data    = json.loads(resp.read())
            raw_text = data.get("content", [{}])[0].get("text", "")
            latency  = (time.monotonic() - t0) * 1000

            # Strip possible markdown fences
            clean = re.sub(r"```(?:json)?|```", "", raw_text).strip()
            parsed  = json.loads(clean)
            fix = CandidateFix(
                source      = self.SOURCE,
                name        = f"ai_{parsed.get('name', incident.event.error_type)}",
                description = parsed.get("description", "AI-generated fix"),
                command     = parsed.get("command", ""),
                confidence  = float(parsed.get("confidence", self.CONF)),
                raw         = raw_text,
                latency_ms  = latency,
            )
            self._cache[cache_key] = fix
            log.info("multi_ai | anthropic → %s  conf=%.2f  ms=%.0f",
                     fix.name, fix.confidence, latency)
            return fix

        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            log.warning("multi_ai | anthropic HTTP error: %s", exc)
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            log.debug("multi_ai | anthropic parse error: %s  raw=%s", exc, raw_text[:120] if 'raw_text' in dir() else "")
        except Exception as exc:
            log.debug("multi_ai | anthropic unexpected: %s", exc)
        return None


class WebSearchBackend:
    """
    Queries DuckDuckGo Instant Answer API for a fix description.
    Zero external dependencies, completely free.
    """

    SOURCE = "web_search"
    CONF   = 0.45
    URL    = "https://api.duckduckgo.com/"

    def __init__(self, timeout: float = 5.0) -> None:
        self._timeout = timeout
        self._cache: Dict[str, CandidateFix] = {}

    @property
    def enabled(self) -> bool:
        return True  # always available (falls back gracefully)

    def query(self, incident: "Incident") -> Optional[CandidateFix]:
        query_str = (
            f"{incident.event.error_type} {incident.event.message[:80]} fix site:stackoverflow.com OR site:superuser.com"
        )
        cache_key = query_str[:80]
        if cache_key in self._cache:
            return self._cache[cache_key]

        params = urllib.parse.urlencode({
            "q":       query_str,
            "format":  "json",
            "no_html": "1",
            "skip_disambig": "1",
        })
        t0 = time.monotonic()
        try:
            req = urllib.request.Request(
                f"{self.URL}?{params}",
                headers={"User-Agent": "HealingCore/0.7 (+github.com/healing-core)"},
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read())
            latency = (time.monotonic() - t0) * 1000

            answer = (
                data.get("AbstractText") or
                data.get("Answer") or
                data.get("Definition") or
                ""
            )
            source_url = data.get("AbstractURL", "")

            if not answer:
                return None

            fix = CandidateFix(
                source      = self.SOURCE,
                name        = f"web_{incident.event.error_type}",
                description = answer[:300],
                command     = "",   # web results are descriptive, not command-ready
                confidence  = self.CONF,
                raw         = answer,
                latency_ms  = latency,
            )
            self._cache[cache_key] = fix
            log.info("multi_ai | web_search → %s  ms=%.0f  url=%s",
                     incident.event.error_type, latency, source_url[:60])
            return fix

        except Exception as exc:
            log.debug("multi_ai | web_search failed: %s", exc)
        return None


class LocalKnowledgeBackend:
    """
    Wraps KnowledgeCore.find_best_fix() as an oracle backend.
    Highest confidence because it's validated from past successes.
    """

    SOURCE = "local_knowledge"
    CONF   = 0.90

    def __init__(self, knowledge) -> None:
        self._knowledge = knowledge

    @property
    def enabled(self) -> bool:
        return self._knowledge is not None

    def query(self, incident: "Incident") -> Optional[CandidateFix]:
        try:
            fix_name = self._knowledge.find_best_fix(incident)
            if not fix_name:
                return None
            return CandidateFix(
                source      = self.SOURCE,
                name        = fix_name,
                description = f"Known fix from knowledge base: {fix_name}",
                command     = "",
                confidence  = self.CONF,
            )
        except Exception as exc:
            log.debug("multi_ai | local_knowledge error: %s", exc)
        return None


class OsFaultCatalogBackend:
    """
    Uses OsFaultCatalog to map error text → preferred primitive list.
    Returns the top-ranked primitive as a candidate.
    """

    SOURCE = "os_catalog"
    CONF   = 0.75

    def __init__(self, os_catalog) -> None:
        self._catalog = os_catalog

    @property
    def enabled(self) -> bool:
        return self._catalog is not None

    def query(self, incident: "Incident") -> Optional[CandidateFix]:
        try:
            import platform
            plat = "windows" if platform.system() == "Windows" else "linux"
            text  = f"{incident.event.error_type} {incident.event.message}"
            entry = self._catalog.lookup(text, platform=plat)
            if not entry or not entry.fix_primitives:
                return None
            prim = entry.fix_primitives[0]
            return CandidateFix(
                source      = self.SOURCE,
                name        = prim,
                description = (
                    f"OS catalog fix for '{entry.title}': {prim} "
                    f"(alternatives: {', '.join(entry.fix_primitives[1:3])})"
                ),
                command     = "",
                confidence  = self.CONF,
            )
        except Exception as exc:
            log.debug("multi_ai | os_catalog error: %s", exc)
        return None


class ExceptionCatalogBackend:
    """
    Uses ExceptionCatalog (Python exceptions) as an oracle backend.
    """

    SOURCE = "exception_catalog"
    CONF   = 0.80

    def __init__(self, exc_catalog) -> None:
        self._catalog = exc_catalog

    @property
    def enabled(self) -> bool:
        return self._catalog is not None

    def query(self, incident: "Incident") -> Optional[CandidateFix]:
        try:
            text  = f"{incident.event.error_type} {incident.event.message}"
            entry = self._catalog.lookup(text)
            if not entry or not entry.fix_hints:
                return None
            return CandidateFix(
                source      = self.SOURCE,
                name        = entry.fix_primitive,
                description = f"{entry.description}. Hint: {entry.fix_hints[0]}",
                command     = "",
                confidence  = self.CONF,
            )
        except Exception as exc:
            log.debug("multi_ai | exception_catalog error: %s", exc)
        return None


# ── MultiAIOracle ──────────────────────────────────────────────────────────────

class MultiAIOracle:
    """
    Queries all enabled AI and knowledge backends in parallel, ranks
    candidates by confidence, and returns the ordered list.

    Guide mandate: "asking all available AI services to fix code"
    """

    def __init__(
        self,
        *,
        anthropic_key:    str   = "",
        knowledge_core    = None,
        os_fault_catalog  = None,
        exception_catalog = None,
        max_workers:      int   = 4,
        timeout:          float = 15.0,
    ) -> None:
        self._timeout = timeout
        self._lock    = threading.Lock()
        self._stats: Dict[str, int] = {
            "queries": 0, "hits": 0, "anthropic_hits": 0,
            "web_hits": 0, "local_hits": 0, "catalog_hits": 0,
        }

        # Build backend list; order matters for tie-breaking
        self._backends = []
        if knowledge_core:
            self._backends.append(LocalKnowledgeBackend(knowledge_core))
        if exception_catalog:
            self._backends.append(ExceptionCatalogBackend(exception_catalog))
        if os_fault_catalog:
            self._backends.append(OsFaultCatalogBackend(os_fault_catalog))
        self._backends.append(WebSearchBackend())
        if anthropic_key:
            self._backends.append(AnthropicBackend(api_key=anthropic_key))

        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="hc_oracle",
        )
        log.info(
            "MultiAIOracle | %d backends enabled: %s",
            len([b for b in self._backends if b.enabled]),
            [b.SOURCE for b in self._backends if b.enabled],
        )

    # ── Public API ─────────────────────────────────────────────────────────

    def query(self, incident: "Incident") -> List[CandidateFix]:
        """
        Query all backends and return ranked CandidateFix list.
        Never raises — returns [] on total failure.
        """
        with self._lock:
            self._stats["queries"] += 1

        active = [b for b in self._backends if b.enabled]
        if not active:
            return []

        futures: Dict[Future, str] = {}
        for backend in active:
            fut = self._executor.submit(backend.query, incident)
            futures[fut] = backend.SOURCE

        results: List[CandidateFix] = []
        deadline = time.monotonic() + self._timeout

        for fut in as_completed(futures, timeout=max(0.1, deadline - time.monotonic())):
            source = futures[fut]
            try:
                candidate = fut.result(timeout=0.5)
                if candidate is not None:
                    results.append(candidate)
                    with self._lock:
                        self._stats["hits"] += 1
                        key = f"{source.split('_')[0]}_hits"
                        if key in self._stats:
                            self._stats[key] += 1
            except Exception as exc:
                log.debug("multi_ai | backend=%s error: %s", source, exc)

        # Sort: confidence DESC, then local_knowledge > exception_catalog >
        #        os_catalog > web_search > anthropic (tie-break by source trust order)
        source_rank = {
            "local_knowledge":    0,
            "exception_catalog":  1,
            "os_catalog":         2,
            "anthropic":          3,
            "web_search":         4,
        }
        results.sort(
            key=lambda c: (-c.confidence, source_rank.get(c.source, 9))
        )

        if results:
            log.info(
                "multi_ai | incident=%.8s  candidates=%d  top=%s(%.2f)",
                incident.id, len(results),
                results[0].source, results[0].confidence,
            )
        else:
            log.debug("multi_ai | no candidates for %s", incident.event.error_type)

        return results

    def query_top(self, incident: "Incident") -> Optional[CandidateFix]:
        """Return only the highest-ranked candidate, or None."""
        ranked = self.query(incident)
        return ranked[0] if ranked else None

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._stats)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False)
