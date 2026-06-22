"""
healing_core.knowledge
──────────────────────
KnowledgeCore — the "K" component from the guide's pseudocode:

    fix ← SelectRemediation(classification, LEARNING_STORE, K)
    If fix == NULL:
        fix ← GenerateCandidateRemediation(classification, K)
    ...
    K.ingest({failure=classification, remediation=fix, result="success"})

Guide mandate:
  "converting successful repairs into new, versioned healing primitives
   the seed can reuse autonomously"
  "software building software … build program autonomously"
  "web search for solution / redirect to related module"

Architecture:
  ┌─────────────────────────────────────────────────────────────────┐
  │  KnowledgeCore                                                  │
  │  ├── PatternIndex      – fingerprint → ranked fix list          │
  │  ├── SimilarityMatcher – edit-distance / keyword overlap        │
  │  ├── AIGenerator       – Anthropic API for novel error types    │
  │  └── PrimitivePromoter – validated AI fixes → registry          │
  └─────────────────────────────────────────────────────────────────┘

Persistence: SQLite (same db as audit/learning for simplicity).
The AI generator calls Anthropic's claude-sonnet-4-20250514 via the
same pattern used in the AI-powered artifact API, falling back
gracefully when no key is configured.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Incident, IncidentCategory, RemediationFix
    from .primitives import PrimitivesRegistry

log = logging.getLogger("healing_core.knowledge")


# ── Pattern record ────────────────────────────────────────────────────────────

@dataclass
class KnowledgePattern:
    """A validated error→fix mapping stored in the knowledge base."""
    id:            str
    error_type:    str
    error_keywords: List[str]   # extracted from messages for similarity
    category:      str
    fix_name:      str
    fix_steps_src: str          # serialized step descriptions (not callables)
    success_count: int  = 0
    failure_count: int  = 0
    promoted:      bool = False
    source:        str  = "learned"  # learned | ai_generated | imported
    created_at:    float = field(default_factory=time.time)
    last_used:     float = field(default_factory=time.time)

    @property
    def score(self) -> float:
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.5
        recency = 1.0 / (1.0 + (time.time() - self.last_used) / 86400)
        return (self.success_count / total) * 0.7 + recency * 0.3


# ── KnowledgeCore ─────────────────────────────────────────────────────────────

class KnowledgeCore:
    """
    Cross-session persistent knowledge store.
    Finds, scores, and generates fix candidates for any incident.
    """

    def __init__(
        self,
        db_path:       str  = "healing_core.db",
        anthropic_key: str  = "",
        similarity_threshold: float = 0.35,
        ai_enabled:    bool = True,
    ) -> None:
        self._db             = sqlite3.connect(db_path, check_same_thread=False)
        self._anthropic_key  = anthropic_key
        self._sim_threshold  = similarity_threshold
        self._ai_enabled     = ai_enabled
        self._ai_cache: Dict[str, str] = {}   # error_type → last AI suggestion

        self._db.execute("""
            CREATE TABLE IF NOT EXISTS knowledge_patterns (
                id TEXT PRIMARY KEY,
                error_type TEXT, error_keywords TEXT, category TEXT,
                fix_name TEXT, fix_steps_src TEXT,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                promoted INTEGER DEFAULT 0,
                source TEXT DEFAULT 'learned',
                created_at REAL, last_used REAL
            )""")
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS ix_kp_error ON knowledge_patterns(error_type)"
        )
        self._db.commit()
        self._seed_builtins()

    # ── Public API ────────────────────────────────────────────────────────────

    def ingest(self, incident: "Incident", fix_name: str, outcome: str) -> None:
        """
        Called after every remediation attempt.
        Updates pattern scores and promotes if threshold reached.
        """
        etype = incident.event.error_type
        keywords = self._extract_keywords(incident.event.message)
        pat_id = hashlib.md5(f"{etype}:{fix_name}".encode()).hexdigest()

        row = self._db.execute(
            "SELECT success_count, failure_count FROM knowledge_patterns WHERE id=?",
            (pat_id,)
        ).fetchone()

        if row is None:
            self._db.execute(
                "INSERT INTO knowledge_patterns VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (pat_id, etype, json.dumps(keywords), incident.category.name,
                 fix_name, "", 0, 0, 0, "learned", time.time(), time.time())
            )

        if outcome == "success":
            self._db.execute(
                "UPDATE knowledge_patterns SET success_count=success_count+1, "
                "last_used=? WHERE id=?", (time.time(), pat_id)
            )
        else:
            self._db.execute(
                "UPDATE knowledge_patterns SET failure_count=failure_count+1 WHERE id=?",
                (pat_id,)
            )
        self._db.commit()
        log.debug("knowledge | ingested etype=%s fix=%s outcome=%s", etype, fix_name, outcome)

    def find_best_fix(self, incident: "Incident") -> Optional[str]:
        """
        Return the fix_name most likely to succeed for this incident,
        using exact match first then similarity fallback.
        """
        # 1. Exact error_type match
        rows = self._db.execute(
            "SELECT fix_name, success_count, failure_count FROM knowledge_patterns "
            "WHERE error_type=? AND success_count > 0 "
            "ORDER BY (CAST(success_count AS REAL)/(success_count+failure_count+1)) DESC LIMIT 3",
            (incident.event.error_type,)
        ).fetchall()
        if rows:
            return rows[0][0]

        # 2. Category-level fallback
        rows = self._db.execute(
            "SELECT fix_name, success_count, failure_count FROM knowledge_patterns "
            "WHERE category=? AND success_count > 0 "
            "ORDER BY (CAST(success_count AS REAL)/(success_count+failure_count+1)) DESC LIMIT 1",
            (incident.category.name,)
        ).fetchone()
        if rows:
            return rows[0]

        # 3. Similarity match
        return self._similarity_match(incident)

    def generate_candidate(self, incident: "Incident") -> Optional["RemediationFix"]:
        """
        For novel/unknown errors, call the AI to suggest a fix.
        Falls back gracefully if no key or network unavailable.
        """
        if not self._ai_enabled:
            return None

        etype = incident.event.error_type
        if etype in self._ai_cache:
            log.debug("knowledge | AI cache hit for %s", etype)
            return self._build_fix_from_ai(incident, self._ai_cache[etype])

        suggestion = self._call_anthropic(incident)
        if suggestion:
            self._ai_cache[etype] = suggestion
            # Persist as an AI-generated pattern
            self._store_ai_pattern(incident, suggestion)
            return self._build_fix_from_ai(incident, suggestion)
        return None

    def promote_to_registry(self, fix_name: str,
                             registry: "PrimitivesRegistry") -> bool:
        """
        If a learned fix has hit the promotion threshold, build a real
        RemediationFix and register it.
        """
        row = self._db.execute(
            "SELECT error_type, category, fix_name, fix_steps_src, "
            "success_count, failure_count, promoted "
            "FROM knowledge_patterns WHERE fix_name=? "
            "AND success_count >= 3 AND promoted=0 LIMIT 1",
            (fix_name,)
        ).fetchone()
        if not row:
            return False

        from .models import RemediationFix, IncidentCategory
        try:
            cat = IncidentCategory[row[1]]
        except KeyError:
            cat = IncidentCategory.UNKNOWN

        fix = RemediationFix(
            name        = f"promoted_{row[2]}",
            category    = cat,
            description = f"Auto-promoted from knowledge base (etype={row[0]})",
            source      = "knowledge_promoted",
            cost        = 0.4,
            impact      = 0.4,
            steps       = [lambda inc, _s=row[3]: log.info("[promoted-fix] %s", _s)],
        )
        registry.register(fix)
        self._db.execute(
            "UPDATE knowledge_patterns SET promoted=1 WHERE fix_name=?", (fix_name,)
        )
        self._db.commit()
        log.info("knowledge | promoted fix=%s → registry", fix_name)
        return True

    def summary(self) -> Dict[str, Any]:
        row = self._db.execute(
            "SELECT COUNT(*), SUM(success_count), SUM(failure_count), "
            "SUM(CASE WHEN promoted=1 THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN source='ai_generated' THEN 1 ELSE 0 END) "
            "FROM knowledge_patterns"
        ).fetchone()
        total, succ, fail, prom, ai_gen = row
        total = total or 0
        succ  = succ  or 0
        fail  = fail  or 0
        return {
            "patterns":      total,
            "total_success": succ,
            "total_failure": fail,
            "promoted":      prom or 0,
            "ai_generated":  ai_gen or 0,
            "overall_rate":  round(succ / (succ + fail), 3) if (succ + fail) else 0.0,
            "ai_enabled":    self._ai_enabled,
            "ai_cache_size": len(self._ai_cache),
        }

    def top_patterns(self, n: int = 10) -> List[Dict]:
        rows = self._db.execute(
            "SELECT error_type, category, fix_name, success_count, failure_count, source "
            "FROM knowledge_patterns "
            "WHERE success_count > 0 "
            "ORDER BY success_count DESC LIMIT ?", (n,)
        ).fetchall()
        return [
            {"error_type": r[0], "category": r[1], "fix_name": r[2],
             "success": r[3], "failure": r[4], "source": r[5]}
            for r in rows
        ]

    # ── Similarity matching ───────────────────────────────────────────────────

    def _similarity_match(self, incident: "Incident") -> Optional[str]:
        """
        Find the most similar known error using keyword overlap (Jaccard).
        """
        query_kw = set(self._extract_keywords(
            f"{incident.event.error_type} {incident.event.message}"
        ))
        if not query_kw:
            return None

        rows = self._db.execute(
            "SELECT fix_name, error_keywords, success_count, failure_count "
            "FROM knowledge_patterns WHERE success_count > 0"
        ).fetchall()

        best_score, best_fix = 0.0, None
        for fix_name, kw_json, succ, fail in rows:
            try:
                stored_kw = set(json.loads(kw_json))
            except Exception:
                continue
            if not stored_kw:
                continue
            jaccard = len(query_kw & stored_kw) / len(query_kw | stored_kw)
            if jaccard > best_score:
                best_score = jaccard
                best_fix   = fix_name

        if best_score >= self._sim_threshold:
            log.debug("knowledge | similarity match fix=%s  score=%.3f", best_fix, best_score)
            return best_fix
        return None

    @staticmethod
    def _extract_keywords(text: str) -> List[str]:
        """Extract lowercase alphanumeric tokens > 3 chars, dedup, sort."""
        words = re.findall(r'[a-z0-9_]{4,}', text.lower())
        stop  = {"with", "that", "this", "from", "have", "been", "will",
                 "when", "then", "after", "error", "fail", "failed"}
        return sorted(set(w for w in words if w not in stop))

    # ── AI candidate generation ───────────────────────────────────────────────

    def _call_anthropic(self, incident: "Incident") -> Optional[str]:
        """
        Call Anthropic API for a fix suggestion.
        Returns a plain-text description of what to try, or None on failure.
        """
        if not self._anthropic_key:
            log.debug("knowledge | no Anthropic key configured, skipping AI generation")
            return None

        prompt = (
            f"You are a systems reliability engineer. A service has the following fault:\n"
            f"  error_type: {incident.event.error_type}\n"
            f"  actor: {incident.event.actor}\n"
            f"  subsystem: {incident.event.subsystem}\n"
            f"  message: {incident.event.message[:300]}\n"
            f"  category: {incident.category.name}\n\n"
            f"Suggest ONE specific, safe, automated remediation step that can be "
            f"executed by a script on {'Windows' if __import__('platform').system() == 'Windows' else 'Linux'}. "
            f"Reply with ONLY: a JSON object with keys 'name' (short snake_case), "
            f"'command' (the exact shell command or Python snippet), "
            f"'description' (one sentence). No markdown, no explanation."
        )

        payload = json.dumps({
            "model":      "claude-sonnet-4-20250514",
            "max_tokens": 300,
            "messages":   [{"role": "user", "content": prompt}],
        }).encode()

        try:
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data    = payload,
                headers = {
                    "Content-Type":      "application/json",
                    "x-api-key":         self._anthropic_key,
                    "anthropic-version": "2023-06-01",
                },
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            text = data.get("content", [{}])[0].get("text", "")
            if text:
                log.info("knowledge | AI generated suggestion for %s", incident.event.error_type)
                return text.strip()
        except urllib.error.HTTPError as e:
            log.warning("knowledge | Anthropic API error: %s", e)
        except Exception as e:
            log.debug("knowledge | AI call failed: %s", e)
        return None

    def _build_fix_from_ai(self, incident: "Incident", ai_text: str) -> "RemediationFix":
        """Wrap AI suggestion in a RemediationFix."""
        from .models import RemediationFix

        # Try to parse JSON suggestion; fall back to plain text
        name, description = f"ai_{incident.event.error_type}", ai_text[:200]
        try:
            parsed = json.loads(ai_text)
            name        = f"ai_{parsed.get('name', incident.event.error_type)}"
            description = parsed.get("description", ai_text[:200])
            command     = parsed.get("command", "")
            steps = [
                lambda inc, cmd=command:
                __import__("subprocess").run(cmd, shell=True, capture_output=True, timeout=30)
                if cmd else log.info("[ai-fix] %s", description)
            ]
        except (json.JSONDecodeError, KeyError):
            steps = [lambda inc, d=description: log.info("[ai-fix] %s", d)]

        return RemediationFix(
            name        = name,
            category    = incident.category,
            description = description,
            source      = "ai_generated",
            cost        = 0.5,
            impact      = 0.4,
            steps       = steps,
        )

    def _store_ai_pattern(self, incident: "Incident", ai_text: str) -> None:
        import uuid
        pat_id   = str(uuid.uuid4())
        keywords = self._extract_keywords(
            f"{incident.event.error_type} {incident.event.message}"
        )
        self._db.execute(
            "INSERT OR IGNORE INTO knowledge_patterns VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (pat_id, incident.event.error_type, json.dumps(keywords),
             incident.category.name, f"ai_{incident.event.error_type}",
             ai_text[:500], 0, 0, 0, "ai_generated", time.time(), time.time())
        )
        self._db.commit()

    # ── Seed built-in patterns ────────────────────────────────────────────────

    def _store_synthesized_pattern(self, incident: "Incident", fix: "RemediationFix") -> None:
        """Store a synthesized fix as a knowledge pattern for future reuse."""
        import uuid
        pat_id   = str(uuid.uuid4())
        keywords = self._extract_keywords(
            f"{incident.event.error_type} {incident.event.message}"
        )
        cmd = getattr(fix, "_raw_command", "")
        self._db.execute(
            "INSERT OR IGNORE INTO knowledge_patterns VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (pat_id, incident.event.error_type, json.dumps(keywords),
             incident.category.name, fix.name,
             f"synthesized:{cmd[:300]}", 0, 0, 0, "synthesized",
             time.time(), time.time())
        )
        self._db.commit()
        log.info("knowledge | stored synthesized pattern fix=%s", fix.name)

    def _seed_builtins(self) -> None:
        """Pre-populate with high-confidence known mappings."""
        seeds = [
            # (error_type, category, fix_name, keywords, success_count)
            ("wifi_down",         "NETWORK",   "restart_wifi",         ["wifi","interface","carrier","wlan"],    5),
            ("dns_failure",       "NETWORK",   "flush_dns",            ["dns","resolv","nxdomain","lookup"],     5),
            ("gateway_unreachable","NETWORK",  "release_renew_ip",     ["gateway","unreachable","dhcp"],         4),
            ("service_hung",      "SERVICE",   "restart_service",      ["hung","deadlock","service","timeout"],  5),
            ("service_crash",     "SERVICE",   "restart_service",      ["crash","killed","exited","segfault"],   5),
            ("memory_depletion",  "RESOURCE",  "drop_caches",          ["memory","oom","rss","heap","leak"],     4),
            ("disk_full",         "RESOURCE",  "clear_temp",           ["disk","full","space","inode"],          4),
            ("cpu_overload",      "RESOURCE",  "renice_process",       ["cpu","overload","high","throttle"],     4),
            ("config_corrupt",    "CONFIGURATION","restore_config",    ["config","corrupt","invalid","yaml"],    3),
            ("auth_failure",      "AUTHENTICATION","sync_time",        ["auth","kerberos","ldap","login","token"],3),
            ("malware_detected",  "MALWARE",   "run_defender_scan",    ["malware","ransomware","virus","trojan"],4),
            ("cert_expiry",       "AUTHENTICATION","update_cert",      ["cert","tls","ssl","expired","x509"],    3),
            ("api_down",          "DEPENDENCY","flush_dns",            ["api","503","upstream","endpoint"],      3),
            ("disk_failure",      "HARDWARE",  "chkdsk",               ["disk","bad","sector","smart","io"],     3),
            ("time_sync_failure", "SYSTEMIC",  "sync_time",            ["time","ntp","clock","drift","sync"],    5),
        ]
        import uuid
        for etype, cat, fix, kws, succ in seeds:
            pat_id = hashlib.md5(f"{etype}:{fix}".encode()).hexdigest()
            self._db.execute(
                "INSERT OR IGNORE INTO knowledge_patterns VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (pat_id, etype, json.dumps(kws), cat, fix, "",
                 succ, 0, 0, "builtin", time.time(), time.time())
            )
        self._db.commit()
