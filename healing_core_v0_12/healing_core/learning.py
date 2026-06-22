"""healing_core.learning — LearningStore + AdaptivePolicyEngine."""
from __future__ import annotations
import json, logging, sqlite3, time
from collections import defaultdict
from typing import TYPE_CHECKING, Dict, List
from .models import Incident, LearningRecord

if TYPE_CHECKING:
    from .policy import HealingPolicy

log = logging.getLogger("healing_core.learning")

class LearningStore:
    def __init__(self, db_path: str = "healing_core.db"):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS learning (
                id TEXT PRIMARY KEY, category TEXT, fix_name TEXT,
                outcome TEXT, detail TEXT, fingerprint TEXT, timestamp REAL
            )""")
        self._conn.commit()

    def record(self, incident: Incident, fix_name: str, outcome: str, detail: str = "") -> None:
        r = LearningRecord(
            category    = incident.category,
            fix_name    = fix_name,
            outcome     = outcome,
            detail      = detail,
            fingerprint = incident.event.fingerprint,
        )
        self._conn.execute(
            "INSERT INTO learning VALUES (?,?,?,?,?,?,?)",
            (r.id, r.category.name, r.fix_name, r.outcome, r.detail, r.fingerprint, r.timestamp)
        )
        self._conn.commit()

    def best_fix(self, category_name: str) -> str:
        row = self._conn.execute(
            "SELECT fix_name, COUNT(*) as n FROM learning "
            "WHERE category=? AND outcome='success' GROUP BY fix_name ORDER BY n DESC LIMIT 1",
            (category_name,)
        ).fetchone()
        return row[0] if row else ""

    def success_rate(self, fix_name: str) -> float:
        total   = self._conn.execute("SELECT COUNT(*) FROM learning WHERE fix_name=?", (fix_name,)).fetchone()[0]
        success = self._conn.execute("SELECT COUNT(*) FROM learning WHERE fix_name=? AND outcome='success'", (fix_name,)).fetchone()[0]
        return success / total if total else 0.0

    def recent(self, n: int = 20) -> List[Dict]:
        rows = self._conn.execute(
            "SELECT category,fix_name,outcome,timestamp FROM learning ORDER BY timestamp DESC LIMIT ?", (n,)
        ).fetchall()
        return [{"category": r[0], "fix_name": r[1], "outcome": r[2], "timestamp": r[3]} for r in rows]

    def category_stats(self) -> Dict[str, Dict]:
        rows = self._conn.execute(
            "SELECT category, outcome, COUNT(*) FROM learning GROUP BY category, outcome"
        ).fetchall()
        stats: Dict[str, Dict] = defaultdict(lambda: {"success": 0, "failure": 0, "verifier_failure": 0})
        for cat, outcome, count in rows:
            stats[cat][outcome] = count
        return dict(stats)


class AdaptivePolicyEngine:
    """Adjusts policy parameters based on learning outcomes."""
    def __init__(self, policy: "HealingPolicy", learning: LearningStore):
        self._policy   = policy
        self._learning = learning

    def update(self, incident: Incident) -> None:
        stats = self._learning.category_stats()
        cat   = incident.category.name
        if cat not in stats:
            return
        s = stats[cat]
        total = s.get("success", 0) + s.get("failure", 0)
        if total < 5:
            return   # not enough data
        rate = s.get("success", 0) / total
        if rate < 0.3 and self._policy.max_automated_attempts < 5:
            self._policy.max_automated_attempts += 1
            log.info("adaptive | increased max_attempts → %d  (cat=%s  rate=%.2f)",
                     self._policy.max_automated_attempts, cat, rate)
        elif rate > 0.8 and self._policy.cooldown_seconds > 10:
            self._policy.cooldown_seconds = max(10.0, self._policy.cooldown_seconds - 5)
            log.info("adaptive | reduced cooldown → %.1fs  (cat=%s  rate=%.2f)",
                     self._policy.cooldown_seconds, cat, rate)

    def summary(self) -> Dict:
        return self._learning.category_stats()
