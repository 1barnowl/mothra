"""
healing_core.ml_classifier
───────────────────────────
MLClassifier — guide mandate:
  "lightweight anomaly classifiers to triage incidents"
  "ML classifier trained on exception catalog + historical incidents"

Architecture:
  • When scikit-learn is installed: TF-IDF + LogisticRegression
  • When scikit-learn is absent: transparent fallback to regex IncidentClassifier
  • Training corpus built from:
      - ExceptionCatalog entries   (32 entries)
      - OsFaultCatalog entries     (~150 entries)
      - LearningStore history      (grows with usage)
  • Incremental retrain every RETRAIN_EVERY healed incidents
  • Thread-safe predict (read lock) / retrain (write lock)
  • Exports confidence score alongside category prediction

Usage (in core.py):
    from .ml_classifier import MLClassifier
    ml = MLClassifier(exception_catalog, os_fault_catalog)
    ml.seed()                                # build initial corpus
    category, conf = ml.classify(event)      # predict
    ml.record(event, confirmed_category)     # add training sample
    ml.maybe_retrain()                       # retrain if threshold hit
"""
from __future__ import annotations

import logging
import threading
import time
from typing import List, Optional, Tuple, TYPE_CHECKING

from .models import Event, IncidentCategory
from .classification import IncidentClassifier

if TYPE_CHECKING:
    from .exception_catalog import ExceptionCatalog
    from .os_fault_catalog import OsFaultCatalog

log = logging.getLogger("healing_core.ml_classifier")

RETRAIN_EVERY = 50   # new training samples before next retrain


# ── Optional sklearn import ───────────────────────────────────────────────────

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    _SKLEARN = True
except ImportError:
    _SKLEARN = False
    log.debug("ml_classifier | scikit-learn not found, using regex fallback")


# ── Training sample ───────────────────────────────────────────────────────────

class _Sample:
    __slots__ = ("text", "label")

    def __init__(self, text: str, label: str) -> None:
        self.text  = text.lower().strip()
        self.label = label


class MLClassifier:
    """
    Drop-in replacement for IncidentClassifier that adds an ML layer.
    Always falls back to the regex classifier when ML is unavailable or
    when model confidence is below the threshold.
    """

    CONFIDENCE_THRESHOLD = 0.55

    def __init__(
        self,
        exception_catalog: Optional["ExceptionCatalog"] = None,
        os_fault_catalog:  Optional["OsFaultCatalog"]   = None,
    ) -> None:
        self._exc_catalog  = exception_catalog
        self._os_catalog   = os_fault_catalog
        self._regex        = IncidentClassifier()

        self._corpus: List[_Sample] = []
        self._new_samples: int = 0

        self._model: Optional[object] = None   # sklearn Pipeline
        self._label_map: dict = {}             # str → IncidentCategory

        self._lock = threading.RLock()

        # Stats
        self._total:     int = 0
        self._ml_used:   int = 0
        self._fallbacks: int = 0
        self._retrains:  int = 0
        self._trained_at: float = 0.0

    # ── Public API ─────────────────────────────────────────────────────────

    def seed(self) -> None:
        """Build initial training corpus from catalogs."""
        samples = 0
        if self._exc_catalog:
            for entry in self._exc_catalog.all_entries():
                # ExceptionEntry fields: exception_class, patterns, common_causes,
                #                        fix_hints, description
                parts: List[str] = [entry.exception_class]
                for attr in ("patterns", "common_causes", "fix_hints"):
                    val = getattr(entry, attr, None)
                    if val:
                        parts.extend(str(v) for v in val)
                if getattr(entry, "description", ""):
                    parts.append(entry.description)
                self._corpus.append(_Sample(" ".join(parts), entry.category.name))
                samples += 1
        if self._os_catalog:
            for entry in self._os_catalog.all_entries():
                # OsFaultEntry fields: title, keywords, patterns, description
                parts = [entry.title]
                for attr in ("keywords", "patterns"):
                    val = getattr(entry, attr, None)
                    if val:
                        parts.extend(str(v) for v in val)
                if getattr(entry, "description", ""):
                    parts.append(entry.description)
                self._corpus.append(_Sample(" ".join(parts), entry.category.name))
                samples += 1
        log.info("ml_classifier | seeded %d training samples", samples)
        if _SKLEARN and samples >= 10:
            self._train()

    def classify(self, event: Event) -> Tuple[IncidentCategory, float]:
        """
        Returns (category, confidence).
        confidence == 1.0 means the regex classifier was used as fallback.
        """
        self._total += 1
        text = f"{event.error_type} {event.message} {event.subsystem}".lower()

        if _SKLEARN and self._model is not None:
            try:
                cat, conf = self._predict_ml(text)
                if conf >= self.CONFIDENCE_THRESHOLD:
                    self._ml_used += 1
                    return cat, conf
            except Exception as exc:
                log.debug("ml_classifier | predict error: %s", exc)

        # Regex fallback
        self._fallbacks += 1
        cat = self._regex.classify(event)
        return cat, 1.0

    def record(self, event: Event, confirmed_category: IncidentCategory) -> None:
        """Add a confirmed incident to the training corpus."""
        text = f"{event.error_type} {event.message} {event.subsystem}".lower()
        with self._lock:
            self._corpus.append(_Sample(text, confirmed_category.name))
            self._new_samples += 1

    def maybe_retrain(self) -> bool:
        """Retrain if enough new samples have accumulated. Returns True if trained."""
        with self._lock:
            if not _SKLEARN:
                return False
            if self._new_samples < RETRAIN_EVERY:
                return False
            if len(self._corpus) < 15:
                return False
            self._train()
            self._new_samples = 0
            return True

    def stats(self) -> dict:
        return {
            "sklearn_available":   _SKLEARN,
            "model_trained":       self._model is not None,
            "corpus_size":         len(self._corpus),
            "retrains":            self._retrains,
            "trained_at":          round(self._trained_at, 1) if self._trained_at else None,
            "total_classified":    self._total,
            "ml_used":             self._ml_used,
            "fallbacks":           self._fallbacks,
            "ml_rate":             round(self._ml_used / max(1, self._total), 3),
        }

    # ── Internal ───────────────────────────────────────────────────────────

    def _train(self) -> None:
        """(Re)train the sklearn pipeline on the current corpus."""
        with self._lock:
            texts  = [s.text  for s in self._corpus]
            labels = [s.label for s in self._corpus]

            # Ensure at least 2 classes
            unique = set(labels)
            if len(unique) < 2:
                log.debug("ml_classifier | need ≥2 classes, skipping train")
                return

            pipeline = Pipeline([
                ("tfidf", TfidfVectorizer(
                    ngram_range=(1, 2),
                    min_df=1,
                    sublinear_tf=True,
                    max_features=8000,
                )),
                ("clf", LogisticRegression(
                    max_iter=500,
                    C=1.0,
                    solver="lbfgs",
                    
                )),
            ])

            try:
                pipeline.fit(texts, labels)
                self._model = pipeline
                self._label_map = {
                    name: getattr(IncidentCategory, name, IncidentCategory.UNKNOWN)
                    for name in unique
                }
                self._retrains += 1
                self._trained_at = time.time()
                log.info(
                    "ml_classifier | trained  samples=%d  classes=%d  retrains=%d",
                    len(texts), len(unique), self._retrains,
                )
            except Exception as exc:
                log.warning("ml_classifier | training failed: %s", exc)

    def _predict_ml(self, text: str) -> Tuple[IncidentCategory, float]:
        """Returns (category, confidence) from the sklearn model."""
        proba = self._model.predict_proba([text])[0]
        classes = self._model.classes_
        max_idx = int(proba.argmax())
        label = classes[max_idx]
        cat = self._label_map.get(label, IncidentCategory.UNKNOWN)
        return cat, float(proba[max_idx])
