import sys
import time
import math
import hashlib
import zlib
from typing import ClassVar, Dict, Any, List
from abc import ABC, abstractmethod

from forensic_engine.context import ExtractionContext
from forensic_engine.constants import CATEGORY_FILE_INTEGRITY, RELIABILITY_MEDIUM

def _log(msg: str, verbose: bool) -> None:
    if verbose:
        print(f"[forensic-engine] {msg}", file=sys.stderr)

def compute_hashes(data: bytes) -> Dict[str, str]:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "crc32":  hex(zlib.crc32(data) & 0xFFFFFFFF),
    }

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq    = [0] * 256
    for b in data:
        freq[b] += 1
    length  = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p        = count / length
            entropy -= p * math.log2(p)
    return entropy

def detect_zip_header(data: bytes) -> bool:
    return data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06")

def chi_square_bit_test(bits: List[int]) -> float:
    if not bits:
        return 0.0
    n        = len(bits)
    ones     = sum(bits)
    zeros    = n - ones
    expected = n / 2.0
    return ((zeros - expected) ** 2 / expected) + ((ones - expected) ** 2 / expected)


class BaseExtractor(ABC):
    """
    Abstract base for all forensic evidence extractors.

    Subclasses implement _extract() and return the standard evidence schema.
    Class-level attributes declare category, reliability, and known
    methodological limitations.

    IMPORTANT: No extractor may produce verdicts, confidence scores, weighted
    decisions, or cross-extractor fusions. Raw measurements and factual
    observations only.
    """

    name:         ClassVar[str]       = "base"
    version:      ClassVar[str]       = "1.0"
    category:     ClassVar[str]       = CATEGORY_FILE_INTEGRITY
    RELIABILITY:  ClassVar[str]       = RELIABILITY_MEDIUM
    dependencies: ClassVar[List[str]] = []

    _LIMITATIONS:        ClassVar[List[str]] = []
    _FALSE_POSITIVES:    ClassVar[List[str]] = []
    _FALSE_NEGATIVES:    ClassVar[List[str]] = []

    def extract(self, context: ExtractionContext) -> Dict[str, Any]:
        """Run extraction and return the complete evidence schema."""
        start = time.perf_counter()

        for dep in self.dependencies:
            try:
                if getattr(context, dep)() is None:
                    return self._build_result(
                        status="unavailable",
                        summary=f"Required dependency '{dep}' is not available.",
                        execution_time=time.perf_counter() - start,
                    )
            except Exception as exc:
                return self._build_result(
                    status="unavailable",
                    summary=f"Dependency '{dep}' raised: {exc}",
                    execution_time=time.perf_counter() - start,
                )

        try:
            inner = self._extract(context)
        except Exception as exc:
            return self._build_result(
                status="error",
                summary=f"Extraction failed: {exc}",
                evidence={"exception": str(exc)},
                execution_time=time.perf_counter() - start,
            )

        return {
            "extractor":                self.name,
            "version":                  self.version,
            "category":                 self.category,
            "execution_time_s":         round(time.perf_counter() - start, 4),
            "status":                   inner.get("status", "ok"),
            "summary":                  inner.get("summary", ""),
            "raw_measurements":         inner.get("raw_measurements", {}),
            "evidence":                 inner.get("evidence", {}),
            "supports":                 inner.get("supports", []),
            "contradicts":              inner.get("contradicts", []),
            "limitations":              self._LIMITATIONS,
            "possible_false_positives": self._FALSE_POSITIVES,
            "possible_false_negatives": self._FALSE_NEGATIVES,
            "reliability":              self.RELIABILITY,
        }

    @abstractmethod
    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        """
        Perform the forensic measurement.

        Must return a dict containing at minimum:
          status, summary, raw_measurements, evidence, supports, contradicts
        """

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return True

    def _build_result(
        self,
        status:           str,
        summary:          str,
        raw_measurements: Dict[str, Any] = None,
        evidence:         Dict[str, Any] = None,
        execution_time:   float          = 0.0,
    ) -> Dict[str, Any]:
        return {
            "extractor":                self.name,
            "version":                  self.version,
            "category":                 self.category,
            "execution_time_s":         round(execution_time, 4),
            "status":                   status,
            "summary":                  summary,
            "raw_measurements":         raw_measurements or {},
            "evidence":                 evidence or {},
            "supports":                 [],
            "contradicts":              [],
            "limitations":              self._LIMITATIONS,
            "possible_false_positives": self._FALSE_POSITIVES,
            "possible_false_negatives": self._FALSE_NEGATIVES,
            "reliability":              self.RELIABILITY,
        }
