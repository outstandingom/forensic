
#!/usr/bin/env python3
"""
Forensic Engine v10 — Evidence-Only Edition

Pure forensic evidence extraction engine. No AI decisions, no verdicts,
no confidence scores, no cross-extractor evidence fusion. Each extractor
measures and documents specific forensic signals according to accepted
scientific methodologies.

This engine's responsibility ends at evidence collection. All interpretation
is delegated to the examining analyst or a downstream reasoning system.

32 extractors organized across 6 forensic categories:
  camera_origin           — EXIF, XMP, IPTC, CFA Consistency, PRNU,
                            JPEG Quantization
  editing_detection       — ELA v1/v2, JPEG Ghost, Clone Detection,
                            Copy-Move v2, Resampling, Noise Inconsistency,
                            Compression History
  ai_statistical          — Wavelet Consistency, Power Spectrum,
                            Gradient Coherence, Local Patch Statistics,
                            AI Signal Heuristics, AI Block Heuristics,
                            Noise
  document_forensics      — PDF Metadata, PDF Structure, PDF Embedded,
                            PDF Fonts, PDF Hidden, PDF Layout, PDF Revision,
                            OCR, Font Consistency, OCR Image Consistency
  steganography           — LSB Analysis, Advanced RS Steganalysis
  file_integrity          — File Evidence, Statistics, Structure, Security,
                            Perceptual Hash

Schema: Every extractor returns:
  extractor               str   — extractor identifier
  version                 str   — version string
  category                str   — forensic category key
  execution_time_s        float — wall-clock seconds
  status                  str   — "ok" | "unavailable" | "error"
  summary                 str   — one-sentence factual description
  raw_measurements        dict  — all numeric/scalar outputs
  evidence                dict  — structured findings
  supports                list  — forensic possibilities consistent with data
  contradicts             list  — forensic hypotheses inconsistent with data
  limitations             list  — known scientific/technical limitations
  possible_false_positives list — real-world false-trigger conditions
  possible_false_negatives list — real-world miss conditions
  reliability             str   — "High" | "Medium" | "Low"

Reliability Definitions:
  High   — Well-established forensic method; repeatable, peer-reviewed.
  Medium — Accepted heuristic with corroborating value; some ambiguity.
  Low    — Experimental or content-dependent; use as one of many signals.
"""

from __future__ import annotations

import os
import sys
import json
import hashlib
import zlib
import math
import struct
import time
import io
import base64
import argparse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import ClassVar, Dict, Any, List, Optional, Tuple
from abc import ABC, abstractmethod
from collections import Counter
import warnings

warnings.filterwarnings("ignore")


# ─────────────────────────────────────────────────────────────────────────────
# Optional dependency imports
# ─────────────────────────────────────────────────────────────────────────────

try:
    import magic
except ImportError:
    magic = None

try:
    import exifread
except ImportError:
    exifread = None

try:
    import pypdf
except ImportError:
    pypdf = None

try:
    from PIL import Image, ImageChops, ImageStat
except ImportError:
    Image = ImageChops = ImageStat = None

try:
    import imagehash
except ImportError:
    imagehash = None

try:
    import cv2
    import numpy as np
except ImportError:
    cv2 = np = None

try:
    import pytesseract
except ImportError:
    pytesseract = None

try:
    from pdf2image import convert_from_bytes
except ImportError:
    convert_from_bytes = None

_SCIPY_OK = True
try:
    from scipy import ndimage
    from scipy import fft as sp_fft
except ImportError:
    _SCIPY_OK = False
    ndimage = sp_fft = None

_PDFMINER_OK = True
try:
    from pdfminer.high_level import extract_text
    from pdfminer.layout import LTTextBox, LTTextLine, LTChar, LTRect
    from pdfminer.converter import PDFPageAggregator
    from pdfminer.pdfparser import PDFParser
    from pdfminer.pdfdocument import PDFDocument
    from pdfminer.pdfpage import PDFPage
    from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
    from pdfminer.layout import LAParams
except ImportError:
    _PDFMINER_OK = False
    LAParams = None


# ─────────────────────────────────────────────────────────────────────────────
# Configuration & category constants
# ─────────────────────────────────────────────────────────────────────────────

MAX_MEMORY_FILE_SIZE: int = 1024 * 1024 * 1024  # 1 GB
PDF_IMAGE_RESOLUTION: int = 150
STEGO_SAMPLE_PIXELS: int  = 20_000

CATEGORY_CAMERA_ORIGIN  = "camera_origin"
CATEGORY_EDITING        = "editing_detection"
CATEGORY_AI_STATISTICAL = "ai_statistical_indicators"
CATEGORY_DOCUMENT       = "document_forensics"
CATEGORY_STEGANOGRAPHY  = "steganography"
CATEGORY_FILE_INTEGRITY = "file_integrity"

RELIABILITY_HIGH   = "High"
RELIABILITY_MEDIUM = "Medium"
RELIABILITY_LOW    = "Low"

CATEGORY_LABELS: Dict[str, str] = {
    CATEGORY_CAMERA_ORIGIN:  "Camera Origin",
    CATEGORY_EDITING:        "Editing Detection",
    CATEGORY_AI_STATISTICAL: "AI Statistical Indicators",
    CATEGORY_DOCUMENT:       "Document Forensics",
    CATEGORY_STEGANOGRAPHY:  "Steganography",
    CATEGORY_FILE_INTEGRITY: "File Integrity",
}


def _log(msg: str, verbose: bool) -> None:
    if verbose:
        print(f"[forensic-engine] {msg}", file=sys.stderr)


# ─────────────────────────────────────────────────────────────────────────────
# Shared Extraction Context
# ─────────────────────────────────────────────────────────────────────────────

class ExtractionContext:
    """
    Shared mutable state passed to every extractor. Caches decoded images,
    PDF readers, OCR text, and layout data to avoid redundant computation
    across a pipeline run.
    """

    def __init__(self, file_path: str, raw_data: bytes, options: "RunOptions" = None) -> None:
        self.file_path            = file_path
        self.raw_data             = raw_data
        self.options              = options or RunOptions()
        self._mime_type: Optional[str] = None
        self._file_type: Optional[str] = None
        self._decoded_image            = None
        self._pdf_reader               = None
        self._ocr_text: Optional[str]  = None
        self._pdf_images: List         = []
        self._pdf_layout               = None
        self._warning: Optional[str]   = None

    @property
    def mime_type(self) -> str:
        if self._mime_type is None:
            self._detect_type()
        return self._mime_type

    @property
    def file_type(self) -> str:
        if self._file_type is None:
            self._detect_type()
        return self._file_type

    def _detect_type(self) -> None:
        ext  = os.path.splitext(self.file_path)[1].lower()
        mime = "application/octet-stream"
        if magic:
            try:
                mime = magic.from_buffer(self.raw_data, mime=True)
            except Exception:
                pass
        else:
            if ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"):
                mime = f"image/{ext[1:]}"
            elif ext == ".pdf":
                mime = "application/pdf"
        self._mime_type = mime
        self._file_type = (
            "image" if mime.startswith("image") else
            "pdf"   if mime == "application/pdf"  else
            "unknown"
        )
        if len(self.raw_data) > MAX_MEMORY_FILE_SIZE:
            self._warning = f"File size exceeds {MAX_MEMORY_FILE_SIZE // 1024 // 1024} MB."

    def get_decoded_image(self):
        if self._decoded_image is None and Image is not None and self.file_type == "image":
            try:
                img = Image.open(io.BytesIO(self.raw_data))
                img.load()
                self._decoded_image = img
            except Exception:
                self._decoded_image = False
        return self._decoded_image if self._decoded_image is not False else None

    def get_pdf_reader(self):
        if self._pdf_reader is None and pypdf is not None and self.file_type == "pdf":
            try:
                self._pdf_reader = pypdf.PdfReader(io.BytesIO(self.raw_data))
            except Exception:
                self._pdf_reader = False
        return self._pdf_reader if self._pdf_reader is not False else None

    @staticmethod
    def _safe_resources(page) -> dict:
        try:
            res = page.get("/Resources")
            if res is None:
                return {}
            return res.get_object() if hasattr(res, "get_object") else res
        except Exception:
            return {}

    def get_pdf_images(self) -> List:
        if not self._pdf_images and self.file_type == "pdf":
            reader = self.get_pdf_reader()
            if reader:
                for page_num, page in enumerate(reader.pages):
                    resources    = self._safe_resources(page)
                    xobjects_ref = resources.get("/XObject") if resources else None
                    if not xobjects_ref:
                        continue
                    try:
                        xobjects = xobjects_ref.get_object()
                    except Exception:
                        continue
                    for obj_name in xobjects:
                        try:
                            obj = xobjects[obj_name]
                            if obj.get("/Subtype") == "/Image":
                                img_data = obj.get_data()
                                if img_data:
                                    fmt  = "jpeg"
                                    filt = obj.get("/Filter")
                                    if filt == "/FlateDecode":
                                        fmt = "png"
                                    self._pdf_images.append((page_num, img_data, fmt))
                        except Exception:
                            continue
        return self._pdf_images

    def get_pdf_text_with_positions(self):
        if self._pdf_layout is None and self.file_type == "pdf" and _PDFMINER_OK:
            try:
                self._pdf_layout = self._extract_layout()
            except Exception:
                self._pdf_layout = False
        return self._pdf_layout if self._pdf_layout is not False else None

    def _extract_layout(self) -> Dict[str, Any]:
        if not _PDFMINER_OK:
            return {}
        layout_data: Dict[str, Any] = {"pages": [], "margins": {}}
        try:
            rsrcmgr     = PDFResourceManager()
            laparams    = LAParams()
            device      = PDFPageAggregator(rsrcmgr, laparams=laparams)
            interpreter = PDFPageInterpreter(rsrcmgr, device)
            parser      = PDFParser(io.BytesIO(self.raw_data))
            doc         = PDFDocument(parser)
            for page_num, page in enumerate(PDFPage.create_pages(doc)):
                interpreter.process_page(page)
                layout    = device.get_result()
                page_data = {"page": page_num, "texts": [], "rects": []}
                for element in layout:
                    if isinstance(element, LTTextBox):
                        for textline in element:
                            if isinstance(textline, LTTextLine):
                                entry = {
                                    "text": textline.get_text().strip(),
                                    "x0": textline.x0, "y0": textline.y0,
                                    "x1": textline.x1, "y1": textline.y1,
                                    "fontname": None, "size": None,
                                    "near_white": False,
                                }
                                for ch in textline:
                                    if isinstance(ch, LTChar):
                                        entry["fontname"] = getattr(ch, "fontname", None)
                                        entry["size"]     = getattr(ch, "size", None)
                                        color = self._char_color(ch)
                                        if color is not None and all(c > 0.92 for c in color):
                                            entry["near_white"] = True
                                        break
                                page_data["texts"].append(entry)
                    elif isinstance(element, LTRect):
                        page_data["rects"].append({
                            "x0": element.x0, "y0": element.y0,
                            "x1": element.x1, "y1": element.y1,
                        })
                layout_data["pages"].append(page_data)
            if layout_data["pages"]:
                first = layout_data["pages"][0]
                if first["texts"]:
                    xs = [t["x0"] for t in first["texts"]]
                    layout_data["margins"] = {
                        "left":   min(xs),
                        "right":  max(t["x1"] for t in first["texts"]),
                        "top":    max(t["y0"] for t in first["texts"]),
                        "bottom": min(t["y0"] for t in first["texts"]),
                    }
        except Exception:
            pass
        return layout_data

    @staticmethod
    def _char_color(ch) -> Optional[Tuple[float, ...]]:
        try:
            gs     = getattr(ch, "graphicstate", None)
            if gs is None:
                return None
            ncolor = getattr(gs, "ncolor", None)
            if ncolor is None:
                return None
            if isinstance(ncolor, (int, float)):
                return (float(ncolor),) * 3
            if isinstance(ncolor, (list, tuple)):
                return tuple(float(c) for c in ncolor)
        except Exception:
            return None

    def get_ocr_text(self) -> str:
        if self._ocr_text is None:
            if self.options.mode == "light":
                self._ocr_text = ""
                return self._ocr_text
            if self.file_type == "image" and pytesseract is not None:
                img = self.get_decoded_image()
                if img:
                    try:
                        self._ocr_text = pytesseract.image_to_string(img)
                    except Exception:
                        self._ocr_text = ""
            elif (self.file_type == "pdf"
                  and pytesseract is not None
                  and convert_from_bytes is not None):
                try:
                    images         = convert_from_bytes(self.raw_data, dpi=self.options.pdf_dpi)
                    self._ocr_text = "\n".join(pytesseract.image_to_string(i) for i in images)
                except Exception:
                    self._ocr_text = ""
            else:
                self._ocr_text = ""
        return self._ocr_text


class RunOptions:
    """Runtime configuration for a forensic engine run."""

    def __init__(
        self,
        mode:           str  = "full",
        include_images: bool = False,
        pdf_dpi:        int  = PDF_IMAGE_RESOLUTION,
        known_hashes:   set  = None,
        verbose:        bool = False,
    ) -> None:
        self.mode           = mode
        self.include_images = include_images
        self.pdf_dpi        = pdf_dpi
        self.known_hashes   = known_hashes or set()
        self.verbose        = verbose


# ─────────────────────────────────────────────────────────────────────────────
# Base Extractor
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# Shared utility functions
# ─────────────────────────────────────────────────────────────────────────────

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


# ═════════════════════════════════════════════════════════════════════════════
# FILE INTEGRITY
# ═════════════════════════════════════════════════════════════════════════════

class FileEvidenceExtractor(BaseExtractor):
    """Cryptographic hashes, byte entropy, MIME type, and structural validity."""

    name        = "file_evidence"
    version     = "10.0"
    category    = CATEGORY_FILE_INTEGRITY
    RELIABILITY = RELIABILITY_HIGH

    _LIMITATIONS = [
        "MIME detection uses file magic bytes only, not semantic content analysis.",
        "Structural validation covers file header / xref only; content integrity "
        "is not guaranteed.",
    ]
    _FALSE_POSITIVES = [
        "Legitimately encrypted or compressed files always produce high byte entropy.",
    ]
    _FALSE_NEGATIVES = [
        "SHA-256 duplicate detection requires a pre-populated known-hash list.",
    ]

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        data      = context.raw_data
        hashes    = compute_hashes(data)
        entropy   = shannon_entropy(data)
        corrupted = False
        if context.file_type == "image" and Image:
            try:
                Image.open(io.BytesIO(data)).verify()
            except Exception:
                corrupted = True
        elif context.file_type == "pdf" and pypdf:
            try:
                pypdf.PdfReader(io.BytesIO(data))
            except Exception:
                corrupted = True

        is_dup = hashes["sha256"] in context.options.known_hashes
        supports: List[str] = []

        if entropy > 7.9:
            supports.append(
                f"Byte entropy {entropy:.4f}/8.0 is consistent with encrypted, "
                "compressed, or densely packed binary content."
            )
        if corrupted:
            supports.append(
                "Structural validation failed — consistent with file truncation, "
                "malformation, or deliberate corruption."
            )
        if is_dup:
            supports.append(
                "SHA-256 matches a known-files hash list entry — possible duplicate "
                "or re-used file artifact."
            )
        if not corrupted and entropy <= 7.9:
            supports.append(
                "Structure valid and entropy within normal bounds — consistent "
                "with an intact, standard file."
            )

        return {
            "status":  "ok",
            "summary": (
                f"{context.file_type.upper()}, {len(data):,} bytes, "
                f"entropy={entropy:.4f}/8.0, structure={'valid' if not corrupted else 'INVALID'}."
            ),
            "raw_measurements": {
                "file_size_bytes": len(data),
                "entropy":         entropy,
                "corrupted":       corrupted,
                "is_duplicate":    is_dup,
            },
            "evidence": {
                "file_size_bytes": len(data),
                "mime_type":       context.mime_type,
                "extension":       os.path.splitext(context.file_path)[1].lower(),
                "hashes":          hashes,
                "entropy":         entropy,
                "corrupted":       corrupted,
                "is_duplicate":    is_dup,
            },
            "supports":    supports,
            "contradicts": [],
        }


class StatisticsExtractor(BaseExtractor):
    """Byte-frequency distribution and entropy across the full file body."""

    name        = "statistics"
    version     = "10.0"
    category    = CATEGORY_FILE_INTEGRITY
    RELIABILITY = RELIABILITY_HIGH

    _LIMITATIONS = [
        "Global statistics cannot localise anomalies to specific file regions.",
    ]
    _FALSE_POSITIVES: List[str] = []
    _FALSE_NEGATIVES: List[str] = []

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        data  = context.raw_data
        freq  = [0] * 256
        for b in data:
            freq[b] += 1
        total        = len(data)
        distribution = [count / total for count in freq] if total else []
        entropy      = shannon_entropy(data)
        null_freq    = distribution[0] if distribution else 0.0

        supports: List[str] = []
        if null_freq > 0.30:
            supports.append(
                f"Null bytes comprise {null_freq * 100:.1f}% of content — "
                "consistent with sparse data sections or structured padding."
            )

        return {
            "status":  "ok",
            "summary": f"Entropy={entropy:.4f}/8.0; null-byte frequency={null_freq:.4f}.",
            "raw_measurements": {"entropy": entropy, "null_byte_freq": null_freq},
            "evidence": {
                "entropy":               entropy,
                "null_byte_frequency":   null_freq,
                "byte_distribution_0_19": distribution[:20],
            },
            "supports":    supports,
            "contradicts": [],
        }


class StructureExtractor(BaseExtractor):
    """JPEG segment markers (images) and PDF page/xref structure."""

    name        = "structure"
    version     = "10.0"
    category    = CATEGORY_FILE_INTEGRITY
    RELIABILITY = RELIABILITY_HIGH

    _LIMITATIONS = [
        "JPEG marker list is capped at 20 entries.",
        "PDF xref presence check does not validate xref table integrity.",
    ]
    _FALSE_POSITIVES: List[str] = []
    _FALSE_NEGATIVES: List[str] = []

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        structure: Dict[str, Any] = {}
        supports: List[str]       = []

        if context.file_type == "image":
            markers = self._parse_jpeg(context.raw_data)
            structure["jpeg_markers"] = markers
            summary = f"Image: {len(markers)} JPEG markers parsed."

        elif context.file_type == "pdf":
            reader = context.get_pdf_reader()
            xref   = "missing"
            pages  = 0
            if reader:
                try:
                    xref  = "present" if reader.xref else "missing"
                except Exception:
                    pass
                pages = len(reader.pages)
            structure["pdf"] = {"num_pages": pages, "xref_table": xref}
            summary = f"PDF: {pages} page(s), xref={xref}."
            if xref == "missing":
                supports.append(
                    "Missing or unreadable cross-reference table may indicate "
                    "file corruption, manual editing, or a malformed PDF."
                )
        else:
            summary = "Unknown file type; structure not parsed."

        return {
            "status":           "ok",
            "summary":          summary,
            "raw_measurements": {},
            "evidence":         structure,
            "supports":         supports,
            "contradicts":      [],
        }

    @staticmethod
    def _parse_jpeg(data: bytes) -> List[str]:
        markers, i, n = [], 2, len(data)
        while i < n - 1:
            if data[i] != 0xFF:
                i += 1
                continue
            marker = data[i + 1]
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            if marker == 0xD9:
                break
            markers.append(hex(marker))
            if i + 4 > n:
                break
            seg_len = struct.unpack(">H", data[i + 2:i + 4])[0]
            if marker == 0xDA:
                break
            i += 2 + seg_len
        return markers[:20]


class SecurityExtractor(BaseExtractor):
    """PDF encryption, permission flags, and digital signature presence."""

    name        = "security"
    version     = "10.0"
    category    = CATEGORY_FILE_INTEGRITY
    RELIABILITY = RELIABILITY_HIGH

    _LIMITATIONS = [
        "Signature presence is detected but NOT validated — use a dedicated "
        "signature-verification tool for that purpose.",
    ]
    _FALSE_POSITIVES: List[str] = []
    _FALSE_NEGATIVES: List[str] = []

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        encrypted, permissions, sig_count = False, None, 0
        if context.file_type == "pdf":
            reader = context.get_pdf_reader()
            if reader:
                try:
                    encrypted = reader.is_encrypted
                except Exception:
                    pass
                try:
                    if encrypted and hasattr(reader, "permissions"):
                        permissions = reader.permissions
                except Exception:
                    pass

        supports: List[str] = []
        if encrypted:
            supports.append(
                "PDF encryption is present; full content extraction is limited "
                "to unencrypted header fields."
            )

        return {
            "status":  "ok",
            "summary": f"Encrypted={encrypted}; signatures={sig_count}.",
            "raw_measurements": {"encrypted": encrypted, "signature_count": sig_count},
            "evidence": {
                "encrypted":       encrypted,
                "permissions":     permissions,
                "signature_count": sig_count,
            },
            "supports":    supports,
            "contradicts": [],
        }


class PerceptualHashExtractor(BaseExtractor):
    """pHash, dHash, and aHash perceptual fingerprints for near-duplicate detection."""

    name        = "perceptual_hash"
    version     = "10.0"
    category    = CATEGORY_FILE_INTEGRITY
    RELIABILITY = RELIABILITY_HIGH

    _LIMITATIONS = [
        "Hashes carry no forensic meaning in isolation; they require a reference corpus.",
        "Distance thresholds for near-duplicate classification vary by use case.",
    ]
    _FALSE_POSITIVES: List[str] = []
    _FALSE_NEGATIVES = [
        "Heavy cropping or aspect-ratio changes defeat pHash matching.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type == "image"
                and imagehash is not None and Image is not None)

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        ph, dh, ah = (str(imagehash.phash(img)),
                      str(imagehash.dhash(img)),
                      str(imagehash.average_hash(img)))
        return {
            "status":  "ok",
            "summary": f"pHash={ph}.",
            "raw_measurements": {},
            "evidence": {"phash": ph, "dhash": dh, "ahash": ah},
            "supports": [
                "Perceptual hashes enable near-duplicate and modified-copy "
                "detection when compared against a reference image corpus."
            ],
            "contradicts": [],
        }


# ═════════════════════════════════════════════════════════════════════════════
# CAMERA ORIGIN
# ═════════════════════════════════════════════════════════════════════════════

class EXIFExtractor(BaseExtractor):
    """All EXIF metadata tags: camera make/model, timestamps, software, GPS."""

    name        = "exif"
    version     = "10.0"
    category    = CATEGORY_CAMERA_ORIGIN
    RELIABILITY = RELIABILITY_HIGH

    _LIMITATIONS = [
        "EXIF fields can be stripped, added, or modified without altering pixels.",
        "Software field may reflect post-processing, not the capture device.",
        "GPS coordinates are taken from metadata — not independently verified.",
    ]
    _FALSE_POSITIVES: List[str] = []
    _FALSE_NEGATIVES = [
        "EXIF is absent from AI-generated images, screenshots, or files "
        "processed by social media platforms that strip metadata.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return context.file_type == "image" and exifread is not None

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        tags: Dict[str, str] = {}
        try:
            raw_tags = exifread.process_file(io.BytesIO(context.raw_data), details=False)
            tags     = {tag: str(val) for tag, val in raw_tags.items()}
        except Exception:
            pass

        supports: List[str] = []
        if not tags:
            supports.append(
                "Absence of EXIF is consistent with AI-generated images, "
                "screenshots, or social-media-processed files that strip metadata."
            )
        else:
            make  = tags.get("Image Make",  "")
            model = tags.get("Image Model", "")
            if make or model:
                supports.append(
                    f"Camera/device present ({make.strip()} {model.strip()}).strip() — "
                    "consistent with camera-captured origin, though EXIF can be fabricated."
                )
            if tags.get("EXIF Software"):
                supports.append(
                    f"Software field: '{tags['EXIF Software']}' — indicates "
                    "post-processing or metadata rewriting after capture."
                )
            if tags.get("GPS GPSLatitude"):
                supports.append(
                    "GPS coordinates embedded in EXIF — location data present "
                    "but not independently verified."
                )

        return {
            "status":           "ok",
            "summary":          f"{len(tags)} EXIF tag(s) found." if tags else "No EXIF found.",
            "raw_measurements": {"tag_count": len(tags)},
            "evidence":         tags,
            "supports":         supports,
            "contradicts":      [],
        }


class XMPExtractor(BaseExtractor):
    """Raw XMP metadata block; may contain editing history and creator fields."""

    name        = "xmp"
    version     = "10.0"
    category    = CATEGORY_CAMERA_ORIGIN
    RELIABILITY = RELIABILITY_MEDIUM

    _LIMITATIONS = [
        "Only the first 500 characters of XMP are returned in the snippet field.",
        "Full XMP parsing requires domain-specific parsers (e.g., python-xmp-toolkit).",
    ]
    _FALSE_POSITIVES: List[str] = []
    _FALSE_NEGATIVES: List[str] = []

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return context.file_type == "image"

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        xmp_raw = img.info.get("xmp") or img.info.get("XML:com.adobe.xmp")
        if not xmp_raw:
            return {
                "status":  "ok",
                "summary": "No XMP metadata block found.",
                "raw_measurements": {"xmp_present": False},
                "evidence":         {"xmp_present": False},
                "supports": [
                    "Absence of XMP is consistent with images not processed by "
                    "Adobe or XMP-aware editing software."
                ],
                "contradicts": [],
            }
        if isinstance(xmp_raw, bytes):
            xmp_raw = xmp_raw.decode("utf-8", errors="replace")
        return {
            "status":  "ok",
            "summary": "XMP metadata block present.",
            "raw_measurements": {"xmp_present": True, "xmp_bytes": len(xmp_raw)},
            "evidence": {"xmp_present": True, "xmp_snippet": xmp_raw[:500]},
            "supports": [
                "XMP present — may contain editing history, software chain, or "
                "creator/rights information absent from core EXIF."
            ],
            "contradicts": [],
        }


class IPTCExtractor(BaseExtractor):
    """IPTC-IIM metadata (presence report only; full parsing requires iptcinfo3)."""

    name        = "iptc"
    version     = "10.0"
    category    = CATEGORY_CAMERA_ORIGIN
    RELIABILITY = RELIABILITY_LOW

    _LIMITATIONS = [
        "Full IPTC-IIM parsing is not implemented; install iptcinfo3 for "
        "complete field extraction.",
    ]
    _FALSE_POSITIVES: List[str] = []
    _FALSE_NEGATIVES: List[str] = []

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return context.file_type == "image"

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        return {
            "status":  "ok",
            "summary": "IPTC: full IIM parsing not implemented; dedicated library required.",
            "raw_measurements": {},
            "evidence": {
                "note": (
                    "IPTC-IIM parsing requires a dedicated parser such as iptcinfo3. "
                    "IPTC data may contain caption, copyright, keywords, and origin fields."
                )
            },
            "supports":    [],
            "contradicts": [],
        }


class JPEGQuantizationExtractor(BaseExtractor):
    """
    JPEG DQT segment parser — estimates quality per quantization table and
    measures cross-table quality spread.
    """

    name        = "jpeg_quantization"
    version     = "10.0"
    category    = CATEGORY_CAMERA_ORIGIN
    RELIABILITY = RELIABILITY_HIGH

    _LIMITATIONS = [
        "Quality estimation is a heuristic; non-standard encoders may deviate "
        "from the IJEG reference tables.",
    ]
    _FALSE_POSITIVES = [
        "Intentional luma/chroma quality separation appears as a quality spread "
        "without manipulation.",
    ]
    _FALSE_NEGATIVES = [
        "Lossless JPEG operations (jpegtran rotation) do not alter quantization "
        "tables and will not be detected here.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type == "image"
                and context.mime_type in ("image/jpeg", "image/jpg"))

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        tables = self._parse_dqt(context.raw_data)
        if not tables:
            return {
                "status":  "ok",
                "summary": "No DQT markers found.",
                "raw_measurements": {"tables_found": 0},
                "evidence":         {"tables_found": 0},
                "supports":    [],
                "contradicts": [],
            }

        table_data = []
        for tid, prec, vals in tables:
            q = self._estimate_quality(vals)
            table_data.append({
                "table_id":          tid,
                "precision":         prec,
                "estimated_quality": q,
                "mean_coefficient":  float(sum(vals) / len(vals)),
            })

        qualities = [t["estimated_quality"] for t in table_data]
        spread    = float(max(qualities) - min(qualities)) if len(qualities) >= 2 else 0.0

        supports: List[str] = []
        if spread > 15:
            supports.append(
                f"Quality spread {spread:.1f} pts across quantization tables — "
                "consistent with re-encoding at a different quality or using a "
                "different JPEG encoder."
            )
        else:
            supports.append(
                f"Quantization table quality spread {spread:.1f} pts — within "
                "the range expected for a single-encode operation."
            )

        raw: Dict[str, Any] = {
            "tables_found":             len(tables),
            "quality_spread":           spread,
            "quality_spread_above_15":  spread > 15,
        }
        for t in table_data:
            raw[f"table_{t['table_id']}_quality"]          = t["estimated_quality"]
            raw[f"table_{t['table_id']}_mean_coefficient"] = t["mean_coefficient"]

        return {
            "status":           "ok",
            "summary":          f"{len(tables)} DQT table(s); quality spread {spread:.1f} pts.",
            "raw_measurements": raw,
            "evidence":         {"tables": table_data, "quality_spread": spread},
            "supports":         supports,
            "contradicts":      [],
        }

    @staticmethod
    def _parse_dqt(data: bytes) -> List[Tuple[int, int, List[int]]]:
        tables, i, n = [], 2, len(data)
        while i < n - 1:
            if data[i] != 0xFF:
                i += 1
                continue
            marker = data[i + 1]
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            if marker == 0xD9:
                break
            if i + 4 > n:
                break
            seg_len = struct.unpack(">H", data[i + 2:i + 4])[0]
            if marker == 0xDB:
                payload, p = data[i + 4:i + 2 + seg_len], 0
                while p < len(payload):
                    pq_tq     = payload[p]
                    precision = pq_tq >> 4
                    table_id  = pq_tq & 0x0F
                    p += 1
                    count = 64 * (2 if precision else 1)
                    vals  = (list(struct.unpack(f">{64}H", payload[p:p + count]))
                             if precision else list(payload[p:p + count]))
                    tables.append((table_id, precision, vals))
                    p += count
            if marker == 0xDA:
                break
            i += 2 + seg_len
        return tables

    @staticmethod
    def _estimate_quality(values: List[int]) -> int:
        avg = sum(values) / len(values) if values else 1
        if avg <= 0:
            return 100
        q = 5000 / avg if avg < 100 else 200 - avg * 2
        return int(max(1, min(100, q)))


class CFAExtractor(BaseExtractor):
    """
    Bayer CFA demosaicing correlation strength across 32×32 blocks.
    Low scores are consistent with AI-generated, screenshot, or composited content.
    """

    name        = "cfa_consistency"
    version     = "10.0"
    category    = CATEGORY_CAMERA_ORIGIN
    RELIABILITY = RELIABILITY_MEDIUM

    _LIMITATIONS = [
        "Only the green channel and a bilinear-interpolation model are analysed.",
        "Reports a statistical tendency, not a binary camera/no-camera determination.",
    ]
    _FALSE_POSITIVES = [
        "Screenshots and composited images without camera origin score low.",
        "Heavily JPEG-compressed camera images show reduced CFA correlation.",
    ]
    _FALSE_NEGATIVES = [
        "High-resolution demosaicing + sharpening may partially restore CFA "
        "patterns in composited regions.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type == "image" and np is not None and cv2 is not None)

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        rgb   = np.array(img.convert("RGB"), dtype=np.float64)
        h, w  = rgb.shape[:2]
        block = 32
        scores: List[float] = [
            self._cfa_score(rgb[by:by + block, bx:bx + block, :])
            for by in range(0, h - block, block)
            for bx in range(0, w - block, block)
        ]
        if not scores:
            return {
                "status": "unavailable", "summary": "Image too small.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        arr      = np.array(scores)
        mean_    = float(arr.mean())
        std_     = float(arr.std())
        incon    = float(np.sum(np.abs(arr - mean_) > 2 * std_) / arr.size) if std_ > 0 else 0.0
        cfa_weak = mean_ < 0.15

        supports: List[str] = []
        if cfa_weak:
            supports.append(
                f"Mean CFA score {mean_:.4f} < 0.15 — consistent with AI-generated "
                "images, screenshots, or composited regions lacking demosaicing patterns."
            )
            return {
                "status":  "ok",
                "summary": f"CFA: mean={mean_:.4f}, blocks={len(scores)}, score_below_0.15=True.",
                "raw_measurements": {
                    "mean_cfa_score": mean_, "std_cfa_score": std_,
                    "inconsistency_ratio": incon, "blocks_analyzed": len(scores),
                    "mean_below_0.15": True,
                },
                "evidence": {
                    "mean_cfa_score": mean_, "std_cfa_score": std_,
                    "block_inconsistency_ratio": incon, "blocks_analyzed": len(scores),
                    "mean_below_threshold": True,
                    "method": "Green-channel bilinear-interpolation correlation heuristic",
                },
                "supports":    supports,
                "contradicts": ["Strong CFA correlation typical of unprocessed camera-captured images."],
            }
        else:
            supports.append(
                f"Mean CFA score {mean_:.4f} ≥ 0.15 — consistent with camera-captured "
                "imagery retaining demosaicing artifacts."
            )
            return {
                "status":  "ok",
                "summary": f"CFA: mean={mean_:.4f}, blocks={len(scores)}, score_below_0.15=False.",
                "raw_measurements": {
                    "mean_cfa_score": mean_, "std_cfa_score": std_,
                    "inconsistency_ratio": incon, "blocks_analyzed": len(scores),
                    "mean_below_0.15": False,
                },
                "evidence": {
                    "mean_cfa_score": mean_, "std_cfa_score": std_,
                    "block_inconsistency_ratio": incon, "blocks_analyzed": len(scores),
                    "mean_below_threshold": False,
                    "method": "Green-channel bilinear-interpolation correlation heuristic",
                },
                "supports":    supports,
                "contradicts": [],
            }

    @staticmethod
    def _cfa_score(patch: np.ndarray) -> float:
        g    = patch[:, :, 1]
        sim  = g.copy()
        sim[0::2, 0::2] = 0
        sim[1::2, 1::2] = 0
        interp = cv2.blur(sim, (3, 3))
        mask   = (sim == 0)
        if mask.sum() == 0:
            return 0.0
        a, b = g[mask].flatten(), interp[mask].flatten()
        if a.std() < 1e-6 or b.std() < 1e-6:
            return 0.0
        corr = np.corrcoef(a, b)[0, 1]
        return float(0.0 if np.isnan(corr) else abs(corr))


class PRNUExtractor(BaseExtractor):
    """
    Single-image PRNU residual energy spatial CV.
    NOTE: Camera attribution requires multi-image reference fingerprints.
    This measures spatial noise-texture inconsistency only.
    """

    name        = "prnu_residual"
    version     = "10.0"
    category    = CATEGORY_CAMERA_ORIGIN
    RELIABILITY = RELIABILITY_LOW

    _LIMITATIONS = [
        "Cannot attribute to a specific camera — a multi-image reference "
        "fingerprint is required for camera attribution.",
        "Measures spatial noise-texture inconsistency only.",
    ]
    _FALSE_POSITIVES = [
        "Images with naturally varying texture produce high CV without manipulation.",
    ]
    _FALSE_NEGATIVES = [
        "Smooth AI-generated images may produce uniformly low residuals.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type == "image" and np is not None and cv2 is not None)

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        gray     = np.array(img.convert("L"), dtype=np.float32)
        denoised = cv2.fastNlMeansDenoising(gray.astype(np.uint8), h=6).astype(np.float32)
        residual = gray - denoised
        h, w     = residual.shape
        block    = 64
        energies = [
            float(np.var(residual[by:by + block, bx:bx + block]))
            for by in range(0, h - block, block)
            for bx in range(0, w - block, block)
        ]
        if not energies:
            return {
                "status": "unavailable", "summary": "Image too small (need ≥ 64×64).",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        arr    = np.array(energies)
        mean_e = float(arr.mean())
        cv_    = float(arr.std() / mean_e) if mean_e > 0 else 0.0
        high   = cv_ > 0.8

        supports: List[str] = []
        if high:
            supports.append(
                f"Residual energy CV={cv_:.3f} > 0.8 — spatially heterogeneous noise "
                "texture, consistent with content from different capture pipelines."
            )
        else:
            supports.append(
                f"Residual energy CV={cv_:.3f} — spatially homogeneous noise, "
                "consistent with a uniform capture pipeline."
            )

        return {
            "status":  "ok",
            "summary": f"PRNU: mean_energy={mean_e:.4f}, CV={cv_:.4f}, blocks={len(energies)}.",
            "raw_measurements": {
                "blocks_analyzed": len(energies),
                "mean_residual_energy": mean_e,
                "residual_energy_cv": cv_,
                "cv_above_0.8": high,
            },
            "evidence": {
                "blocks_analyzed": len(energies),
                "mean_residual_energy": mean_e,
                "residual_energy_cv": cv_,
                "cv_above_0.8": high,
                "method": "NLMeans residual spatial CV",
                "important_note": (
                    "Single-image PRNU — not camera attribution. "
                    "Multi-image reference fingerprint required for attribution."
                ),
            },
            "supports":    supports,
            "contradicts": [],
        }


# ═════════════════════════════════════════════════════════════════════════════
# EDITING DETECTION
# ═════════════════════════════════════════════════════════════════════════════

class ELAExtractor(BaseExtractor):
    """ELA v1: global JPEG recompression error at quality 90."""

    name        = "ela"
    version     = "10.0"
    category    = CATEGORY_EDITING
    RELIABILITY = RELIABILITY_MEDIUM

    _LIMITATIONS = [
        "Single global metric; cannot localise anomalies. Use ela_v2 for block-level.",
        "Non-JPEG originals or multiply-saved images produce misleading scores.",
    ]
    _FALSE_POSITIVES = [
        "Low-quality originals produce high ELA scores without editing.",
        "Images saved at many different quality levels show high scores.",
    ]
    _FALSE_NEGATIVES = [
        "Editing re-saved at the same quality may not produce detectable differences.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return context.file_type == "image" and Image is not None

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        try:
            buf = io.BytesIO()
            img.convert("RGB").save(buf, "JPEG", quality=90)
            buf.seek(0)
            recomp   = Image.open(buf)
            diff     = ImageChops.difference(img.convert("RGB"), recomp.convert("RGB"))
            stat     = ImageStat.Stat(diff)
            mean_err = sum(stat.mean) / 3.0
            max_diff = max(stat.extrema[0]) if stat.extrema else None

            supports: List[str] = []
            if mean_err > 15:
                supports.append(
                    f"ELA mean error {mean_err:.2f} is elevated — consistent with "
                    "possible localised re-compression at a different quality setting."
                )
            elif mean_err <= 8:
                supports.append(
                    f"ELA mean error {mean_err:.2f} is low — consistent with a "
                    "uniform, single-compression history."
                )
            else:
                supports.append(
                    f"ELA mean error {mean_err:.2f} is moderate; content and "
                    "original quality context required for interpretation."
                )

            return {
                "status":  "ok",
                "summary": f"ELA mean error={mean_err:.4f} at JPEG Q90.",
                "raw_measurements": {
                    "ela_mean_error": mean_err,
                    "ela_max_diff":   max_diff,
                    "recompression_quality": 90,
                },
                "evidence": {
                    "ela_mean_error": mean_err,
                    "ela_max_diff":   max_diff,
                    "method":         "JPEG recompression at Q90; pixel-difference mean",
                },
                "supports":    supports,
                "contradicts": [],
            }
        except Exception as exc:
            return {
                "status": "error", "summary": str(exc),
                "raw_measurements": {}, "evidence": {"error": str(exc)},
                "supports": [], "contradicts": [],
            }


class ELAExtractorV2(BaseExtractor):
    """ELA v2: multi-quality (Q60/75/90) block-level hot-spot detection."""

    name        = "ela_v2"
    version     = "10.0"
    category    = CATEGORY_EDITING
    RELIABILITY = RELIABILITY_MEDIUM

    _LIMITATIONS = [
        "Hot-block threshold (2.5× global mean) is heuristic.",
        "Block size 32 px may miss very small spliced regions.",
    ]
    _FALSE_POSITIVES = [
        "Hard edges, text, and fine textures naturally produce high ELA blocks.",
    ]
    _FALSE_NEGATIVES = [
        "Editing at the same quality as the background will not be detected.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type == "image" and Image is not None and np is not None)

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        rgb     = img.convert("RGB")
        rgb_arr = np.array(rgb, dtype=np.int16)
        hi, wi  = rgb_arr.shape[:2]
        block   = 32
        scores, regions = {}, {}

        for q in (60, 75, 90):
            buf = io.BytesIO()
            rgb.save(buf, "JPEG", quality=q)
            buf.seek(0)
            recomp = np.array(Image.open(buf).convert("RGB"), dtype=np.int16)
            diff   = np.abs(rgb_arr - recomp).sum(axis=2)
            scores[q] = float(diff.mean())
            bm = [
                float(diff[by:by + block, bx:bx + block].mean())
                for by in range(0, hi - block, block)
                for bx in range(0, wi - block, block)
            ]
            gm = scores[q]
            hr = sum(1 for b in bm if b > gm * 2.5) / len(bm) if bm else 0.0
            regions[q] = {"global_mean": gm, "max_block_mean": max(bm) if bm else 0.0,
                          "hot_block_ratio": hr}

        max_hr    = max(r["hot_block_ratio"] for r in regions.values())
        has_spots = max_hr > 0.02

        supports: List[str] = []
        if has_spots:
            supports.append(
                f"Hot-block ratio {max_hr:.4f} > 0.02 at one or more quality levels — "
                "consistent with localised content from a different JPEG compression history."
            )
        else:
            supports.append(
                f"Max hot-block ratio {max_hr:.4f} is low across all tested quality "
                "levels — consistent with spatially uniform compression history."
            )

        raw: Dict[str, Any] = {"max_hot_block_ratio": max_hr, "hot_spots_above_0.02": has_spots}
        for q, r in regions.items():
            raw[f"q{q}_global_mean"]     = r["global_mean"]
            raw[f"q{q}_hot_block_ratio"] = r["hot_block_ratio"]

        return {
            "status":  "ok",
            "summary": f"ELA v2: max hot-block ratio={max_hr:.4f} (Q60/75/90).",
            "raw_measurements": raw,
            "evidence": {
                "scores_by_quality":   scores,
                "region_analysis":     regions,
                "max_hot_block_ratio": max_hr,
                "method": "Multi-quality JPEG ELA with 32-px block hot-spot ratio",
            },
            "supports":    supports,
            "contradicts": [],
        }


class CloneExtractor(BaseExtractor):
    """ORB feature-based copy-move detection (displaced >10 px keypoint pairs)."""

    name        = "clone_detection"
    version     = "10.0"
    category    = CATEGORY_EDITING
    RELIABILITY = RELIABILITY_LOW

    _LIMITATIONS = [
        "ORB is less precise than SIFT; use copy_move_v2 for geometric verification.",
    ]
    _FALSE_POSITIVES = [
        "Repetitive patterns (wallpaper, fabric) and bilateral symmetry produce "
        "matching keypoints without copy-move editing.",
    ]
    _FALSE_NEGATIVES = [
        "Copy-move of smooth feature-poor regions produces no ORB keypoints.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type == "image" and cv2 is not None
                and np is not None and context.options.mode != "light")

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        gray   = cv2.cvtColor(np.array(img.convert("RGB")), cv2.COLOR_RGB2GRAY)
        orb    = cv2.ORB_create()
        kp, des = orb.detectAndCompute(gray, None)
        if des is None or len(kp) < 2:
            return {
                "status":  "ok",
                "summary": "Insufficient ORB keypoints.",
                "raw_measurements": {"keypoints": len(kp) if kp else 0, "displaced_matches": 0},
                "evidence":         {"keypoints": len(kp) if kp else 0},
                "supports":    [],
                "contradicts": [],
            }
        bf      = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
        matches = bf.match(des, des)
        real    = sum(
            1 for m in matches
            if m.queryIdx != m.trainIdx
            and math.hypot(
                kp[m.queryIdx].pt[0] - kp[m.trainIdx].pt[0],
                kp[m.queryIdx].pt[1] - kp[m.trainIdx].pt[1],
            ) > 10
        )
        supports: List[str] = []
        if real > 10:
            supports.append(
                f"{real} ORB pairs with separation > 10 px — consistent with "
                "copy-move editing. Confirm with copy_move_v2 (SIFT+RANSAC)."
            )
        else:
            supports.append(
                f"Only {real} displaced ORB matches — insufficient evidence of "
                "copy-move from ORB alone."
            )
        return {
            "status":  "ok",
            "summary": f"ORB clone: {real} displaced matches (>10 px).",
            "raw_measurements": {"keypoints": len(kp), "displaced_matches": real, "above_10": real > 10},
            "evidence":         {"keypoints": len(kp), "displaced_matches": real,
                                 "method": "ORB matching; displacement threshold 10 px"},
            "supports":    supports,
            "contradicts": [],
        }


class CopyMoveExtractorV2(BaseExtractor):
    """SIFT + BFMatcher kNN + RANSAC homography — geometrically verified copy-move."""

    name        = "copy_move_v2"
    version     = "10.0"
    category    = CATEGORY_EDITING
    RELIABILITY = RELIABILITY_MEDIUM

    _LIMITATIONS = [
        "RANSAC threshold 5.0 px may miss very small displacements.",
        "Does not identify the shape or extent of copied regions.",
    ]
    _FALSE_POSITIVES = [
        "Highly repetitive textures may produce geometric correspondences "
        "without deliberate copy-move.",
    ]
    _FALSE_NEGATIVES = [
        "Smooth, textureless regions yield no SIFT keypoints.",
        "Post-editing blurring destroys SIFT features.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type == "image" and cv2 is not None
                and np is not None and context.options.mode != "light")

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        gray    = cv2.cvtColor(np.array(img.convert("RGB")), cv2.COLOR_RGB2GRAY)
        sift    = cv2.SIFT_create(nfeatures=2000)
        kp, des = sift.detectAndCompute(gray, None)
        if des is None or len(kp) < 8:
            return {
                "status":  "ok",
                "summary": f"Insufficient SIFT keypoints ({len(kp) if kp else 0}).",
                "raw_measurements": {"keypoints": len(kp) if kp else 0, "ransac_inliers": 0},
                "evidence":         {"note": "Insufficient keypoints for RANSAC."},
                "supports":    [],
                "contradicts": [],
            }
        bf      = cv2.BFMatcher()
        matches = bf.knnMatch(des, des, k=3)
        good    = []
        for grp in matches:
            for m in grp[1:]:
                if m.queryIdx == m.trainIdx:
                    continue
                if np.linalg.norm(np.array(kp[m.queryIdx].pt) - np.array(kp[m.trainIdx].pt)) > 16:
                    good.append(m)
                break
        if len(good) < 8:
            return {
                "status":  "ok",
                "summary": f"SIFT: {len(good)} candidates — insufficient for RANSAC.",
                "raw_measurements": {"keypoints": len(kp), "raw_matches": len(good), "ransac_inliers": 0},
                "evidence":    {"note": "Too few matches for RANSAC."},
                "supports":    [],
                "contradicts": [],
            }
        src = np.float32([kp[m.queryIdx].pt for m in good]).reshape(-1, 1, 2)
        dst = np.float32([kp[m.trainIdx].pt for m in good]).reshape(-1, 1, 2)
        _, mask   = cv2.findHomography(src, dst, cv2.RANSAC, 5.0)
        inliers   = int(mask.sum()) if mask is not None else 0
        geom      = inliers >= 8

        supports: List[str] = []
        if geom:
            supports.append(
                f"SIFT+RANSAC: {inliers} geometrically verified inliers (≥8 threshold) — "
                "consistent with a copy-move manipulation."
            )
        else:
            supports.append(
                f"Only {inliers} RANSAC inliers — below ≥8 threshold for geometrically "
                "verified copy-move evidence."
            )
        return {
            "status":  "ok",
            "summary": f"SIFT+RANSAC: {inliers} geometric inliers from {len(good)} candidates.",
            "raw_measurements": {
                "keypoints": len(kp), "raw_matches": len(good),
                "ransac_inliers": inliers, "inliers_meet_threshold": geom,
            },
            "evidence": {
                "keypoints": len(kp), "raw_matches": len(good),
                "ransac_inliers": inliers, "inlier_threshold": 8,
                "method": "SIFT + BFMatcher kNN (k=3) + RANSAC homography (5.0 px)",
            },
            "supports":    supports,
            "contradicts": [],
        }


class ResamplingExtractor(BaseExtractor):
    """
    Popescu–Farid (2005) resampling detection: Laplacian second-derivative
    + 2D FFT periodic peak analysis.
    """

    name        = "resampling"
    version     = "10.0"
    category    = CATEGORY_EDITING
    RELIABILITY = RELIABILITY_MEDIUM

    _LIMITATIONS = [
        "Peak threshold (0.0008) is a conservative heuristic.",
        "Cannot identify the type, scale, or direction of transformation.",
        "Requires SciPy.",
    ]
    _FALSE_POSITIVES = [
        "Highly repetitive textures (fabric, screen patterns) may produce "
        "periodic FFT peaks without geometric transformation.",
    ]
    _FALSE_NEGATIVES = [
        "Heavy JPEG re-compression after resampling can mask the FFT signal.",
        "AI super-resolution may not produce traditional resampling artefacts.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type == "image" and np is not None and _SCIPY_OK)

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        if not _SCIPY_OK:
            return {
                "status": "unavailable", "summary": "SciPy not installed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        gray     = np.array(img.convert("L"), dtype=np.float64)
        d2       = ndimage.laplace(gray)
        spectrum = np.abs(sp_fft.fftshift(sp_fft.fft2(d2)))
        h, w     = spectrum.shape
        cy, cx   = h // 2, w // 2
        r        = max(2, min(h, w) // 100)
        spectrum[cy - r:cy + r, cx - r:cx + r] = 0
        flat      = spectrum.flatten()
        threshold = flat.mean() + 6 * flat.std()
        peaks     = int(np.sum(flat > threshold))
        ratio     = peaks / flat.size
        exceeds   = ratio > 0.0008

        supports: List[str] = []
        if exceeds:
            supports.append(
                f"FFT peak ratio {ratio:.6f} > 0.0008 — consistent with geometric "
                "transformation (scaling, rotation, or warping)."
            )
            return {
                "status":  "ok",
                "summary": f"Resampling: peak ratio={ratio:.7f} > 0.0008.",
                "raw_measurements": {
                    "periodic_peak_count": peaks, "peak_ratio": ratio,
                    "threshold": 0.0008, "ratio_exceeds_threshold": True,
                },
                "evidence": {
                    "periodic_peak_count": peaks, "peak_ratio": ratio,
                    "detection_threshold": 0.0008,
                    "method": "Popescu–Farid (2005) second-derivative FFT peak detection",
                },
                "supports":    supports,
                "contradicts": ["Absence of geometric post-processing transformations."],
            }
        else:
            supports.append(
                f"FFT peak ratio {ratio:.7f} < 0.0008 — no detectable periodic "
                "FFT peaks consistent with geometric resampling."
            )
            return {
                "status":  "ok",
                "summary": f"Resampling: peak ratio={ratio:.7f} — below 0.0008 threshold.",
                "raw_measurements": {
                    "periodic_peak_count": peaks, "peak_ratio": ratio,
                    "threshold": 0.0008, "ratio_exceeds_threshold": False,
                },
                "evidence": {
                    "periodic_peak_count": peaks, "peak_ratio": ratio,
                    "detection_threshold": 0.0008,
                    "method": "Popescu–Farid (2005) second-derivative FFT peak detection",
                },
                "supports":    supports,
                "contradicts": [],
            }


class CompressionHistoryExtractor(BaseExtractor):
    """AC(1,1) DCT coefficient histogram periodicity — Double Quantisation effect."""

    name        = "compression_history"
    version     = "10.0"
    category    = CATEGORY_EDITING
    RELIABILITY = RELIABILITY_MEDIUM

    _LIMITATIONS = [
        "Only AC(1,1) coefficient analysed (Farid's simplified DQ method).",
        "Cannot determine original or re-save quality values.",
        "Requires SciPy.",
    ]
    _FALSE_POSITIVES = [
        "Non-standard quantisation tables may produce spurious periodicity.",
    ]
    _FALSE_NEGATIVES = [
        "Re-encoding at the same quality produces no detectable DQ effect.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type == "image"
                and context.mime_type in ("image/jpeg", "image/jpg")
                and cv2 is not None and np is not None)

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        if not _SCIPY_OK:
            return {
                "status": "unavailable", "summary": "SciPy not installed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        gray = np.array(img.convert("L"), dtype=np.float32)
        h, w = gray.shape
        h8, w8 = h - h % 8, w - w % 8
        gray   = gray[:h8, :w8]
        coeffs = []
        for by in range(0, h8, 8):
            for bx in range(0, w8, 8):
                block = gray[by:by + 8, bx:bx + 8] - 128.0
                coeffs.append(cv2.dct(block)[1, 1])
        if not coeffs:
            return {
                "status": "unavailable", "summary": "No 8×8 blocks extracted.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        ca     = np.round(np.array(coeffs)).astype(int)
        hc     = Counter(ca.tolist())
        vals   = [hc[k] for k in sorted(hc.keys())]
        ps     = self._periodicity_score(vals)
        exceeds = ps > 0.35

        supports: List[str] = []
        if exceeds:
            supports.append(
                f"DCT periodicity score {ps:.4f} > 0.35 — consistent with the "
                "Double Quantisation effect from re-saving at a different JPEG quality."
            )
        else:
            supports.append(
                f"DCT periodicity score {ps:.4f} < 0.35 — consistent with single "
                "JPEG encoding without detectable re-compression."
            )
        return {
            "status":  "ok",
            "summary": f"Compression history: periodicity={ps:.5f}, threshold=0.35.",
            "raw_measurements": {
                "blocks_analyzed": len(coeffs), "histogram_bins": len(hc),
                "periodicity_score": ps, "threshold": 0.35, "score_above_threshold": exceeds,
            },
            "evidence": {
                "blocks_analyzed": len(coeffs), "histogram_bins": len(hc),
                "periodicity_score": ps, "periodicity_threshold": 0.35,
                "score_above_threshold": exceeds,
                "method": "AC(1,1) DCT histogram periodicity (DQ effect)",
            },
            "supports":    supports,
            "contradicts": [],
        }

    @staticmethod
    def _periodicity_score(values: List[int]) -> float:
        if len(values) < 16 or not _SCIPY_OK:
            return 0.0
        arr      = np.array(values, dtype=np.float64) - np.mean(values)
        spectrum = np.abs(sp_fft.rfft(arr))
        if len(spectrum) < 4:
            return 0.0
        spectrum[0] = 0
        return float(spectrum.max() / (spectrum.sum() + 1e-9))


class JPEGGhostExtractor(BaseExtractor):
    """JPEG Ghost (Farid 2009): block-level minimum recompression error quality map."""

    name           = "jpeg_ghost"
    version        = "10.0"
    category       = CATEGORY_EDITING
    RELIABILITY    = RELIABILITY_MEDIUM
    QUALITY_LEVELS = (50, 65, 75, 85, 95)
    BLOCK_SIZE     = 32

    _LIMITATIONS = [
        "Only five quality levels tested; original quality may fall between them.",
        "Block size 32 px limits ghost map resolution.",
    ]
    _FALSE_POSITIVES = [
        "Documents with regions photographed at very different qualities show "
        "ghost inconsistency without manipulation.",
    ]
    _FALSE_NEGATIVES = [
        "Copy-paste from the same JPEG quality as the background is not detected.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type == "image" and Image is not None and np is not None)

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        rgb      = img.convert("RGB")
        gray_arr = np.array(rgb.convert("L"), dtype=np.float64)
        h, w     = gray_arr.shape
        block    = self.BLOCK_SIZE
        if h < block * 4 or w < block * 4:
            return {
                "status": "unavailable", "summary": "Image too small (need ≥128×128).",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        diff_maps: Dict[int, np.ndarray] = {}
        for q in self.QUALITY_LEVELS:
            buf = io.BytesIO()
            rgb.save(buf, "JPEG", quality=q)
            buf.seek(0)
            diff_maps[q] = np.abs(gray_arr - np.array(Image.open(buf).convert("L"), dtype=np.float64))

        block_ghosts = [
            min({q: diff_maps[q][by:by + block, bx:bx + block].mean() for q in self.QUALITY_LEVELS},
                key=lambda k: diff_maps[k][by:by + block, bx:bx + block].mean())
            for by in range(0, h - block, block)
            for bx in range(0, w - block, block)
        ]
        gc       = Counter(block_ghosts)
        dom_q    = gc.most_common(1)[0][0]
        total    = len(block_ghosts)
        incon    = sum(1 for g in block_ghosts if g != dom_q)
        ir       = incon / total
        gstd     = float(np.std(block_ghosts))
        mixed    = ir > 0.12 and gstd > 8.0

        supports: List[str] = []
        if mixed:
            supports.append(
                f"Ghost inconsistency ratio {ir:.3f} > 0.12 and std {gstd:.1f} > 8.0 — "
                "consistent with regions originating from a different JPEG compression history."
            )
        else:
            supports.append(
                f"Ghost map spatially consistent (ratio {ir:.4f}, std {gstd:.2f}) — "
                "consistent with a uniform JPEG compression history."
            )
        return {
            "status":  "ok",
            "summary": f"JPEG Ghost: dominant Q={dom_q}, inconsistency={ir:.4f}, std={gstd:.2f}.",
            "raw_measurements": {
                "blocks_analyzed": total, "dominant_ghost_quality": int(dom_q),
                "inconsistent_blocks": incon, "inconsistency_ratio": ir,
                "ghost_std": gstd, "ir_above_0.12_and_std_above_8": mixed,
            },
            "evidence": {
                "qualities_tested": list(self.QUALITY_LEVELS),
                "blocks_analyzed": total, "dominant_ghost_quality": int(dom_q),
                "inconsistent_blocks": incon, "inconsistency_ratio": ir,
                "ghost_std": gstd, "spatial_inconsistency": mixed,
                "ghost_distribution": {int(k): v for k, v in gc.items()},
                "method": "Farid (2009) JPEG Ghost",
                "thresholds": {"inconsistency_ratio": 0.12, "ghost_quality_std": 8.0},
            },
            "supports":    supports,
            "contradicts": (
                ["Uniform single-source JPEG compression history."] if mixed else []
            ),
        }


class NoiseInconsistencyExtractor(BaseExtractor):
    """Block-wise Laplacian-variance MAD outlier detection (6× MAD threshold)."""

    name        = "noise_inconsistency"
    version     = "10.0"
    category    = CATEGORY_EDITING
    RELIABILITY = RELIABILITY_MEDIUM

    _LIMITATIONS = [
        "Block size 32 px means very small manipulation regions may not produce "
        "enough outlier blocks.",
    ]
    _FALSE_POSITIVES = [
        "Images with extreme natural variance (sharp edges next to smooth sky) "
        "produce noise-variance outliers without manipulation.",
    ]
    _FALSE_NEGATIVES = [
        "Compositing that matches noise levels across regions.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type == "image" and np is not None and cv2 is not None)

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        gray  = np.array(img.convert("L"), dtype=np.float32)
        h, w  = gray.shape
        block = 32
        variances = [
            float(cv2.Laplacian(gray[by:by + block, bx:bx + block], cv2.CV_32F).var())
            for by in range(0, h - block, block)
            for bx in range(0, w - block, block)
        ]
        if not variances:
            return {
                "status": "unavailable", "summary": "Image too small.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        arr      = np.array(variances)
        median   = float(np.median(arr))
        mad      = float(np.median(np.abs(arr - median))) + 1e-9
        outliers = int(np.sum(np.abs(arr - median) > 6 * mad))
        ratio    = outliers / len(variances)
        exceeds  = ratio > 0.03

        supports: List[str] = []
        if exceeds:
            supports.append(
                f"Noise outlier ratio {ratio:.3f} > 0.03 ({outliers} blocks deviate "
                "> 6× MAD) — consistent with regions having different noise characteristics "
                "(possible splicing, inpainting, or compositing)."
            )
        else:
            supports.append(
                f"Noise variance spatially consistent (outlier ratio {ratio:.4f}) — "
                "consistent with a uniform capture or synthesis pipeline."
            )
        return {
            "status":  "ok",
            "summary": f"Noise inconsistency: {outliers} outlier blocks ({ratio:.3%}).",
            "raw_measurements": {
                "blocks_analyzed": len(variances), "median_variance": median, "mad": mad,
                "outlier_count": outliers, "outlier_ratio": ratio, "ratio_above_0.03": exceeds,
            },
            "evidence": {
                "blocks_analyzed": len(variances), "median_block_variance": median,
                "mad": mad, "outlier_block_count": outliers, "outlier_ratio": ratio,
                "threshold": 0.03, "ratio_exceeds_threshold": exceeds,
                "method": "Block Laplacian-variance MAD outlier detection (6× MAD)",
            },
            "supports":    supports,
            "contradicts": (
                ["Uniform noise texture throughout the image."] if exceeds else []
            ),
        }


# ═════════════════════════════════════════════════════════════════════════════
# STEGANOGRAPHY
# ═════════════════════════════════════════════════════════════════════════════

class SteganographyExtractor(BaseExtractor):
    """LSB chi-square uniformity test and hidden ZIP signature detection."""

    name        = "steganography"
    version     = "10.0"
    category    = CATEGORY_STEGANOGRAPHY
    RELIABILITY = RELIABILITY_LOW

    _LIMITATIONS = [
        "Chi-square detects uniformity only; cannot identify the steganographic "
        "tool or payload content.",
        "Only 20,000-pixel sample analysed.",
    ]
    _FALSE_POSITIVES = [
        "Solid-colour images and gradients produce highly uniform LSBs.",
    ]
    _FALSE_NEGATIVES = [
        "Adaptive or palette-based steganography is not detected.",
        "Non-LSB bit-plane embedding is not analysed.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return context.file_type == "image"

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        if np is not None:
            pixels   = np.array(img.convert("RGB")).reshape(-1, 3)
            lsb_bits = (pixels[:STEGO_SAMPLE_PIXELS] & 1).flatten().tolist()
        else:
            data     = list(img.convert("RGB").getdata())[:STEGO_SAMPLE_PIXELS]
            lsb_bits = [c & 1 for r, g, b in data for c in (r, g, b)]

        chi2       = chi_square_bit_test(lsb_bits)
        ones_ratio = sum(lsb_bits) / len(lsb_bits) if lsb_bits else 0.5
        lsb_susp   = len(lsb_bits) > 5_000 and chi2 < 0.5
        hidden_zip = detect_zip_header(context.raw_data)

        supports: List[str] = []
        if lsb_susp:
            supports.append(
                f"LSB chi-square {chi2:.4f} < 0.5 with {len(lsb_bits):,} bits — "
                "near-uniform LSB distribution consistent with possible LSB steganographic embedding."
            )
        else:
            supports.append(
                f"LSB chi-square {chi2:.4f} does not strongly indicate LSB uniformity "
                "beyond natural image noise."
            )
        if hidden_zip:
            supports.append(
                "ZIP signature in raw bytes — may indicate a polyglot file or "
                "hidden archive appended to the image data."
            )
        return {
            "status":  "ok",
            "summary": f"LSB: {len(lsb_bits):,} bits, chi2={chi2:.4f}, zip={hidden_zip}.",
            "raw_measurements": {
                "lsb_bits_sampled": len(lsb_bits), "lsb_ones_ratio": ones_ratio,
                "lsb_chi_square": chi2, "chi2_below_0.5": lsb_susp, "hidden_zip": hidden_zip,
            },
            "evidence": {
                "lsb_bits_sampled": len(lsb_bits), "lsb_ones_ratio": ones_ratio,
                "lsb_chi_square": chi2, "chi_square_threshold": 0.5,
                "chi2_below_threshold": lsb_susp, "hidden_zip_signature": hidden_zip,
            },
            "supports":    supports,
            "contradicts": [],
        }


class AdvancedSteganalysisExtractor(BaseExtractor):
    """Simplified RS (Regular/Singular) steganalysis — LSB asymmetry scoring."""

    name        = "advanced_steganalysis"
    version     = "10.0"
    category    = CATEGORY_STEGANOGRAPHY
    RELIABILITY = RELIABILITY_LOW

    _LIMITATIONS = [
        "Simplified RS implementation; not the full Fridrich et al. method.",
        "Cannot estimate payload size or identify steganographic tool.",
    ]
    _FALSE_POSITIVES = [
        "Very noisy or highly textured images may exceed the asymmetry threshold.",
    ]
    _FALSE_NEGATIVES = [
        "Adaptive steganography preserving statistical properties may evade RS.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return context.file_type == "image" and np is not None

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        gray = np.array(img.convert("L"), dtype=np.int16)
        h, w = gray.shape
        h4, w4 = h - h % 4, w - w % 4
        gray   = gray[:h4, :w4]
        groups = (gray.reshape(h4 // 4, 4, w4 // 4, 4)
                  .transpose(0, 2, 1, 3).reshape(-1, 4, 4))
        mask   = np.array([[1,0,1,0],[0,1,0,1],[1,0,1,0],[0,1,0,1]])

        def disc(g: np.ndarray) -> int:
            return int(np.sum(np.abs(np.diff(g.flatten()))))

        r, s, rn, sn = 0, 0, 0, 0
        for g in groups:
            f  = disc(g); ff = disc(g ^ 1)
            if ff > f: r += 1
            elif ff < f: s += 1
            ng = g.copy(); ng[mask == 1] ^= 1
            fn = disc(ng)
            if fn > f: rn += 1
            elif fn < f: sn += 1

        total    = max(len(groups), 1)
        rs       = (r - s) / total
        rsn      = (rn - sn) / total
        asym     = abs(rs - rsn)
        exceeds  = asym > 0.03

        supports: List[str] = []
        if exceeds:
            supports.append(
                f"RS asymmetry {asym:.4f} > 0.03 — consistent with a statistical "
                "deviation produced by LSB steganographic embedding."
            )
        else:
            supports.append(
                f"RS asymmetry {asym:.4f} < 0.03 — no significant asymmetry "
                "consistent with LSB embedding detected by this method."
            )
        return {
            "status":  "ok",
            "summary": f"RS steganalysis: asymmetry={asym:.5f}, threshold=0.03.",
            "raw_measurements": {
                "groups_analyzed": int(total), "rm_minus_sm": float(rs),
                "rm_minus_sm_negative": float(rsn), "rs_asymmetry": float(asym),
                "asymmetry_above_0.03": exceeds,
            },
            "evidence": {
                "groups_analyzed": int(total), "rm_minus_sm": float(rs),
                "rm_minus_sm_negative": float(rsn), "rs_asymmetry": float(asym),
                "asymmetry_threshold": 0.03, "asymmetry_exceeds_threshold": exceeds,
                "method": "Simplified RS (Regular/Singular) analysis",
            },
            "supports":    supports,
            "contradicts": (
                ["An unmodified image with natural LSB distribution."] if exceeds else []
            ),
        }


# ═════════════════════════════════════════════════════════════════════════════
# AI STATISTICAL INDICATORS
# ═════════════════════════════════════════════════════════════════════════════

class NoiseExtractor(BaseExtractor):
    """Global Laplacian variance — image sharpness/noise proxy."""

    name        = "noise"
    version     = "10.0"
    category    = CATEGORY_AI_STATISTICAL
    RELIABILITY = RELIABILITY_MEDIUM

    _LIMITATIONS = [
        "Single global metric; cannot localise anomalies.",
        "Highly content-dependent — smooth vs. textured scenes differ greatly.",
    ]
    _FALSE_POSITIVES: List[str] = []
    _FALSE_NEGATIVES: List[str] = []

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type == "image" and cv2 is not None and np is not None)

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        var = float(cv2.Laplacian(np.array(img.convert("L")), cv2.CV_64F).var())
        supports: List[str] = []
        if var < 10:
            supports.append(
                f"Very low Laplacian variance ({var:.2f}) — consistent with "
                "an unusually smooth image (heavy denoising, AI generation, or intentional blur)."
            )
        elif var > 2000:
            supports.append(
                f"Very high Laplacian variance ({var:.2f}) — consistent with "
                "a highly textured image, motion blur, or compression artefacts."
            )
        else:
            supports.append(f"Laplacian variance {var:.2f} is within a typical photographic range.")

        return {
            "status":  "ok",
            "summary": f"Laplacian variance={var:.4f}.",
            "raw_measurements": {"laplacian_variance": var},
            "evidence": {"laplacian_variance": var, "method": "Laplacian variance (Vollath 1988)"},
            "supports":    supports,
            "contradicts": [],
        }


class WaveletConsistencyExtractor(BaseExtractor):
    """
    4-level Haar wavelet: HH subband kurtosis, inter-level energy ratios,
    LH/HL anisotropy. Reports raw measurements only — no AI verdict.
    """

    name        = "wavelet_consistency"
    version     = "10.0"
    category    = CATEGORY_AI_STATISTICAL
    RELIABILITY = RELIABILITY_LOW

    _LIMITATIONS = [
        "Thresholds are heuristic; no validated training dataset underpins them.",
        "Modern diffusion models (2025+) may produce kurtosis within natural ranges.",
    ]
    _FALSE_POSITIVES = [
        "HDR tone-mapping, heavy JPEG compression, and AI denoising alter "
        "wavelet statistics without full AI synthesis.",
    ]
    _FALSE_NEGATIVES = [
        "Diffusion models post-processed with natural noise injection may pass.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return context.file_type == "image" and np is not None

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        gray    = np.array(img.convert("L"), dtype=np.float64)
        subbands: List[Dict[str, Any]] = []
        current = gray.copy()
        for level in range(1, 5):
            h, w = current.shape
            if h < 16 or w < 16:
                break
            LL, LH, HL, HH = self._haar_1level(current)
            subbands.append({
                "level":       level,
                "kurtosis_HH": self._kurtosis(HH.flatten()),
                "kurtosis_LH": self._kurtosis(LH.flatten()),
                "energy_HH":   float(np.mean(HH ** 2)),
                "energy_LH":   float(np.mean(LH ** 2)),
                "energy_HL":   float(np.mean(HL ** 2)),
                "lh_hl_ratio": float(np.mean(LH ** 2) / (np.mean(HL ** 2) + 1e-12)),
            })
            current = LL
        if not subbands:
            return {
                "status": "unavailable", "summary": "Image too small for wavelet analysis.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        l1k   = subbands[0]["kurtosis_HH"]
        ratios = [subbands[i]["energy_HH"] / (subbands[i+1]["energy_HH"] + 1e-12)
                  for i in range(len(subbands) - 1)]
        rm     = float(np.mean(ratios)) if ratios else 0.0
        ani    = abs(float(np.mean([s["lh_hl_ratio"] for s in subbands])) - 1.0)
        low_k  = l1k < 3.5
        low_r  = rm < 2.5 and len(ratios) >= 2
        high_a = ani > 0.40

        notes: List[str] = []
        if low_k:
            notes.append(f"L1 HH kurtosis {l1k:.3f} < 3.5 (more Gaussian than expected for camera subbands).")
        if low_r:
            notes.append(f"Energy ratio {rm:.3f} < 2.5 (shallow inter-level falloff).")
        if high_a:
            notes.append(f"LH/HL anisotropy {ani:.4f} > 0.40 (directional bias).")
        supports = notes if notes else [
            f"Wavelet statistics within natural ranges: kurtosis={l1k:.3f}, ratio={rm:.3f}, anisotropy={ani:.4f}."
        ]

        raw: Dict[str, Any] = {
            "levels_computed": len(subbands), "l1_hh_kurtosis": l1k,
            "energy_ratio_mean": rm, "lh_hl_anisotropy": ani,
            "kurtosis_below_3.5": low_k, "ratio_below_2.5": low_r, "anisotropy_above_0.40": high_a,
        }
        for s in subbands:
            raw[f"level_{s['level']}_kurtosis_HH"] = s["kurtosis_HH"]
            raw[f"level_{s['level']}_energy_HH"]   = s["energy_HH"]
            raw[f"level_{s['level']}_lh_hl_ratio"] = s["lh_hl_ratio"]
        return {
            "status":  "ok",
            "summary": f"Wavelet: L1 HH kurt={l1k:.3f}, ratio_mean={rm:.3f}, aniso={ani:.4f}.",
            "raw_measurements": raw,
            "evidence": {
                "subband_stats": subbands, "l1_hh_kurtosis": l1k,
                "energy_ratios": [float(r) for r in ratios],
                "energy_ratio_mean": rm, "lh_hl_anisotropy": ani,
                "thresholds": {"kurtosis": 3.5, "energy_ratio": 2.5, "anisotropy": 0.40},
            },
            "supports":    supports,
            "contradicts": [],
        }

    @staticmethod
    def _haar_1level(img: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        h, w   = img.shape
        h2, w2 = h - h % 2, w - w % 2
        img    = img[:h2, :w2]
        L  = (img[:, 0::2] + img[:, 1::2]) * 0.5
        H  = (img[:, 0::2] - img[:, 1::2]) * 0.5
        LL = (L[0::2, :] + L[1::2, :]) * 0.5
        LH = (L[0::2, :] - L[1::2, :]) * 0.5
        HL = (H[0::2, :] + H[1::2, :]) * 0.5
        HH = (H[0::2, :] - H[1::2, :]) * 0.5
        return LL, LH, HL, HH

    @staticmethod
    def _kurtosis(data: np.ndarray) -> float:
        if data.size < 4:
            return 3.0
        mu = data.mean(); sigma = data.std() + 1e-9
        return float(np.mean(((data - mu) / sigma) ** 4))


class PowerSpectrumExtractor(BaseExtractor):
    """
    Radially-averaged PSD: spectral beta (1/f^beta slope), periodic HF peaks,
    azimuthal CV. Reports raw measurements only — no AI verdict.
    """

    name        = "power_spectrum"
    version     = "10.0"
    category    = CATEGORY_AI_STATISTICAL
    RELIABILITY = RELIABILITY_LOW

    _LIMITATIONS = [
        "Spectral beta fit assumes power-law behaviour; cartoons/illustrations deviate.",
        "Requires SciPy.",
    ]
    _FALSE_POSITIVES = [
        "Strong directional content (horizon lines, architecture) produces "
        "azimuthal non-uniformity without AI synthesis.",
    ]
    _FALSE_NEGATIVES = [
        "Diffusion models fine-tuned on natural images may produce natural PSD.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type == "image" and np is not None and _SCIPY_OK)

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        if not _SCIPY_OK:
            return {
                "status": "unavailable", "summary": "SciPy not installed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        gray = np.array(img.convert("L"), dtype=np.float64)
        h, w = gray.shape
        if h < 64 or w < 64:
            return {
                "status": "unavailable", "summary": "Image too small (need ≥64×64).",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        win  = np.outer(np.hanning(h), np.hanning(w))
        gray = (gray - gray.mean()) * win
        F    = sp_fft.fftshift(sp_fft.fft2(gray))
        psd  = np.abs(F) ** 2
        cy, cx = h // 2, w // 2
        profile, freqs = self._radial_avg(psd, cy, cx)
        if len(freqs) < 16:
            return {
                "status": "unavailable", "summary": "Insufficient frequency resolution.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        n = len(freqs)
        lo, hi = n // 8, 3 * n // 4
        beta = float(-np.polyfit(np.log(freqs[lo:hi]),
                                 np.log(np.array(profile[lo:hi]) + 1e-9), 1)[0])
        hf = np.array(profile[3 * n // 4:])
        peaks = int(np.sum(hf > hf.mean() + 3.0 * (hf.std() + 1e-9))) if hf.size > 4 else 0
        az_cv = self._azimuthal_cv(psd, cy, cx, min(cy, cx) // 4)

        beta_out = beta < 1.4 or beta > 4.2
        hi_peaks = peaks > 5
        hi_az    = az_cv > 0.60

        notes: List[str] = []
        if beta_out:
            notes.append(f"Spectral beta {beta:.3f} outside expected range [1.4, 4.2].")
        if hi_peaks:
            notes.append(f"{peaks} periodic HF spectral peaks (consistent with tiled operations).")
        if hi_az:
            notes.append(f"Azimuthal CV {az_cv:.3f} > 0.60 — angular non-uniformity in PSD.")
        supports = notes if notes else [
            f"PSD within natural 1/f² range: beta={beta:.3f}, peaks={peaks}, az_cv={az_cv:.3f}."
        ]
        return {
            "status":  "ok",
            "summary": f"PSD: beta={beta:.4f}, peaks={peaks}, az_cv={az_cv:.4f}.",
            "raw_measurements": {
                "spectral_beta": beta, "periodic_hf_peaks": peaks, "azimuthal_cv": az_cv,
                "beta_outside_1.4_4.2": beta_out, "peaks_above_5": hi_peaks, "az_cv_above_0.60": hi_az,
            },
            "evidence": {
                "spectral_beta": beta, "beta_expected_range": [1.4, 4.2],
                "beta_outside_range": beta_out, "periodic_hf_peaks": peaks,
                "peaks_threshold": 5, "azimuthal_cv": az_cv, "az_cv_threshold": 0.60,
            },
            "supports":    supports,
            "contradicts": [],
        }

    @staticmethod
    def _radial_avg(psd: np.ndarray, cy: int, cx: int) -> Tuple[List[float], List[int]]:
        h, w  = psd.shape
        max_r = min(cy, cx, h - cy, w - cx)
        y, x  = np.ogrid[:h, :w]
        r_map = np.sqrt((y - cy)**2 + (x - cx)**2).astype(int)
        prof, fq = [], []
        for r in range(1, max_r):
            m = (r_map == r)
            if m.sum() > 0:
                prof.append(float(psd[m].mean())); fq.append(r)
        return prof, fq

    @staticmethod
    def _azimuthal_cv(psd: np.ndarray, cy: int, cx: int, ring_r: int) -> float:
        y, x  = np.ogrid[:psd.shape[0], :psd.shape[1]]
        r_map = np.sqrt((y - cy)**2 + (x - cx)**2)
        ring  = psd[(r_map >= ring_r) & (r_map < ring_r + 4)]
        return float(ring.std() / (ring.mean() + 1e-9)) if ring.size >= 8 else 0.0


class LocalPatchStatisticsExtractor(BaseExtractor):
    """
    4×4 grid brightness/texture CV and HF kurtosis. Low CV may indicate
    unusually uniform content. Reports raw measurements only — no AI verdict.
    """

    name        = "local_patch_statistics"
    version     = "10.0"
    category    = CATEGORY_AI_STATISTICAL
    RELIABILITY = RELIABILITY_LOW
    GRID        = 4

    _LIMITATIONS = [
        "Coarse 4×4 grid (16 patches); large images with localised uniform "
        "regions may score deceptively.",
        "Brightness and texture thresholds are empirical, not trained.",
    ]
    _FALSE_POSITIVES = [
        "Minimalist art and flat-design graphics produce low CV without AI synthesis.",
    ]
    _FALSE_NEGATIVES = [
        "AI images with deliberate compositional variety may show high brightness CV.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type == "image" and np is not None and cv2 is not None)

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        gray = np.array(img.convert("L"), dtype=np.float64)
        h, w = gray.shape
        g    = self.GRID
        ph, pw = h // g, w // g
        if ph < 16 or pw < 16:
            return {
                "status": "unavailable", "summary": "Image too small.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        patches, means, hf_vars = [], [], []
        for row in range(g):
            for col in range(g):
                patch = gray[row * ph:(row + 1) * ph, col * pw:(col + 1) * pw]
                m = float(patch.mean()); s = float(patch.std())
                f = patch.flatten(); mu = f.mean(); sig = f.std() + 1e-9
                sk = float(np.mean(((f - mu) / sig) ** 3))
                ku = float(np.mean(((f - mu) / sig) ** 4))
                hfv = float(cv2.Laplacian(patch, cv2.CV_64F).var())
                patches.append({"row": row, "col": col, "mean": m, "std": s,
                                 "skewness": sk, "kurtosis": ku, "hf_variance": hfv})
                means.append(m); hf_vars.append(hfv)

        ma  = np.array(means); ha = np.array(hf_vars)
        bcv = float(ma.std() / (ma.mean() + 1e-9))
        tcv = float(ha.std() / (ha.mean() + 1e-9))
        hfk = float(np.mean(((ha - ha.mean()) / (ha.std() + 1e-9)) ** 4))
        low_b = bcv < 0.25; low_t = tcv < 0.40; low_h = hfk < 3.0

        notes: List[str] = []
        if low_b: notes.append(f"Brightness CV {bcv:.4f} < 0.25 — unusually uniform brightness.")
        if low_t: notes.append(f"Texture CV {tcv:.4f} < 0.40 — unusually uniform HF content.")
        if low_h: notes.append(f"HF kurtosis {hfk:.4f} < 3.0 — texture evenly distributed.")
        supports = notes if notes else [
            f"Natural inter-patch variability: brightness_CV={bcv:.4f}, texture_CV={tcv:.4f}."
        ]
        return {
            "status":  "ok",
            "summary": f"Patches: brightness_CV={bcv:.4f}, texture_CV={tcv:.4f}, HF_kurt={hfk:.4f}.",
            "raw_measurements": {
                "patches_analyzed": g * g, "brightness_cv": bcv, "texture_cv": tcv,
                "hf_variance_kurtosis": hfk, "brightness_cv_below_0.25": low_b,
                "texture_cv_below_0.40": low_t, "hf_kurtosis_below_3.0": low_h,
            },
            "evidence": {
                "grid_size": f"{g}×{g}", "patches_analyzed": g * g,
                "patch_stats": patches, "brightness_cv": bcv, "texture_cv": tcv,
                "hf_variance_kurtosis": hfk,
                "thresholds": {"brightness_cv": 0.25, "texture_cv": 0.40, "hf_kurtosis": 3.0},
            },
            "supports":    supports,
            "contradicts": [],
        }


class GradientCoherenceExtractor(BaseExtractor):
    """
    Sobel gradient orientation entropy and dominant-orientation concentration.
    Reports raw measurements only — no AI verdict.
    """

    name        = "gradient_coherence"
    version     = "10.0"
    category    = CATEGORY_AI_STATISTICAL
    RELIABILITY = RELIABILITY_LOW

    _LIMITATIONS = [
        "Highly texture-rich natural scenes (forest, water) may legitimately show "
        "high entropy.",
    ]
    _FALSE_POSITIVES = [
        "Abstract art and HDR tone-mapping can homogenise gradient fields.",
    ]
    _FALSE_NEGATIVES = [
        "AI-generated architectural scenes with strong dominant edges may pass.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type == "image" and np is not None and cv2 is not None)

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        gray   = np.array(img.convert("L"), dtype=np.float32)
        gx     = cv2.Sobel(gray, cv2.CV_32F, 1, 0, ksize=3)
        gy     = cv2.Sobel(gray, cv2.CV_32F, 0, 1, ksize=3)
        mag    = np.sqrt(gx**2 + gy**2)
        strong = mag > np.percentile(mag, 80)
        if strong.sum() < 100:
            return {
                "status": "unavailable", "summary": "Insufficient strong-gradient pixels.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        ori_dir  = np.mod(np.arctan2(gy[strong], gx[strong]), np.pi)
        hist, _  = np.histogram(ori_dir, bins=36, range=(0, np.pi), density=True)
        hist     = hist / (hist.sum() + 1e-9)
        ent      = float(-np.sum(hist * np.log2(hist + 1e-12)))
        norm_e   = ent / math.log2(36)
        top3     = float(np.sort(hist)[::-1][:3].sum())
        h, w     = gray.shape; bsz = 32
        bv       = [float(mag[by:by+bsz, bx:bx+bsz].mean())
                    for by in range(0, h-bsz, bsz) for bx in range(0, w-bsz, bsz)]
        bva      = np.array(bv) if bv else np.array([0.0])
        block_cv = float(bva.std() / (bva.mean() + 1e-9))
        hi_ent = norm_e > 0.82; lo_conc = top3 < 0.25

        notes: List[str] = []
        if hi_ent and lo_conc:
            notes.append(
                f"Entropy {norm_e:.4f} > 0.82 and top-3 power {top3:.4f} < 0.25 — "
                "isotropic gradient field with no dominant directions."
            )
        elif hi_ent:
            notes.append(f"Entropy {norm_e:.4f} > 0.82 — high gradient isotropy.")
        supports = notes if notes else [
            f"Entropy {norm_e:.4f} and top-3 power {top3:.4f} within natural range "
            "for scenes with structured edges."
        ]
        return {
            "status":  "ok",
            "summary": f"Gradient: entropy_norm={norm_e:.4f}, top3_power={top3:.4f}.",
            "raw_measurements": {
                "orientation_entropy_bits": ent, "orientation_entropy_norm": norm_e,
                "top3_orientation_power": top3, "gradient_block_cv": block_cv,
                "strong_pixels": int(strong.sum()),
                "entropy_above_0.82": hi_ent, "top3_below_0.25": lo_conc,
            },
            "evidence": {
                "orientation_entropy_bits": ent, "orientation_entropy_norm": norm_e,
                "top3_orientation_power": top3, "gradient_block_cv": block_cv,
                "strong_pixels_used": int(strong.sum()),
                "entropy_threshold": 0.82, "top3_power_threshold": 0.25,
            },
            "supports":    supports,
            "contradicts": [],
        }


class AIGeneratedImageExtractor(BaseExtractor):
    """
    Computes 8 heuristic signals associated with AI image generation research.
    Reports raw signal values and individual threshold comparisons.
    DOES NOT produce a verdict, confidence score, or weighted decision.
    """

    name        = "ai_generated_heuristics"
    version     = "10.0"
    category    = CATEGORY_AI_STATISTICAL
    RELIABILITY = RELIABILITY_LOW

    _LIMITATIONS = [
        "All signals are heuristic with no validated training corpus.",
        "Modern diffusion models (2025+) defeat several of these signals.",
        "This extractor produces NO AI generation verdict.",
    ]
    _FALSE_POSITIVES = [
        "Heavily post-processed camera images (HDR, computational photography, "
        "AI denoising) may trigger multiple signals.",
    ]
    _FALSE_NEGATIVES = [
        "State-of-the-art diffusion models may pass all eight tests.",
    ]

    SIGNAL_THRESHOLDS: ClassVar[Dict[str, Any]] = {
        "wavelet_kurtosis":      {"threshold": 3.5,       "direction": "below"},
        "power_spectrum_beta":   {"threshold": [1.4, 4.2],"direction": "outside"},
        "local_variance_cv":     {"threshold": 0.50,      "direction": "below"},
        "shot_noise_slope":      {"threshold": 0.15,      "direction": "below"},
        "gradient_uniformity":   {"threshold": 0.82,      "direction": "above"},
        "hf_autocorrelation":    {"threshold": 0.18,      "direction": "above"},
        "channel_hf_corr":       {"threshold": 0.75,      "direction": "above"},
        "saturation_entropy":    {"threshold": [0.55,0.95],"direction": "outside"},
    }

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type == "image" and np is not None and cv2 is not None)

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        gray = np.array(img.convert("L"), dtype=np.float64)
        rgb  = np.array(img.convert("RGB"), dtype=np.float64)

        signals = {
            "wavelet_kurtosis":    self._sig_wavelet_kurtosis(gray),
            "power_spectrum_beta": self._sig_power_spectrum(gray),
            "local_variance_cv":   self._sig_local_variance_cv(gray),
            "shot_noise_slope":    self._sig_shot_noise(gray),
            "gradient_uniformity": self._sig_gradient_uniformity(gray),
            "hf_autocorrelation":  self._sig_hf_autocorrelation(gray),
            "channel_hf_corr":     self._sig_channel_hf_corr(rgb),
            "saturation_entropy":  self._sig_saturation_entropy(img),
        }
        triggered = [n for n, s in signals.items() if s.get("threshold_exceeded")]
        raw = {n: s.get("value") for n, s in signals.items()}
        raw["signals_above_threshold"] = len(triggered)
        raw["signals_total"]           = len(signals)
        for n, s in signals.items():
            raw[f"{n}_threshold_exceeded"] = s.get("threshold_exceeded", False)

        supports = (
            [f"Signal '{n}': value={signals[n].get('value')}, "
             f"threshold={signals[n].get('threshold')} — {signals[n].get('description','')}"
             for n in triggered]
            if triggered else
            ["All eight statistical signals are within their respective thresholds."]
        )
        return {
            "status":  "ok",
            "summary": (
                f"AI signal heuristics: {len(triggered)}/{len(signals)} "
                "signals exceeded individual thresholds."
            ),
            "raw_measurements": raw,
            "evidence": {
                "signals": signals,
                "triggered_signal_names":   triggered,
                "signals_above_threshold":  len(triggered),
                "signals_total":            len(signals),
                "thresholds":               self.SIGNAL_THRESHOLDS,
                "important_note": (
                    "Raw signal measurements only. No weighted scoring or AI "
                    "generation verdict is produced by this extractor."
                ),
            },
            "supports":    supports,
            "contradicts": [],
        }

    # ── Signal implementations ────────────────────────────────────────────────

    def _sig_wavelet_kurtosis(self, gray: np.ndarray) -> Dict:
        try:
            h, w   = gray.shape
            h2, w2 = h - h%2, w - w%2
            g      = gray[:h2, :w2]
            HH     = ((g[:,0::2] - g[:,1::2]) * 0.5)
            HH     = (HH[0::2,:] - HH[1::2,:]) * 0.5
            flat   = HH.flatten()
            mu     = flat.mean(); sig = flat.std() + 1e-9
            kurt   = float(np.mean(((flat - mu) / sig) ** 4))
            return {"value": kurt, "threshold": 3.5, "threshold_exceeded": kurt < 3.5,
                    "description": f"L1 HH kurtosis {kurt:.3f} (natural >3.5 from sparse edge energy)"}
        except Exception as e:
            return {"value": None, "threshold": 3.5, "threshold_exceeded": False, "description": str(e)}

    def _sig_power_spectrum(self, gray: np.ndarray) -> Dict:
        if not _SCIPY_OK:
            return {"value": None, "threshold": [1.4,4.2], "threshold_exceeded": False,
                    "description": "SciPy unavailable"}
        try:
            h, w = gray.shape
            if h < 64 or w < 64:
                return {"value": None, "threshold": [1.4,4.2], "threshold_exceeded": False,
                        "description": "Image too small"}
            win = np.outer(np.hanning(h), np.hanning(w))
            g   = (gray - gray.mean()) * win
            F   = sp_fft.fftshift(sp_fft.fft2(g)); psd = np.abs(F)**2
            cy, cx = h//2, w//2
            y, x   = np.ogrid[:h, :w]
            r_map  = np.sqrt((y-cy)**2 + (x-cx)**2).astype(int)
            max_r  = min(cy, cx)
            prof   = [float(psd[r_map==r].mean()) for r in range(1, max_r) if (r_map==r).sum()>0]
            n      = len(prof); lo, hi = n//8, 3*n//4
            fs     = list(range(1, n+1))[lo:hi]; ps = prof[lo:hi]
            beta   = float(-np.polyfit(np.log(fs), np.log(np.array(ps)+1e-9), 1)[0])
            ex     = beta < 1.4 or beta > 4.2
            return {"value": beta, "threshold": [1.4,4.2], "threshold_exceeded": ex,
                    "description": f"Spectral beta {beta:.3f} (natural 1.4–4.2)"}
        except Exception as e:
            return {"value": None, "threshold": [1.4,4.2], "threshold_exceeded": False, "description": str(e)}

    def _sig_local_variance_cv(self, gray: np.ndarray) -> Dict:
        try:
            h, w = gray.shape; block = 32
            variances = [float(gray[by:by+block,bx:bx+block].var())
                         for by in range(0,h-block,block) for bx in range(0,w-block,block)]
            if len(variances) < 9:
                return {"value": None, "threshold": 0.50, "threshold_exceeded": False, "description": "Too few blocks"}
            arr = np.array(variances)
            cv_ = float(arr.std() / (arr.mean() + 1e-9))
            return {"value": cv_, "threshold": 0.50, "threshold_exceeded": cv_ < 0.50,
                    "description": f"Block-variance CV {cv_:.4f} (low = spatially uniform texture)"}
        except Exception as e:
            return {"value": None, "threshold": 0.50, "threshold_exceeded": False, "description": str(e)}

    def _sig_shot_noise(self, gray: np.ndarray) -> Dict:
        try:
            g_u8     = gray.astype(np.uint8)
            denoised = cv2.fastNlMeansDenoising(g_u8, h=6).astype(np.float64)
            residual = gray - denoised
            flat_g   = gray.flatten(); flat_r = residual.flatten()
            q_edges  = np.percentile(flat_g, [0,20,40,60,80,100])
            vars_q   = [float(flat_r[(flat_g>=q_edges[i])&(flat_g<q_edges[i+1])].var())
                        for i in range(5)
                        if ((flat_g>=q_edges[i])&(flat_g<q_edges[i+1])).sum() > 50]
            if len(vars_q) < 3:
                return {"value": None, "threshold": 0.15, "threshold_exceeded": False,
                        "description": "Insufficient brightness range"}
            x = np.arange(len(vars_q), dtype=np.float64); y = np.array(vars_q)
            sn = float(np.polyfit(x,y,1)[0] / (np.mean(y)+1e-9)) if y.std()>1e-9 else 0.0
            return {"value": sn, "threshold": 0.15, "threshold_exceeded": sn < 0.15,
                    "description": f"Brightness-noise slope ratio {sn:.4f} (camera noise increases with brightness)"}
        except Exception as e:
            return {"value": None, "threshold": 0.15, "threshold_exceeded": False, "description": str(e)}

    def _sig_gradient_uniformity(self, gray: np.ndarray) -> Dict:
        try:
            g32 = gray.astype(np.float32)
            gx  = cv2.Sobel(g32, cv2.CV_32F, 1, 0, ksize=3)
            gy  = cv2.Sobel(g32, cv2.CV_32F, 0, 1, ksize=3)
            mag = np.sqrt(gx**2 + gy**2)
            strong = mag > np.percentile(mag, 80)
            if strong.sum() < 100:
                return {"value": None, "threshold": 0.82, "threshold_exceeded": False,
                        "description": "Insufficient gradient pixels"}
            ori_dir = np.mod(np.arctan2(gy[strong], gx[strong]), np.pi)
            hist, _ = np.histogram(ori_dir, bins=36, range=(0, np.pi), density=True)
            hist    = hist / (hist.sum() + 1e-9)
            ent     = float(-np.sum(hist * np.log2(hist + 1e-12)))
            norm_e  = ent / math.log2(36)
            return {"value": norm_e, "threshold": 0.82, "threshold_exceeded": norm_e > 0.82,
                    "description": f"Gradient entropy {norm_e:.4f} (high = isotropic field)"}
        except Exception as e:
            return {"value": None, "threshold": 0.82, "threshold_exceeded": False, "description": str(e)}

    def _sig_hf_autocorrelation(self, gray: np.ndarray) -> Dict:
        try:
            blur = cv2.GaussianBlur(gray.astype(np.float32),(5,5),0).astype(np.float64)
            res  = gray - blur
            rh   = float(np.corrcoef(res[:-1,:].flatten(), res[1:,:].flatten())[0,1])
            rv   = float(np.corrcoef(res[:,:-1].flatten(), res[:,1:].flatten())[0,1])
            mac  = (abs(rh)+abs(rv))/2.0
            return {"value": mac, "threshold": 0.18, "threshold_exceeded": mac > 0.18,
                    "description": f"HF autocorrelation {mac:.4f} (high = correlated noise, consistent with upsampling)"}
        except Exception as e:
            return {"value": None, "threshold": 0.18, "threshold_exceeded": False, "description": str(e)}

    def _sig_channel_hf_corr(self, rgb: np.ndarray) -> Dict:
        try:
            hf_ch = []
            for c in range(3):
                ch   = rgb[:,:,c].astype(np.float64)
                blur = cv2.GaussianBlur(ch.astype(np.float32),(5,5),0).astype(np.float64)
                hf_ch.append((ch - blur).flatten())
            n   = min(20000, len(hf_ch[0]))
            idx = np.random.choice(len(hf_ch[0]), size=n, replace=False)
            rg  = float(np.corrcoef(hf_ch[0][idx], hf_ch[1][idx])[0,1])
            rb  = float(np.corrcoef(hf_ch[0][idx], hf_ch[2][idx])[0,1])
            mc  = (abs(rg)+abs(rb))/2.0
            return {"value": mc, "threshold": 0.75, "threshold_exceeded": mc > 0.75,
                    "description": f"Cross-channel HF correlation {mc:.4f} (high = jointly synthesised channels)"}
        except Exception as e:
            return {"value": None, "threshold": 0.75, "threshold_exceeded": False, "description": str(e)}

    def _sig_saturation_entropy(self, img) -> Dict:
        try:
            rgb_f = np.array(img.convert("RGB"), dtype=np.float64) / 255.0
            r,g,b = rgb_f[:,:,0], rgb_f[:,:,1], rgb_f[:,:,2]
            cmax  = np.maximum(np.maximum(r,g),b)
            delta = cmax - np.minimum(np.minimum(r,g),b)
            sat   = np.where(cmax > 1e-9, delta/cmax, 0.0)
            hist, _ = np.histogram(sat, bins=32, range=(0,1), density=True)
            hist    = hist / (hist.sum()+1e-9)
            ent     = float(-np.sum(hist * np.log2(hist+1e-12)))
            ne      = ent / math.log2(32)
            lo, hi  = 0.55, 0.95
            ex      = ne < lo or ne > hi
            return {"value": ne, "threshold": [lo,hi], "threshold_exceeded": ex,
                    "description": f"Saturation entropy {ne:.4f} (expected {lo}–{hi})"}
        except Exception as e:
            return {"value": None, "threshold": [0.55,0.95], "threshold_exceeded": False, "description": str(e)}


class AIManipulationExtractor(BaseExtractor):
    """
    Multi-signal block-level co-occurrence analysis (noise + CFA + edge + entropy).
    Reports suspect block counts and spatial cluster statistics.
    DOES NOT produce a verdict or confidence score.
    """

    name        = "ai_manipulation_heuristics"
    version     = "10.0"
    category    = CATEGORY_AI_STATISTICAL
    RELIABILITY = RELIABILITY_LOW

    _LIMITATIONS = [
        "Spatial clustering requires SciPy.",
        "MAD thresholds (4× / 3×) are heuristic.",
        "Block size 32 px limits detection resolution.",
        "This extractor produces NO AI manipulation verdict.",
    ]
    _FALSE_POSITIVES = [
        "Naturally heterogeneous images produce many multi-signal blocks.",
        "Text overlaid on uniform backgrounds creates co-occurring edge/entropy anomalies.",
    ]
    _FALSE_NEGATIVES = [
        "AI inpainting matching surrounding statistics may evade all four signals.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type == "image" and np is not None and cv2 is not None)

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "Image decode failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        gray = np.array(img.convert("L"), dtype=np.float32)
        rgb  = np.array(img.convert("RGB"), dtype=np.float64)
        h, w = gray.shape
        block = 32
        if h < block * 4 or w < block * 4:
            return {
                "status": "unavailable", "summary": "Image too small (need ≥128×128).",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        rows_g = list(range(0, h - block, block))
        cols_g = list(range(0, w - block, block))
        noise_vars, cfa_scores, edge_dens, entropies = [], [], [], []
        for by in rows_g:
            for bx in cols_g:
                gb  = gray[by:by+block, bx:bx+block]
                rb  = rgb[by:by+block, bx:bx+block, :]
                noise_vars.append(float(cv2.Laplacian(gb, cv2.CV_32F).var()))
                cfa_scores.append(CFAExtractor._cfa_score(rb))
                ed = cv2.Canny(gb.astype(np.uint8), 50, 150)
                edge_dens.append(float(ed.mean()) / 255.0)
                hb, _ = np.histogram(gb, bins=8, range=(0,255))
                hb    = hb / (hb.sum() + 1e-9)
                entropies.append(float(-np.sum(hb * np.log2(hb + 1e-12))))
        if not noise_vars:
            return {
                "status": "unavailable", "summary": "No blocks extracted.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        def mad_bounds(arr: np.ndarray, k: float = 4.0) -> Tuple[float, float]:
            med = np.median(arr); mad_ = np.median(np.abs(arr - med)) + 1e-9
            return med - k*mad_, med + k*mad_
        na, ca = np.array(noise_vars), np.array(cfa_scores)
        ea, ha = np.array(edge_dens), np.array(entropies)
        n_lo, n_hi = mad_bounds(na); c_lo, _ = mad_bounds(ca, 3.0)
        e_lo, e_hi = mad_bounds(ea); h_lo, h_hi = mad_bounds(ha)
        n_anom = (na < n_lo) | (na > n_hi)
        c_anom = ca < max(float(c_lo), 0.05)
        e_anom = (ea < e_lo) | (ea > e_hi)
        h_anom = (ha < h_lo) | (ha > h_hi)
        ct      = n_anom.astype(int) + c_anom.astype(int) + e_anom.astype(int) + h_anom.astype(int)
        suspect = ct >= 2
        sr      = float(suspect.sum() / len(suspect))
        lc, tc  = 0, 0
        nr, nc  = len(rows_g), len(cols_g)
        if nr * nc == len(suspect) and _SCIPY_OK:
            labeled, tc = ndimage.label(suspect.reshape(nr, nc))
            sizes       = [(labeled == i).sum() for i in range(1, tc + 1)]
            lc          = sum(1 for s in sizes if s >= 4)

        supports: List[str] = []
        if sr > 0.05:
            supports.append(
                f"{suspect.sum()} blocks ({sr:.2%}) show ≥2 co-occurring signal anomalies — "
                "consistent with spatially non-uniform content from different sources."
            )
        if lc >= 2:
            supports.append(
                f"{lc} spatially coherent cluster(s) of ≥4 adjacent suspect blocks — "
                "spatial coherence is a stronger indicator than isolated outliers."
            )
        if sr <= 0.05 and lc < 2:
            supports.append(
                f"Suspect block ratio {sr:.3%} and cluster count {lc} are "
                "below heuristic thresholds (5% / 2 clusters)."
            )
        return {
            "status":  "ok",
            "summary": f"Block heuristics: {suspect.sum()} suspect blocks ({sr:.3%}), {lc} large cluster(s).",
            "raw_measurements": {
                "blocks_analyzed": len(noise_vars),
                "noise_anomaly_count": int(n_anom.sum()), "cfa_anomaly_count": int(c_anom.sum()),
                "edge_anomaly_count": int(e_anom.sum()), "entropy_anomaly_count": int(h_anom.sum()),
                "suspect_block_count": int(suspect.sum()), "suspect_block_ratio": sr,
                "total_clusters": int(tc), "large_clusters_ge_4": lc,
                "ratio_above_0.05": sr > 0.05, "large_clusters_ge_2": lc >= 2,
            },
            "evidence": {
                "blocks_analyzed": len(noise_vars),
                "noise_anomaly_count": int(n_anom.sum()), "cfa_anomaly_count": int(c_anom.sum()),
                "edge_anomaly_count": int(e_anom.sum()), "entropy_anomaly_count": int(h_anom.sum()),
                "suspect_block_count": int(suspect.sum()), "suspect_block_ratio": sr,
                "total_suspect_clusters": int(tc), "large_clusters_ge_4_blocks": lc,
                "method": "Multi-signal co-occurrence + spatial cluster analysis",
                "important_note": "Raw measurements only — no AI manipulation verdict produced.",
            },
            "supports":    supports,
            "contradicts": [],
        }


# ═════════════════════════════════════════════════════════════════════════════
# DOCUMENT FORENSICS
# ═════════════════════════════════════════════════════════════════════════════

class PDFMetadataExtractor(BaseExtractor):
    """PDF document information dictionary: author, creator, producer, dates."""

    name        = "pdf_metadata"
    version     = "10.0"
    category    = CATEGORY_DOCUMENT
    RELIABILITY = RELIABILITY_HIGH

    _LIMITATIONS = [
        "PDF metadata fields can be freely set by any PDF editing tool.",
        "Dates are not cryptographically verified.",
    ]
    _FALSE_POSITIVES: List[str] = []
    _FALSE_NEGATIVES = [
        "Metadata may have been deliberately stripped.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return context.file_type == "pdf" and pypdf is not None

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        reader = context.get_pdf_reader()
        if reader is None:
            return {
                "status": "unavailable", "summary": "PDF reader unavailable.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        meta   = reader.metadata
        fields = {k.lstrip("/"): v for k, v in meta.items()} if meta else {}

        supports: List[str] = []
        if not fields:
            supports.append(
                "No PDF metadata fields found — may have been deliberately stripped."
            )
        else:
            cd = fields.get("CreationDate") or fields.get("creationdate")
            md = fields.get("ModDate")      or fields.get("moddate")
            if cd and md and str(cd) != str(md):
                supports.append(
                    f"CreationDate ({cd}) and ModDate ({md}) differ — consistent "
                    "with the PDF having been modified after initial creation."
                )
            if fields.get("Creator"):
                supports.append(f"Creator: '{fields['Creator']}'.")
            if fields.get("Producer"):
                supports.append(f"Producer: '{fields['Producer']}'.")

        return {
            "status":           "ok",
            "summary":          f"PDF metadata: {len(fields)} field(s).",
            "raw_measurements": {"field_count": len(fields)},
            "evidence":         fields,
            "supports":         supports,
            "contradicts":      [],
        }


class PDFEmbeddedExtractor(BaseExtractor):
    """Images, file attachments, JavaScript actions, AcroForm objects in PDF."""

    name         = "pdf_embedded"
    version      = "10.0"
    category     = CATEGORY_DOCUMENT
    RELIABILITY  = RELIABILITY_HIGH
    dependencies = ["get_pdf_reader", "get_pdf_images"]

    _LIMITATIONS = [
        "Embedded image pixel content requires separate image-forensics pipeline runs.",
    ]
    _FALSE_POSITIVES: List[str] = []
    _FALSE_NEGATIVES = [
        "Encrypted attachments may not be fully enumerated.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return context.file_type == "pdf" and pypdf is not None

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        reader = context.get_pdf_reader()
        if reader is None:
            return {
                "status": "unavailable", "summary": "PDF reader unavailable.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        result: Dict[str, Any] = {"images": [], "attachments": [], "javascript": [], "forms": []}
        try:
            for page_num, img_data, fmt in context.get_pdf_images():
                entry = {"page": page_num, "format": fmt, "size_bytes": len(img_data)}
                if context.options.include_images:
                    entry["base64"] = base64.b64encode(img_data).decode("utf-8")
                result["images"].append(entry)
            root_ref = reader.trailer.get("/Root", {})
            try:
                root = root_ref.get_object() if hasattr(root_ref, "get_object") else root_ref
            except Exception:
                root = {}
            if self._check_embedded_files(root):
                result["attachments"].append({"status": "found"})
            if self._check_javascript(root):
                result["javascript"].append({"status": "found"})
            if hasattr(root, "get") and root.get("/AcroForm"):
                result["forms"].append({"status": "found"})
        except Exception as exc:
            result["error"] = str(exc)

        supports: List[str] = []
        if result["attachments"]:
            supports.append("Embedded file attachments detected — examine independently.")
        if result["javascript"]:
            supports.append("JavaScript actions detected — potential security risk.")
        if result["forms"]:
            supports.append("AcroForm fields present — may submit data to remote servers.")

        return {
            "status":  "ok",
            "summary": (
                f"PDF: {len(result['images'])} image(s), {len(result['attachments'])} "
                f"attachment(s), {len(result['javascript'])} JS action(s)."
            ),
            "raw_measurements": {
                "image_count": len(result["images"]), "attachment_count": len(result["attachments"]),
                "javascript_count": len(result["javascript"]), "form_count": len(result["forms"]),
            },
            "evidence":    result,
            "supports":    supports,
            "contradicts": [],
        }

    @staticmethod
    def _check_embedded_files(root) -> bool:
        try:
            if not hasattr(root, "get"): return False
            nr = root.get("/Names")
            if nr is None: return False
            names = nr.get_object() if hasattr(nr, "get_object") else nr
            if not hasattr(names, "get"): return False
            er = names.get("/EmbeddedFiles")
            if er is None: return False
            ef = er.get_object() if hasattr(er, "get_object") else er
            if ef is None: return False
            en = ef.get("/Names") if hasattr(ef, "get") else None
            if en is None: return True
            if hasattr(en, "get_object"): en = en.get_object()
            return bool(en)
        except Exception:
            return False

    @staticmethod
    def _check_javascript(root) -> bool:
        try:
            if not hasattr(root, "get"): return False
            nr = root.get("/Names")
            if nr is not None:
                names = nr.get_object() if hasattr(nr, "get_object") else nr
                if hasattr(names, "get") and names.get("/JavaScript") is not None:
                    return True
            ar = root.get("/OpenAction")
            if ar is not None:
                action = ar.get_object() if hasattr(ar, "get_object") else ar
                if hasattr(action, "get") and action.get("/S") in ("/JavaScript", "/Launch"):
                    return True
        except Exception:
            pass
        return False


class PDFFontExtractor(BaseExtractor):
    """PDF font enumeration: embedded, non-embedded, and subset fonts."""

    name         = "pdf_fonts"
    version      = "10.0"
    category     = CATEGORY_DOCUMENT
    RELIABILITY  = RELIABILITY_MEDIUM
    dependencies = ["get_pdf_reader"]

    _LIMITATIONS = [
        "Font name parsing relies on PDF naming conventions.",
    ]
    _FALSE_POSITIVES: List[str] = []
    _FALSE_NEGATIVES = [
        "CID fonts with unusual embedding keys may be misclassified.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return context.file_type == "pdf" and pypdf is not None

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        reader = context.get_pdf_reader()
        if reader is None:
            return {
                "status": "unavailable", "summary": "PDF reader unavailable.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        fonts: Dict[str, List[str]] = {"embedded": [], "missing": [], "subsets": []}
        try:
            for page in reader.pages:
                resources = ExtractionContext._safe_resources(page)
                fr        = resources.get("/Font") if resources else None
                if not fr: continue
                try:
                    pf = fr.get_object()
                except Exception:
                    continue
                for fn in pf:
                    try:
                        fo = pf[fn]
                        if any(k in fo for k in ("/FontFile","/FontFile2","/FontFile3")):
                            fonts["embedded"].append(str(fn))
                        else:
                            fonts["missing"].append(str(fn))
                        if "+" in str(fn):
                            fonts["subsets"].append(str(fn))
                    except Exception:
                        continue
            for k in fonts:
                fonts[k] = list(set(fonts[k]))
        except Exception:
            pass

        supports: List[str] = []
        if fonts["missing"]:
            supports.append(
                f"{len(fonts['missing'])} non-embedded font(s): "
                f"{', '.join(fonts['missing'][:5])} — may indicate text replaced without "
                "proper font re-embedding."
            )
        return {
            "status":  "ok",
            "summary": (f"PDF fonts: {len(fonts['embedded'])} embedded, "
                        f"{len(fonts['missing'])} non-embedded."),
            "raw_measurements": {
                "embedded_count": len(fonts["embedded"]),
                "missing_count":  len(fonts["missing"]),
                "subset_count":   len(fonts["subsets"]),
            },
            "evidence":    fonts,
            "supports":    supports,
            "contradicts": [],
        }


class PDFHiddenExtractor(BaseExtractor):
    """Near-white text blocks and annotations without visible appearance streams."""

    name         = "pdf_hidden"
    version      = "10.0"
    category     = CATEGORY_DOCUMENT
    RELIABILITY  = RELIABILITY_MEDIUM
    dependencies = ["get_pdf_reader"]

    _LIMITATIONS = [
        "Near-white threshold (RGB > 0.92) may miss off-white hiding.",
    ]
    _FALSE_POSITIVES = [
        "Legitimate watermarks and background text trigger the near-white detector.",
    ]
    _FALSE_NEGATIVES = [
        "Hidden content using paper-coloured backgrounds, negative tracking, "
        "or 1pt text may not be detected.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return context.file_type == "pdf" and pypdf is not None

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        reader = context.get_pdf_reader()
        if reader is None:
            return {
                "status": "unavailable", "summary": "PDF reader unavailable.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        hidden: Dict[str, List] = {"annotations": [], "white_text": []}
        try:
            for idx, page in enumerate(reader.pages):
                if "/Annots" not in page: continue
                try:
                    annots = page["/Annots"].get_object()
                    for annot in annots:
                        ao = annot.get_object()
                        if "/Subtype" in ao and "/AP" not in ao:
                            hidden["annotations"].append({"page": idx, "subtype": str(ao["/Subtype"])})
                except Exception:
                    continue
        except Exception:
            pass
        layout = context.get_pdf_text_with_positions()
        if layout:
            for page in layout.get("pages", []):
                for t in page["texts"]:
                    if t.get("near_white") and t.get("text"):
                        hidden["white_text"].append({"page": page["page"], "text": t["text"][:100]})

        supports: List[str] = []
        if hidden["white_text"]:
            supports.append(
                f"{len(hidden['white_text'])} near-white text block(s) — consistent "
                "with a common PDF hidden-content technique."
            )
        if hidden["annotations"]:
            supports.append(
                f"{len(hidden['annotations'])} annotation(s) without visible appearance "
                "stream — may carry hidden metadata."
            )
        if not hidden["white_text"] and not hidden["annotations"]:
            supports.append("No near-white text or invisible-appearance annotations detected.")

        return {
            "status":  "ok",
            "summary": (f"PDF hidden: {len(hidden['white_text'])} near-white blocks, "
                        f"{len(hidden['annotations'])} invisible annotations."),
            "raw_measurements": {
                "white_text_count": len(hidden["white_text"]),
                "annotation_count": len(hidden["annotations"]),
            },
            "evidence":    hidden,
            "supports":    supports,
            "contradicts": [],
        }


class PDFLayoutExtractor(BaseExtractor):
    """PDFMiner per-page text line counts, rectangle counts, near-white items, margins."""

    name         = "pdf_layout"
    version      = "10.0"
    category     = CATEGORY_DOCUMENT
    RELIABILITY  = RELIABILITY_MEDIUM
    dependencies = ["get_pdf_text_with_positions"]

    _LIMITATIONS = [
        "Not all PDF structures are fully supported by PDFMiner "
        "(Type 3 fonts, complex CJK layouts).",
    ]
    _FALSE_POSITIVES: List[str] = []
    _FALSE_NEGATIVES: List[str] = []

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return context.file_type == "pdf" and _PDFMINER_OK

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        layout = context.get_pdf_text_with_positions()
        if layout is None:
            return {
                "status": "unavailable", "summary": "Layout extraction failed.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        pages, total_nw = [], 0
        for page in layout.get("pages", []):
            nwc = sum(1 for t in page["texts"] if t.get("near_white"))
            total_nw += nwc
            pages.append({"page": page["page"], "text_count": len(page["texts"]),
                          "rect_count": len(page["rects"]), "near_white_count": nwc})
        supports: List[str] = []
        if total_nw > 0:
            supports.append(f"{total_nw} near-white text item(s) across all pages.")
        return {
            "status":  "ok",
            "summary": f"Layout: {len(pages)} page(s), {total_nw} near-white items.",
            "raw_measurements": {"pages_analyzed": len(pages), "total_near_white": total_nw},
            "evidence":         {"pages": pages, "margins": layout.get("margins", {})},
            "supports":         supports,
            "contradicts":      [],
        }


class PDFRevisionExtractor(BaseExtractor):
    """PDF incremental save chain detection via /Prev trailer traversal."""

    name         = "pdf_revision"
    version      = "10.0"
    category     = CATEGORY_DOCUMENT
    RELIABILITY  = RELIABILITY_HIGH
    dependencies = ["get_pdf_reader"]

    _LIMITATIONS = [
        "Only the first /Prev link is followed.",
        "Does not recover or analyse content from earlier revisions.",
    ]
    _FALSE_POSITIVES: List[str] = []
    _FALSE_NEGATIVES = [
        "Some linearisation schemes may not produce detectable incremental saves.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return context.file_type == "pdf" and pypdf is not None

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        reader = context.get_pdf_reader()
        if reader is None:
            return {
                "status": "unavailable", "summary": "PDF reader unavailable.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        inc = 0
        try:
            trailer = reader.trailer; seen = set()
            cur = trailer
            while cur is not None and "/Prev" in cur:
                inc += 1
                prev = cur["/Prev"]
                if prev in seen: break
                seen.add(prev); break
        except Exception:
            pass

        supports: List[str] = []
        if inc > 0:
            supports.append(
                f"{inc} incremental-save link(s) — content from earlier revisions "
                "may be recoverable from the file body."
            )
        else:
            supports.append("No incremental-save chain detected.")
        return {
            "status":           "ok",
            "summary":          f"PDF incremental saves: {inc}.",
            "raw_measurements": {"incremental_saves": inc},
            "evidence":         {"incremental_saves": inc},
            "supports":         supports,
            "contradicts":      [],
        }


class OCRExtractor(BaseExtractor):
    """Tesseract OCR text extraction from image or rasterised PDF."""

    name         = "ocr"
    version      = "10.0"
    category     = CATEGORY_DOCUMENT
    RELIABILITY  = RELIABILITY_MEDIUM
    dependencies = ["get_ocr_text"]

    _LIMITATIONS = [
        "English OCR by default; add language data for multilingual documents.",
        "Does not extract text from vector PDF streams — use PDFMiner for that.",
    ]
    _FALSE_POSITIVES: List[str] = []
    _FALSE_NEGATIVES = [
        "Handwritten text, decorative fonts, and very small text are often missed.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type in ("image","pdf")
                and pytesseract is not None
                and context.options.mode != "light")

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        text = context.get_ocr_text() or ""
        return {
            "status":  "ok",
            "summary": f"OCR: {len(text)} characters extracted.",
            "raw_measurements": {"character_count": len(text), "text_found": bool(text.strip())},
            "evidence":         {"language": "eng", "character_count": len(text),
                                 "text_preview": text[:2000]},
            "supports": ([f"OCR extracted {len(text)} character(s) of visible text."]
                         if text.strip() else ["OCR produced no text."]),
            "contradicts": [],
        }


class FontConsistencyExtractor(BaseExtractor):
    """PDF per-page minority font detection and font-size outlier analysis."""

    name         = "font_consistency"
    version      = "10.0"
    category     = CATEGORY_DOCUMENT
    RELIABILITY  = RELIABILITY_MEDIUM
    dependencies = ["get_pdf_text_with_positions"]

    _LIMITATIONS = [
        "Minority threshold (<10% of dominant count) is heuristic.",
    ]
    _FALSE_POSITIVES = [
        "Legitimate documents with captions or footnotes use minority typefaces.",
    ]
    _FALSE_NEGATIVES = [
        "Replaced text using the same font as surrounding content is not detected.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return context.file_type == "pdf" and _PDFMINER_OK and np is not None

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        layout = context.get_pdf_text_with_positions()
        if not layout:
            return {
                "status": "unavailable", "summary": "Layout unavailable.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        fc, sizes, anomalies = Counter(), [], []
        for page in layout.get("pages", []):
            texts    = page.get("texts", [])
            pf       = Counter(t["fontname"] for t in texts if t.get("fontname"))
            for t in texts:
                if t.get("fontname"): fc[t["fontname"]] += 1
                if t.get("size"):     sizes.append(t["size"])
            if len(pf) > 1:
                dom = pf.most_common(1)[0]
                for fn, cnt in pf.items():
                    if fn != dom[0] and cnt * 10 < dom[1]:
                        anomalies.append({"page": page["page"], "minority_font": fn,
                                          "minority_count": cnt, "dominant_font": dom[0],
                                          "dominant_count": dom[1]})
        sa   = np.array(sizes) if sizes else np.array([0.0])
        sout = int(np.sum(np.abs(sa - np.median(sa)) > 3)) if len(sa) > 1 else 0

        supports: List[str] = []
        if anomalies:
            supports.append(
                f"{len(anomalies)} page(s) with minority fonts — consistent with "
                "localised text replacement or insertion."
            )
        else:
            supports.append("Font distribution appears consistent across pages.")
        return {
            "status":  "ok",
            "summary": f"Font consistency: {len(fc)} distinct fonts, {len(anomalies)} anomaly pages.",
            "raw_measurements": {
                "distinct_fonts": len(fc), "font_anomaly_pages": len(anomalies),
                "size_outlier_count": sout,
            },
            "evidence": {
                "distinct_fonts": len(fc), "font_usage": dict(fc.most_common(10)),
                "font_anomalies": anomalies, "size_outlier_count": sout,
            },
            "supports":    supports,
            "contradicts": [],
        }


class OCRImageConsistencyExtractor(BaseExtractor):
    """Glyph-height outlier ratio and per-word OCR confidence distribution."""

    name         = "ocr_image_consistency"
    version      = "10.0"
    category     = CATEGORY_DOCUMENT
    RELIABILITY  = RELIABILITY_LOW
    dependencies = ["get_decoded_image"]

    _LIMITATIONS = [
        "Depends on Tesseract word-level confidence output; varies by language/font.",
    ]
    _FALSE_POSITIVES = [
        "Mixed-language documents or intentionally varied typography trigger outliers.",
    ]
    _FALSE_NEGATIVES = [
        "Text inserted from a source matching the surrounding rendering quality "
        "will not be detected.",
    ]

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return (context.file_type in ("image","pdf")
                and pytesseract is not None and np is not None
                and context.options.mode != "light")

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {
                "status": "unavailable", "summary": "No decodable image.",
                "raw_measurements": {}, "evidence": {}, "supports": [], "contradicts": [],
            }
        try:
            data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
        except Exception as exc:
            return {
                "status": "error", "summary": str(exc),
                "raw_measurements": {}, "evidence": {"error": str(exc)},
                "supports": [], "contradicts": [],
            }
        heights, confs = [], []
        for i in range(len(data.get("text", []))):
            if not str(data["text"][i]).strip(): continue
            heights.append(data["height"][i])
            conf = data["conf"][i]
            if conf not in ("-1", -1): confs.append(float(conf))

        if not heights:
            return {
                "status":  "ok", "summary": "No text detected by OCR.",
                "raw_measurements": {"word_count": 0},
                "evidence":         {"word_count": 0},
                "supports":    [], "contradicts": [],
            }
        ha   = np.array(heights, dtype=np.float64)
        ca   = np.array(confs) if confs else np.array([0.0])
        hout = int(np.sum(np.abs(ha - np.median(ha)) > 2 * (ha.std() + 1e-6)))
        hr   = hout / len(heights)
        lc   = float(np.sum(ca < 50) / len(ca)) if len(ca) else 0.0

        supports: List[str] = []
        if hr > 0.08:
            supports.append(
                f"Glyph-height outlier ratio {hr:.3%} > 8% — consistent with "
                "text rendered from different sources."
            )
        if lc > 0.25:
            supports.append(
                f"Low-confidence word ratio {lc:.3%} > 25% — may indicate "
                "mixed rendering quality."
            )
        if hr <= 0.08 and lc <= 0.25:
            supports.append("OCR glyph sizes and confidence are uniform.")

        return {
            "status":  "ok",
            "summary": f"OCR consistency: {len(heights)} words, height_outlier_ratio={hr:.3%}.",
            "raw_measurements": {
                "word_count": len(heights), "height_outlier_count": hout,
                "height_outlier_ratio": hr, "mean_ocr_confidence": float(ca.mean()),
                "low_confidence_ratio": lc, "outlier_ratio_above_0.08": hr > 0.08,
                "low_conf_ratio_above_0.25": lc > 0.25,
            },
            "evidence": {
                "word_count": len(heights), "height_outlier_count": hout,
                "height_outlier_ratio": hr, "mean_ocr_confidence": float(ca.mean()),
                "low_confidence_ratio": lc,
                "method": "Glyph-height outlier + localised OCR-confidence analysis",
            },
            "supports":    supports,
            "contradicts": [],
        }


# ═════════════════════════════════════════════════════════════════════════════
# REPORT FORMATTER
# ═════════════════════════════════════════════════════════════════════════════

class ForensicReportFormatter:
    """
    Formats structured extractor evidence into a human-readable text report.

    Organises results by forensic category. Presents raw measurements,
    evidence, supports, contradicts, limitations, and reliability.
    Does NOT add interpretation, conclusions, or cross-extractor reasoning.
    """

    SEP  = "═" * 80
    SEP2 = "─" * 80

    def format_text_report(
        self,
        results_by_category: Dict[str, List[Dict[str, Any]]],
        file_path:   str,
        file_type:   str,
        mime_type:   str,
        timestamp:   str,
        report_id:   Optional[str] = None,
    ) -> str:
        lines: List[str] = []
        lines += [
            self.SEP,
            "  FORENSIC EVIDENCE REPORT — Evidence-Only Edition",
            "  Forensic Engine v10  |  No verdicts, no AI scoring, no fusion",
            self.SEP,
            f"  File      : {file_path}",
            f"  Type      : {file_type}  ({mime_type})",
            f"  Timestamp : {timestamp}",
        ]
        if report_id:
            lines.append(f"  Report ID : {report_id}")
        lines += [self.SEP, ""]

        for cat_key, results in sorted(results_by_category.items()):
            if not results:
                continue
            label = CATEGORY_LABELS.get(cat_key, cat_key.replace("_", " ").title())
            lines += [self.SEP, f"  CATEGORY: {label.upper()}", self.SEP]
            for r in results:
                self._format_result(r, lines)
            lines.append("")

        lines += [
            self.SEP,
            "  DISCLAIMER",
            self.SEP2,
            "  This report contains raw forensic measurements only. No conclusions,",
            "  verdicts, or AI-generation determinations have been made. All",
            "  interpretation must be performed by a qualified forensic examiner.",
            self.SEP,
        ]
        return "\n".join(lines)

    def _format_result(self, r: Dict[str, Any], lines: List[str]) -> None:
        name    = r.get("extractor", "unknown")
        version = r.get("version", "?")
        status  = r.get("status", "?")
        timing  = r.get("execution_time_s", 0.0)
        rel     = r.get("reliability", "?")

        lines.append(f"  ┌─ {name}  (v{version})  [{timing:.4f}s]  reliability={rel}")

        if status in ("unavailable", "error"):
            lines.append(f"  │  STATUS   : {status.upper()} — {r.get('summary', '')}")
            lines.append("  └" + "─" * 70)
            return

        lines.append(f"  │  STATUS   : OK")
        lines.append(f"  │  Summary  : {r.get('summary', '')}")

        raw = r.get("raw_measurements", {})
        if raw:
            lines.append("  │  Raw Measurements:")
            for k, v in raw.items():
                if isinstance(v, float):
                    lines.append(f"  │    {k:<40}: {v:.6f}")
                else:
                    lines.append(f"  │    {k:<40}: {v}")

        ev = r.get("evidence", {})
        if ev:
            lines.append("  │  Evidence:")
            self._format_dict(ev, lines, "  │    ")

        for key, label in [
            ("supports",              "Possible Supports"),
            ("contradicts",           "Possible Contradicts"),
            ("limitations",           "Limitations"),
            ("possible_false_positives", "False Positives"),
            ("possible_false_negatives", "False Negatives"),
        ]:
            items = r.get(key, [])
            if items:
                lines.append(f"  │  {label}:")
                for item in items:
                    lines.append(f"  │    • {item}")

        lines.append("  └" + "─" * 70)

    @staticmethod
    def _format_dict(d: Any, lines: List[str], indent: str, depth: int = 0) -> None:
        if depth > 3:
            lines.append(f"{indent}[nested data truncated]")
            return
        if isinstance(d, dict):
            for k, v in list(d.items())[:30]:
                if isinstance(v, (dict, list)) and v:
                    lines.append(f"{indent}{k}:")
                    ForensicReportFormatter._format_dict(v, lines, indent + "  ", depth + 1)
                elif isinstance(v, float):
                    lines.append(f"{indent}{k}: {v:.6f}")
                else:
                    s = str(v)
                    lines.append(f"{indent}{k}: {s[:200]}")
            if len(d) > 30:
                lines.append(f"{indent}... and {len(d)-30} more key(s)")
        elif isinstance(d, list):
            for item in d[:20]:
                if isinstance(item, dict):
                    ForensicReportFormatter._format_dict(item, lines, indent + "  ", depth + 1)
                else:
                    s = str(item)
                    lines.append(f"{indent}• {s[:200]}")
            if len(d) > 20:
                lines.append(f"{indent}... and {len(d)-20} more item(s)")
        else:
            s = str(d)
            lines.append(f"{indent}{s[:200]}")


# ═════════════════════════════════════════════════════════════════════════════
# PIPELINE, ASSEMBLER, ENGINE
# ═════════════════════════════════════════════════════════════════════════════

class EvidencePipeline:
    """Runs a named group of extractors against an ExtractionContext."""

    def __init__(self, name: str, extractors: List[BaseExtractor]) -> None:
        self.name       = name
        self.extractors = extractors

    def run(self, context: ExtractionContext, verbose: bool = False) -> List[Dict[str, Any]]:
        results = []
        for ext in self.extractors:
            if ext.applicable(context):
                _log(f"  extractor: {ext.name}", verbose)
                try:
                    results.append(ext.extract(context))
                except Exception as exc:
                    results.append({
                        "extractor":                ext.name,
                        "version":                  ext.version,
                        "category":                 ext.category,
                        "execution_time_s":         0.0,
                        "status":                   "error",
                        "summary":                  f"Unhandled exception: {exc}",
                        "raw_measurements":         {},
                        "evidence":                 {"exception": str(exc)},
                        "supports":                 [],
                        "contradicts":              [],
                        "limitations":              ext._LIMITATIONS,
                        "possible_false_positives": ext._FALSE_POSITIVES,
                        "possible_false_negatives": ext._FALSE_NEGATIVES,
                        "reliability":              ext.RELIABILITY,
                    })
        return results


class EvidenceAssembler:
    """
    Assembles pipeline results into the output package.
    Organises evidence by forensic category using each extractor's category field.
    """

    @staticmethod
    def assemble(
        all_results: List[Dict[str, Any]],
        context:     ExtractionContext,
        report_id:   Optional[str] = None,
        user_id:     Optional[str] = None,
    ) -> Dict[str, Any]:
        # Organise by category
        by_category: Dict[str, List[Dict[str, Any]]] = {}
        total, successful, exec_time = 0, 0, 0.0

        for r in all_results:
            cat = r.get("category", CATEGORY_FILE_INTEGRITY)
            by_category.setdefault(cat, []).append(r)
            total      += 1
            if r.get("status") == "ok":
                successful += 1
            exec_time  += r.get("execution_time_s", 0.0)

        package: Dict[str, Any] = {
            "report_id":          report_id,
            "user_id":            user_id,
            "file_path":          context.file_path,
            "file_type":          context.file_type,
            "mime_type":          context.mime_type,
            "timestamp":          datetime.now(timezone.utc).isoformat(),
            "engine_version":     "10.0",
            "evidence":           by_category,
            "summary": {
                "total_extractors":      total,
                "successful_extractors": successful,
                "unavailable_extractors": total - successful,
                "total_extraction_time_s": exec_time,
            },
        }
        if context._warning:
            package["warning"] = context._warning
        return package


class ForensicEngine:
    """
    Evidence-only forensic extraction engine.

    Runs 32 extractors across 6 forensic categories. Returns structured
    evidence with no verdicts, no confidence scores, and no fusion decisions.
    """

    def __init__(self) -> None:
        self._pipelines = [
            EvidencePipeline("file_integrity", [
                FileEvidenceExtractor(),
                StatisticsExtractor(),
                StructureExtractor(),
                SecurityExtractor(),
                PerceptualHashExtractor(),
            ]),
            EvidencePipeline("camera_origin", [
                EXIFExtractor(),
                XMPExtractor(),
                IPTCExtractor(),
                JPEGQuantizationExtractor(),
                CFAExtractor(),
                PRNUExtractor(),
            ]),
            EvidencePipeline("editing_detection", [
                ELAExtractor(),
                ELAExtractorV2(),
                CloneExtractor(),
                CopyMoveExtractorV2(),
                ResamplingExtractor(),
                CompressionHistoryExtractor(),
                JPEGGhostExtractor(),
                NoiseInconsistencyExtractor(),
            ]),
            EvidencePipeline("steganography", [
                SteganographyExtractor(),
                AdvancedSteganalysisExtractor(),
            ]),
            EvidencePipeline("ai_statistical", [
                NoiseExtractor(),
                WaveletConsistencyExtractor(),
                PowerSpectrumExtractor(),
                LocalPatchStatisticsExtractor(),
                GradientCoherenceExtractor(),
                AIGeneratedImageExtractor(),
                AIManipulationExtractor(),
            ]),
            EvidencePipeline("document_forensics", [
                PDFMetadataExtractor(),
                PDFEmbeddedExtractor(),
                PDFFontExtractor(),
                PDFHiddenExtractor(),
                PDFLayoutExtractor(),
                PDFRevisionExtractor(),
                OCRExtractor(),
                FontConsistencyExtractor(),
                OCRImageConsistencyExtractor(),
            ]),
        ]

    def run(
        self,
        file_path:  str,
        options:    RunOptions       = None,
        report_id:  Optional[str]   = None,
        user_id:    Optional[str]   = None,
    ) -> Dict[str, Any]:
        options   = options or RunOptions()
        start     = time.perf_counter()
        with open(file_path, "rb") as fh:
            raw_data = fh.read()
        context   = ExtractionContext(file_path, raw_data, options)
        all_results: List[Dict[str, Any]] = []

        for pipeline in self._pipelines:
            _log(f"pipeline: {pipeline.name}", options.verbose)
            all_results.extend(pipeline.run(context, verbose=options.verbose))

        package = EvidenceAssembler.assemble(all_results, context, report_id, user_id)
        package["summary"]["engine_wall_time_s"] = round(time.perf_counter() - start, 4)
        return package


# ─────────────────────────────────────────────────────────────────────────────
# Callback helper
# ─────────────────────────────────────────────────────────────────────────────

def send_callback(url: str, secret: str, payload: dict) -> None:
    data    = json.dumps(payload, default=str).encode("utf-8")
    headers = {
        "Content-Type":      "application/json",
        "x-callback-secret": secret,
        "User-Agent":        "forensic-engine/10.0",
    }
    cb_auth = os.getenv("CALLBACK_AUTH")
    if cb_auth:
        headers["Authorization"] = f"Bearer {cb_auth}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            print(f"[callback] HTTP {resp.status}", file=sys.stderr)
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = "<no body>"
        print(f"[callback] HTTP {exc.code}: {exc.reason}\n{body[:500]}", file=sys.stderr)
        sys.exit(0)
    except Exception as exc:
        print(f"[callback] Failed: {exc}", file=sys.stderr)
        sys.exit(0)


def load_known_hashes(path: Optional[str]) -> set:
    if not path:
        return set()
    try:
        with open(path) as fh:
            data = json.load(fh)
        if isinstance(data, list):
            return {h.lower() for h in data}
        if isinstance(data, dict) and "sha256" in data:
            return {h.lower() for h in data["sha256"]}
    except Exception as exc:
        print(f"Warning: could not load known-hashes '{path}': {exc}", file=sys.stderr)
    return set()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Forensic Engine v10 — Evidence-Only Edition. "
            "32 extractors across 6 forensic categories. "
            "No AI verdicts, no confidence scores, no cross-extractor fusion."
        )
    )
    parser.add_argument("file",              help="Path to file to analyse")
    parser.add_argument("-o", "--output",    help="Output JSON file (default: stdout)")
    parser.add_argument("--pretty",          action="store_true", help="Pretty-print JSON")
    parser.add_argument("--text-report",     action="store_true",
                        help="Write a human-readable text report alongside JSON")
    parser.add_argument("--mode",            choices=["light", "full"], default="full",
                        help="light = skip OCR + clone detection; full = everything")
    parser.add_argument("--include-images",  action="store_true",
                        help="Embed extracted PDF images as base64 in output")
    parser.add_argument("--pdf-dpi",         type=int, default=PDF_IMAGE_RESOLUTION)
    parser.add_argument("--known-hashes",    help="JSON file of known SHA-256 hashes")
    parser.add_argument("--report-id",       help="Report ID to embed in output")
    parser.add_argument("--user-id",         help="User ID to embed in output")
    parser.add_argument("--callback-url",    help="URL to POST results to")
    parser.add_argument("--callback-secret", default="")
    parser.add_argument("-v", "--verbose",   action="store_true")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"Error: '{args.file}' not found.", file=sys.stderr)
        if args.callback_url and args.report_id:
            send_callback(args.callback_url, args.callback_secret, {
                "report_id": args.report_id,
                "error":     f"File not found: {args.file}",
                "report":    None,
            })
        sys.exit(0)

    options = RunOptions(
        mode           = args.mode,
        include_images = args.include_images,
        pdf_dpi        = args.pdf_dpi,
        known_hashes   = load_known_hashes(args.known_hashes),
        verbose        = args.verbose,
    )
    engine = ForensicEngine()
    try:
        package = engine.run(
            args.file, options,
            report_id = args.report_id,
            user_id   = args.user_id,
        )
    except Exception as exc:
        if args.callback_url and args.report_id:
            send_callback(args.callback_url, args.callback_secret, {
                "report_id": args.report_id, "error": str(exc), "report": None,
            })
        raise

    indent      = 2 if args.pretty else None
    json_output = json.dumps(package, indent=indent, default=str)

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(json_output)
        _log(f"Wrote JSON to {args.output}", args.verbose)
    elif not args.text_report:
        print(json_output)

    if args.text_report:
        formatter   = ForensicReportFormatter()
        text_report = formatter.format_text_report(
            results_by_category = package["evidence"],
            file_path   = package["file_path"],
            file_type   = package["file_type"],
            mime_type   = package["mime_type"],
            timestamp   = package["timestamp"],
            report_id   = args.report_id,
        )
        if args.output:
            txt_path = os.path.splitext(args.output)[0] + ".txt"
            with open(txt_path, "w") as fh:
                fh.write(text_report)
            _log(f"Wrote text report to {txt_path}", args.verbose)
        else:
            print(text_report)

    if args.callback_url and args.report_id:
        send_callback(args.callback_url, args.callback_secret, {
            "report_id": args.report_id,
            "report":    package,
        })


if __name__ == "__main__":
    main()




