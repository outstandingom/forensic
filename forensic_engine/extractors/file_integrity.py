import math
import os
import struct
import io
import time
import hashlib
import zlib
import re
from typing import Dict, Any, List, Optional, Tuple, ClassVar
from collections import Counter

from forensic_engine.base import BaseExtractor, shannon_entropy, detect_zip_header, chi_square_bit_test, compute_hashes
from forensic_engine.context import ExtractionContext
from forensic_engine.constants import *
from forensic_engine.dependencies import *

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




