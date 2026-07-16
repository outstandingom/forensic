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
    def _cfa_score(patch: 'Any') -> float:
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




