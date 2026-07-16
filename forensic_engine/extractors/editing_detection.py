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
        return (context.file_type == "image" and np is not None and SCIPY_OK)

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        if not SCIPY_OK:
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
        if not SCIPY_OK:
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
        if len(values) < 16 or not SCIPY_OK:
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
        diff_maps: Dict[int, 'Any'] = {}
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




