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
    def _haar_1level(img: 'Any') -> Tuple['Any', 'Any', 'Any', 'Any']:
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
    def _kurtosis(data: 'Any') -> float:
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
    def _radial_avg(psd: 'Any', cy: int, cx: int) -> Tuple[List[float], List[int]]:
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
    def _azimuthal_cv(psd: 'Any', cy: int, cx: int, ring_r: int) -> float:
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

    def _sig_wavelet_kurtosis(self, gray: 'Any') -> Dict:
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

    def _sig_power_spectrum(self, gray: 'Any') -> Dict:
        if not SCIPY_OK:
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

    def _sig_local_variance_cv(self, gray: 'Any') -> Dict:
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

    def _sig_shot_noise(self, gray: 'Any') -> Dict:
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

    def _sig_gradient_uniformity(self, gray: 'Any') -> Dict:
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

    def _sig_hf_autocorrelation(self, gray: 'Any') -> Dict:
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

    def _sig_channel_hf_corr(self, rgb: 'Any') -> Dict:
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
        def mad_bounds(arr: 'Any', k: float = 4.0) -> Tuple[float, float]:
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
        if nr * nc == len(suspect) and SCIPY_OK:
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




