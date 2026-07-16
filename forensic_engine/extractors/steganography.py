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

        def disc(g: 'Any') -> int:
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




