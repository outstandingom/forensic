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
        return context.file_type == "pdf" and PDFMINER_OK

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
        return context.file_type == "pdf" and PDFMINER_OK and np is not None

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




