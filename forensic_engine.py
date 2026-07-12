#!/usr/bin/env python3
"""
Forensic Engine v8 – Complete Implementation
All original layers + 13 advanced v8 extractors, fully integrated.
Graceful fallbacks for missing dependencies.

CHANGELOG v8 vs v7:
  NEW EXTRACTORS (all skip gracefully when deps missing):
  - JPEGQuantizationExtractor  : reads DQT markers → quality estimate +
        inconsistent-table detection (re-saved with different encoder)
  - CompressionHistoryExtractor: AC(1,1) DCT coefficient histogram
        periodicity → double-JPEG / DQ-effect detection
  - ResamplingExtractor        : Popescu-Farid FFT peak detection for
        scale/rotate/warp interpolation artifacts
  - CFAExtractor               : block-wise Bayer CFA demosaicing
        consistency (absent in AI-generated/composited regions)
  - PRNUExtractor              : wavelet-denoising residual spatial-
        inconsistency map (single-image version; attribution needs ref bank)
  - NoiseInconsistencyExtractor: block-wise Laplacian-variance MAD
        outlier map (upgrade of NoiseExtractor)
  - AdvancedSteganalysisExtractor: RS (Regular/Singular) analysis,
        substantially more sensitive than chi-square at low embed rates
  - FontConsistencyExtractor   : per-page minority-font anomaly
        detection (PDF localized-edit signal)
  - OCRImageConsistencyExtractor: glyph-height + OCR-confidence
        outlier detection for image-of-text tampering
  - CopyMoveExtractorV2        : SIFT + BFMatcher knn + RANSAC
        homography verification (replaces trivial ORB self-match logic)
  - ELAExtractorV2             : multi-quality (60/75/90) ELA with
        per-block hot-spot ratio (far fewer false positives)
  - AIGeneratedImageExtractor  : frequency-domain + noise-floor +
        channel-correlation + saturation-uniformity heuristics
  - AIManipulationExtractor    : combined CFA + noise deviation block
        map → localized AI-inpainting / compositing signal

  RISK ENGINE: 8 new scoring blocks wired to all v8 extractors.
  PIPELINES:   5 new EvidencePipelines registered in ForensicEngine.

CHANGELOG v7 vs v6:
  - CLI: --report-id, --user-id, --callback-url, --callback-secret for
    GitHub Actions → Supabase pipeline integration.
  - send_callback(): POSTs JSON report to a Supabase edge function using
    only stdlib (urllib.request) — no extra dependency.
  - Risk engine gains combined-signal bonuses: ELA+clone together earn an
    extra 10pts; high entropy+hidden-text together earn an extra 10pts.
  - Date anomaly detection: PDF CreationDate/ModDate and EXIF
    DateTimeOriginal in the future now trigger a 20pt flag.
  - Missing metadata flag: PDF with zero standard metadata fields +5pts.
  - explanation_summary: single human-readable string in risk_assessment
    combining level + top flags (good for DB preview columns / UI cards).
  - PDFEmbeddedExtractor: _check_embedded_files() now walks the PDF Names
    tree properly through indirect references, handles empty arrays, and
    never throws unhandled KeyErrors.
  - Extractor hard-dependency audit: SecurityExtractor and StructureExtractor
    already fixed in v6; confirmed no other extractor has a PDF-only
    dependency on a non-PDF-applicable path.
  - main() wraps engine in try/except and always delivers either a report
    or an error payload to the callback URL before exiting non-zero.
"""

import os
import re
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
from typing import Dict, Any, List, Optional, Tuple
from abc import ABC, abstractmethod
from collections import defaultdict, Counter
import warnings
warnings.filterwarnings("ignore")

# ---------- Optional imports (graceful fallback) ----------
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
    Image = None
    ImageChops = None
    ImageStat = None

try:
    import imagehash
except ImportError:
    imagehash = None

try:
    import cv2
    import numpy as np
except ImportError:
    cv2 = None
    np = None

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
    ndimage  = None
    sp_fft   = None

_PDFMINER_OK = True
try:
    from pdfminer.high_level import extract_text, extract_pages
    from pdfminer.layout import LTTextBox, LTTextLine, LTPage, LTChar, LTRect
    from pdfminer.converter import PDFPageAggregator
    from pdfminer.pdfparser import PDFParser
    from pdfminer.pdfdocument import PDFDocument
    from pdfminer.pdfpage import PDFPage
    from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
    from pdfminer.layout import LAParams
except ImportError:
    _PDFMINER_OK = False
    extract_text = None
    extract_pages = None
    LAParams = None

# ---------- Configuration ----------
MAX_MEMORY_FILE_SIZE = 1024 * 1024 * 1024  # 1 GB
PDF_IMAGE_RESOLUTION = 150                  # DPI for OCR rasterisation
STEGO_SAMPLE_PIXELS  = 20_000              # pixels sampled for LSB chi-square

_FUTURE_THRESHOLD_DAYS = 1  # allow up to 1 day clock skew before flagging


def log(msg: str, verbose: bool):
    if verbose:
        print(f"[forensic-engine] {msg}", file=sys.stderr)


# ---------- Shared Context ----------
class ExtractionContext:
    """Lazy-loaded context caching expensive objects from raw bytes."""

    def __init__(self, file_path: str, raw_data: bytes, options: "RunOptions" = None):
        self.file_path  = file_path
        self.raw_data   = raw_data
        self.options    = options or RunOptions()
        self._mime_type        = None
        self._file_type        = None
        self._decoded_image    = None
        self._pdf_reader       = None
        self._ocr_text         = None
        self._pdf_images: List = []
        self._pdf_layout       = None
        self._warning          = None

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

    def _detect_type(self):
        ext  = os.path.splitext(self.file_path)[1].lower()
        mime = 'application/octet-stream'
        if magic:
            try:
                mime = magic.from_buffer(self.raw_data, mime=True)
            except Exception:
                pass
        else:
            if ext in ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'):
                mime = f'image/{ext[1:]}'
            elif ext == '.pdf':
                mime = 'application/pdf'
        self._mime_type = mime
        self._file_type = (
            'image' if mime.startswith('image') else
            'pdf'   if mime == 'application/pdf' else
            'unknown'
        )
        if len(self.raw_data) > MAX_MEMORY_FILE_SIZE:
            self._warning = f"File size exceeds {MAX_MEMORY_FILE_SIZE // 1024 // 1024} MB."

    def get_decoded_image(self):
        if self._decoded_image is None and Image is not None and self.file_type == 'image':
            try:
                self._decoded_image = Image.open(io.BytesIO(self.raw_data))
                self._decoded_image.load()
            except Exception:
                self._decoded_image = False
        return self._decoded_image if self._decoded_image is not False else None

    def get_pdf_reader(self):
        if self._pdf_reader is None and pypdf is not None and self.file_type == 'pdf':
            try:
                self._pdf_reader = pypdf.PdfReader(io.BytesIO(self.raw_data))
            except Exception:
                self._pdf_reader = False
        return self._pdf_reader if self._pdf_reader is not False else None

    @staticmethod
    def _safe_resources(page) -> dict:
        try:
            res = page.get('/Resources')
            if res is None:
                return {}
            return res.get_object() if hasattr(res, 'get_object') else res
        except Exception:
            return {}

    def get_pdf_images(self):
        if not self._pdf_images and self.file_type == 'pdf':
            reader = self.get_pdf_reader()
            if reader:
                for page_num, page in enumerate(reader.pages):
                    resources = self._safe_resources(page)
                    xobjects_ref = resources.get('/XObject') if resources else None
                    if not xobjects_ref:
                        continue
                    try:
                        xobjects = xobjects_ref.get_object()
                    except Exception:
                        continue
                    for obj_name in xobjects:
                        try:
                            obj = xobjects[obj_name]
                            if obj.get('/Subtype') == '/Image':
                                img_data = obj.get_data()
                                if img_data:
                                    fmt  = 'jpeg'
                                    filt = obj.get('/Filter')
                                    if filt == '/FlateDecode':
                                        fmt = 'png'
                                    self._pdf_images.append((page_num, img_data, fmt))
                        except Exception:
                            continue
        return self._pdf_images

    def get_pdf_text_with_positions(self):
        if self._pdf_layout is None and self.file_type == 'pdf' and _PDFMINER_OK:
            try:
                self._pdf_layout = self._extract_layout()
            except Exception:
                self._pdf_layout = False
        return self._pdf_layout if self._pdf_layout is not False else None

    def _extract_layout(self):
        if not _PDFMINER_OK:
            return {}
        layout_data: Dict[str, Any] = {'pages': [], 'margins': {}}
        try:
            rsrcmgr    = PDFResourceManager()
            laparams   = LAParams()
            device     = PDFPageAggregator(rsrcmgr, laparams=laparams)
            interpreter = PDFPageInterpreter(rsrcmgr, device)
            parser     = PDFParser(io.BytesIO(self.raw_data))
            doc        = PDFDocument(parser)
            for page_num, page in enumerate(PDFPage.create_pages(doc)):
                interpreter.process_page(page)
                layout    = device.get_result()
                page_data = {'page': page_num, 'texts': [], 'rects': []}
                for element in layout:
                    if isinstance(element, LTTextBox):
                        for textline in element:
                            if isinstance(textline, LTTextLine):
                                entry = {
                                    'text': textline.get_text().strip(),
                                    'x0': textline.x0, 'y0': textline.y0,
                                    'x1': textline.x1, 'y1': textline.y1,
                                    'fontname': None, 'size': None,
                                    'near_white': False,
                                }
                                for ch in textline:
                                    if isinstance(ch, LTChar):
                                        entry['fontname'] = getattr(ch, 'fontname', None)
                                        entry['size']     = getattr(ch, 'size', None)
                                        color = self._char_color(ch)
                                        if color is not None and all(c > 0.92 for c in color):
                                            entry['near_white'] = True
                                        break
                                page_data['texts'].append(entry)
                    elif isinstance(element, LTRect):
                        page_data['rects'].append({
                            'x0': element.x0, 'y0': element.y0,
                            'x1': element.x1, 'y1': element.y1
                        })
                layout_data['pages'].append(page_data)
            if layout_data['pages']:
                first = layout_data['pages'][0]
                if first['texts']:
                    xs = [t['x0'] for t in first['texts']]
                    layout_data['margins'] = {
                        'left':   min(xs),
                        'right':  max(t['x1'] for t in first['texts']),
                        'top':    max(t['y0'] for t in first['texts']),
                        'bottom': min(t['y0'] for t in first['texts']),
                    }
        except Exception:
            pass
        return layout_data

    @staticmethod
    def _char_color(ch) -> Optional[Tuple[float, ...]]:
        try:
            gs     = getattr(ch, 'graphicstate', None)
            if gs is None:
                return None
            ncolor = getattr(gs, 'ncolor', None)
            if ncolor is None:
                return None
            if isinstance(ncolor, (int, float)):
                return (float(ncolor),) * 3
            if isinstance(ncolor, (list, tuple)):
                return tuple(float(c) for c in ncolor)
        except Exception:
            return None
        return None

    def get_ocr_text(self):
        if self._ocr_text is None:
            if self.options.mode == 'light':
                self._ocr_text = ''
                return self._ocr_text
            if self.file_type == 'image' and pytesseract is not None:
                img = self.get_decoded_image()
                if img:
                    try:
                        self._ocr_text = pytesseract.image_to_string(img)
                    except Exception:
                        self._ocr_text = ''
            elif (self.file_type == 'pdf'
                  and pytesseract is not None
                  and convert_from_bytes is not None):
                try:
                    images    = convert_from_bytes(self.raw_data, dpi=self.options.pdf_dpi)
                    full_text = [pytesseract.image_to_string(img) for img in images]
                    self._ocr_text = '\n'.join(full_text)
                except Exception:
                    self._ocr_text = ''
            else:
                self._ocr_text = ''
        return self._ocr_text


class RunOptions:
    def __init__(
        self,
        mode          = 'full',
        include_images = False,
        pdf_dpi       = PDF_IMAGE_RESOLUTION,
        known_hashes  = None,
        verbose       = False,
    ):
        self.mode           = mode
        self.include_images = include_images
        self.pdf_dpi        = pdf_dpi
        self.known_hashes   = known_hashes or set()
        self.verbose        = verbose


# ---------- Base Extractor ----------
class BaseExtractor(ABC):
    name        = "base"
    version     = "1.0"
    dependencies: List[str] = []

    def extract(self, context: ExtractionContext) -> Dict[str, Any]:
        start     = time.perf_counter()
        dep_failed = False
        for dep in self.dependencies:
            try:
                if getattr(context, dep)() is None:
                    dep_failed = True
                    break
            except Exception:
                dep_failed = True
                break
        if dep_failed:
            return {
                "extractor":      self.name,
                "version":        self.version,
                "execution_time": time.perf_counter() - start,
                "confidence":     0.0,
                "evidence":       {"error": "Dependency failure"},
            }
        try:
            evidence   = self._extract(context)
            confidence = 1.0
        except Exception as e:
            evidence   = {"error": str(e)}
            confidence = 0.0
        return {
            "extractor":      self.name,
            "version":        self.version,
            "execution_time": time.perf_counter() - start,
            "confidence":     confidence,
            "evidence":       evidence,
        }

    @abstractmethod
    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        pass

    @staticmethod
    def applicable(context: ExtractionContext) -> bool:
        return True


# ---------- Helpers ----------
def compute_hashes(data: bytes) -> Dict[str, str]:
    return {
        'md5':    hashlib.md5(data).hexdigest(),
        'sha1':   hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
        'crc32':  hex(zlib.crc32(data) & 0xFFFFFFFF),
    }


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq   = [0] * 256
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
    return data.startswith(b'PK\x03\x04') or data.startswith(b'PK\x05\x06')


def chi_square_bit_test(bits: List[int]) -> float:
    if not bits:
        return 0.0
    n        = len(bits)
    ones     = sum(bits)
    zeros    = n - ones
    expected = n / 2
    return ((zeros - expected) ** 2) / expected + ((ones - expected) ** 2) / expected


def parse_pdf_date(date_str: str) -> Optional[datetime]:
    """Parse PDF date format D:YYYYMMDDHHmmSS into a UTC datetime, or None."""
    m = re.search(r'D:(\d{4})(\d{2})(\d{2})', str(date_str))
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                            tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def parse_exif_date(date_str: str) -> Optional[datetime]:
    """Parse EXIF date YYYY:MM:DD HH:MM:SS into a UTC datetime, or None."""
    m = re.match(r'(\d{4}):(\d{2}):(\d{2})', str(date_str))
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                            tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


# ---------- LAYER 1: File Evidence ----------
class FileEvidenceExtractor(BaseExtractor):
    name = "file_evidence"

    def _extract(self, context: ExtractionContext) -> Dict[str, Any]:
        data      = context.raw_data
        hashes    = compute_hashes(data)
        corrupted = False
        if context.file_type == 'image' and Image:
            try:
                Image.open(io.BytesIO(data)).verify()
            except Exception:
                corrupted = True
        elif context.file_type == 'pdf' and pypdf:
            try:
                pypdf.PdfReader(io.BytesIO(data))
            except Exception:
                corrupted = True
        return {
            'file_size': len(data),
            'hashes':    hashes,
            'entropy':   shannon_entropy(data),
            'mime_type': context.mime_type,
            'extension': os.path.splitext(context.file_path)[1].lower(),
            'corrupted': corrupted,
            'duplicate': hashes['sha256'] in context.options.known_hashes,
        }


# ---------- LAYER 2: Metadata ----------
class EXIFExtractor(BaseExtractor):
    name = "exif"

    @staticmethod
    def applicable(context):
        return context.file_type == 'image' and exifread is not None

    def _extract(self, context):
        exif = {}
        try:
            tags = exifread.process_file(io.BytesIO(context.raw_data), details=False)
            for tag, value in tags.items():
                exif[tag] = str(value)
        except Exception:
            pass
        return exif


class XMPExtractor(BaseExtractor):
    name = "xmp"

    @staticmethod
    def applicable(context):
        return context.file_type == 'image'

    def _extract(self, context):
        img = context.get_decoded_image()
        if img is None:
            return {}
        xmp_raw = img.info.get('xmp') or img.info.get('XML:com.adobe.xmp')
        if not xmp_raw:
            return {}
        if isinstance(xmp_raw, bytes):
            xmp_raw = xmp_raw.decode('utf-8', errors='replace')
        return {'raw_xmp_present': True, 'xmp_snippet': xmp_raw[:500]}


class IPTCExtractor(BaseExtractor):
    name = "iptc"

    @staticmethod
    def applicable(context):
        return context.file_type == 'image'

    def _extract(self, context):
        return {'note': 'IPTC-IIM parsing not implemented; requires dedicated parser'}


class PDFMetadataExtractor(BaseExtractor):
    name = "pdf_metadata"
    dependencies = ['get_pdf_reader']

    @staticmethod
    def applicable(context):
        return context.file_type == 'pdf' and pypdf is not None

    def _extract(self, context):
        reader = context.get_pdf_reader()
        if reader is None:
            return {}
        meta = reader.metadata
        if meta:
            return {k.lstrip('/'): v for k, v in meta.items()}
        return {}


# ---------- LAYER 3: Structure ----------
class StructureExtractor(BaseExtractor):
    name         = "structure"
    dependencies = []          # no hard deps — handles both image and PDF

    def _extract(self, context):
        structure = {}
        if context.file_type == 'image':
            structure['jpeg_markers'] = self._parse_jpeg(context.raw_data)
        elif context.file_type == 'pdf':
            reader = context.get_pdf_reader()
            if reader:
                xref_present = 'missing'
                try:
                    xref_present = 'present' if reader.xref else 'missing'
                except Exception:
                    pass
                structure['pdf'] = {
                    'num_pages':  len(reader.pages),
                    'xref_table': xref_present,
                }
        return structure

    def _parse_jpeg(self, data):
        markers = []
        for i in range(len(data) - 1):
            if data[i] == 0xFF and data[i + 1] not in (0x00, 0xFF):
                markers.append(hex(data[i + 1]))
        return markers[:20]


# ---------- LAYER 4: Embedded Objects ----------
class PDFEmbeddedExtractor(BaseExtractor):
    name         = "pdf_embedded"
    dependencies = ['get_pdf_reader', 'get_pdf_images']

    @staticmethod
    def applicable(context):
        return context.file_type == 'pdf' and pypdf is not None

    def _extract(self, context):
        reader = context.get_pdf_reader()
        if reader is None:
            return {}
        result = {'images': [], 'attachments': [], 'javascript': [], 'forms': []}
        try:
            for page_num, img_data, fmt in context.get_pdf_images():
                entry = {'page': page_num, 'format': fmt, 'size': len(img_data)}
                if context.options.include_images:
                    entry['base64'] = base64.b64encode(img_data).decode('utf-8')
                result['images'].append(entry)

            root_ref = reader.trailer.get('/Root', {})
            try:
                root = root_ref.get_object() if hasattr(root_ref, 'get_object') else root_ref
            except Exception:
                root = {}

            if self._check_embedded_files(root):
                result['attachments'].append({'count': 'found'})
            if self._check_javascript(root):
                result['javascript'].append({'actions': 'found'})
            if hasattr(root, 'get') and root.get('/AcroForm'):
                result['forms'].append({'form': 'found'})
        except Exception as e:
            result['error'] = str(e)
        return result

    @staticmethod
    def _check_embedded_files(root) -> bool:
        """
        v7 fix: walk the PDF Names tree properly through indirect references.
        The Names tree can contain a /Kids chain; we check one level deep,
        which covers the vast majority of real documents.
        """
        try:
            if not hasattr(root, 'get'):
                return False
            names_ref = root.get('/Names')
            if names_ref is None:
                return False
            names = names_ref.get_object() if hasattr(names_ref, 'get_object') else names_ref
            if not hasattr(names, 'get'):
                return False
            ef_ref = names.get('/EmbeddedFiles')
            if ef_ref is None:
                return False
            ef = ef_ref.get_object() if hasattr(ef_ref, 'get_object') else ef_ref
            if ef is None:
                return False
            # The EmbeddedFiles entry is a name tree; check its /Names array
            ef_names = None
            if hasattr(ef, 'get'):
                ef_names = ef.get('/Names')
            if ef_names is None:
                return True   # key exists — presume present
            if hasattr(ef_names, 'get_object'):
                ef_names = ef_names.get_object()
            return bool(ef_names)
        except Exception:
            return False

    @staticmethod
    def _check_javascript(root) -> bool:
        try:
            if not hasattr(root, 'get'):
                return False
            names_ref = root.get('/Names')
            if names_ref is None:
                return False
            names = names_ref.get_object() if hasattr(names_ref, 'get_object') else names_ref
            if hasattr(names, 'get') and names.get('/JavaScript') is not None:
                return True
            # Also check /OpenAction
            action_ref = root.get('/OpenAction')
            if action_ref is not None:
                action = action_ref.get_object() if hasattr(action_ref, 'get_object') else action_ref
                if hasattr(action, 'get') and action.get('/S') in ('/JavaScript', '/Launch'):
                    return True
        except Exception:
            pass
        return False


class PDFFontExtractor(BaseExtractor):
    name         = "pdf_fonts"
    dependencies = ['get_pdf_reader']

    @staticmethod
    def applicable(context):
        return context.file_type == 'pdf' and pypdf is not None

    def _extract(self, context):
        reader = context.get_pdf_reader()
        if reader is None:
            return {}
        fonts: Dict[str, list] = {'embedded': [], 'missing': [], 'subsets': []}
        try:
            for page in reader.pages:
                resources = ExtractionContext._safe_resources(page)
                font_ref  = resources.get('/Font') if resources else None
                if not font_ref:
                    continue
                try:
                    page_fonts = font_ref.get_object()
                except Exception:
                    continue
                for font_name in page_fonts:
                    try:
                        font_obj = page_fonts[font_name]
                        if any(k in font_obj for k in ('/FontFile', '/FontFile2', '/FontFile3')):
                            fonts['embedded'].append(str(font_name))
                        else:
                            fonts['missing'].append(str(font_name))
                        if '+' in str(font_name):
                            fonts['subsets'].append(str(font_name))
                    except Exception:
                        continue
            for key in fonts:
                fonts[key] = list(set(fonts[key]))
        except Exception:
            pass
        return fonts


# ---------- LAYER 5: OCR ----------
class OCRExtractor(BaseExtractor):
    name         = "ocr"
    dependencies = ['get_ocr_text']

    @staticmethod
    def applicable(context):
        return (context.file_type in ('image', 'pdf')
                and pytesseract is not None
                and context.options.mode != 'light')

    def _extract(self, context):
        text = context.get_ocr_text() or ''
        return {
            'text':       text[:2000],
            'confidence': min(1.0, len(text) / 500),
            'language':   'eng',
        }


# ---------- LAYER 6: Image Forensics ----------
class NoiseExtractor(BaseExtractor):
    name         = "noise"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context):
        return context.file_type == 'image' and cv2 is not None and np is not None

    def _extract(self, context):
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        img_np = np.array(img.convert('L'))
        return {
            'noise_variance': float(cv2.Laplacian(img_np, cv2.CV_64F).var()),
            'method':         'laplacian_var',
        }


class ELAExtractor(BaseExtractor):
    name         = "ela"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context):
        return context.file_type == 'image' and Image is not None

    def _extract(self, context):
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        try:
            buf = io.BytesIO()
            img.convert('RGB').save(buf, 'JPEG', quality=90)
            buf.seek(0)
            recompressed = Image.open(buf)
            diff         = ImageChops.difference(img.convert('RGB'), recompressed.convert('RGB'))
            stat         = ImageStat.Stat(diff)
            ela_score    = sum(stat.mean) / 3.0
            return {
                'ela_score': ela_score,
                'method':    'jpeg_recompression_90',
                'max_diff':  max(stat.extrema[0]) if stat.extrema else None,
            }
        except Exception as e:
            return {'error': str(e)}


class CloneExtractor(BaseExtractor):
    name         = "clone_detection"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context):
        return (context.file_type == 'image'
                and cv2 is not None
                and np is not None
                and context.options.mode != 'light')

    def _extract(self, context):
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        try:
            img_cv = cv2.cvtColor(np.array(img.convert('RGB')), cv2.COLOR_RGB2BGR)
            gray   = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
            orb    = cv2.ORB_create()
            kp, des = orb.detectAndCompute(gray, None)
            if des is None or len(kp) < 2:
                return {'clone_regions': [], 'detected': False, 'match_count': 0}
            bf      = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
            matches = bf.match(des, des)
            real_matches = sum(
                1 for m in matches
                if m.queryIdx != m.trainIdx
                and math.hypot(
                    kp[m.queryIdx].pt[0] - kp[m.trainIdx].pt[0],
                    kp[m.queryIdx].pt[1] - kp[m.trainIdx].pt[1],
                ) > 10
            )
            return {
                'clone_regions': [],
                'detected':      real_matches > 10,
                'match_count':   real_matches,
            }
        except Exception as e:
            return {'error': str(e)}


class SteganographyExtractor(BaseExtractor):
    name         = "steganography"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context):
        return context.file_type == 'image'

    def _extract(self, context):
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        try:
            if np is not None:
                pixels   = np.array(img.convert('RGB')).reshape(-1, 3)
                sample   = pixels[:STEGO_SAMPLE_PIXELS]
                lsb_bits = (sample & 1).flatten().tolist()
            else:
                data     = list(img.convert('RGB').getdata())[:STEGO_SAMPLE_PIXELS]
                lsb_bits = [c & 1 for r, g, b in data for c in (r, g, b)]

            chi2          = chi_square_bit_test(lsb_bits)
            ones_ratio    = sum(lsb_bits) / len(lsb_bits) if lsb_bits else 0.5
            suspicious    = len(lsb_bits) > 5_000 and chi2 < 0.5
            hidden_zip    = 'found' if detect_zip_header(context.raw_data) else None
            return {
                'lsb_bits_sampled':        len(lsb_bits),
                'lsb_ones_ratio':          ones_ratio,
                'lsb_chi_square':          chi2,
                'suspicious_lsb_uniformity': suspicious,
                'hidden_zip_signature':    hidden_zip,
                'hidden_files':            [],
            }
        except Exception as e:
            return {'error': str(e)}


class PerceptualHashExtractor(BaseExtractor):
    name         = "perceptual_hash"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context):
        return context.file_type == 'image' and imagehash is not None and Image is not None

    def _extract(self, context):
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        return {
            'phash': str(imagehash.phash(img)),
            'dhash': str(imagehash.dhash(img)),
            'ahash': str(imagehash.average_hash(img)),
        }


# ---------- LAYER 8: Layout ----------
class PDFLayoutExtractor(BaseExtractor):
    name         = "pdf_layout"
    dependencies = ['get_pdf_text_with_positions']

    @staticmethod
    def applicable(context):
        return context.file_type == 'pdf' and _PDFMINER_OK

    def _extract(self, context):
        layout = context.get_pdf_text_with_positions()
        if layout is None:
            return {'error': 'Layout extraction failed'}
        pages = []
        for page in layout.get('pages', []):
            near_white_count = sum(1 for t in page['texts'] if t.get('near_white'))
            pages.append({
                'page':                page['page'],
                'text_count':          len(page['texts']),
                'rect_count':          len(page['rects']),
                'near_white_text_count': near_white_count,
            })
        return {'pages': pages, 'margins': layout.get('margins', {})}


# ---------- LAYER 9: Hidden Content ----------
class PDFHiddenExtractor(BaseExtractor):
    name         = "pdf_hidden"
    dependencies = ['get_pdf_reader', 'get_pdf_text_with_positions']

    @staticmethod
    def applicable(context):
        return context.file_type == 'pdf' and pypdf is not None

    def _extract(self, context):
        reader = context.get_pdf_reader()
        if reader is None:
            return {}
        hidden: Dict[str, list] = {'annotations': [], 'white_text': [], 'deleted_objects': []}
        try:
            for idx, page in enumerate(reader.pages):
                if '/Annots' not in page:
                    continue
                try:
                    annots = page['/Annots'].get_object()
                    for annot in annots:
                        annot_obj = annot.get_object()
                        if '/Subtype' in annot_obj and '/AP' not in annot_obj:
                            hidden['annotations'].append({
                                'page':    idx,
                                'subtype': str(annot_obj['/Subtype']),
                            })
                except Exception:
                    continue
        except Exception:
            pass
        layout = context.get_pdf_text_with_positions()
        if layout:
            for page in layout.get('pages', []):
                for t in page['texts']:
                    if t.get('near_white') and t.get('text'):
                        hidden['white_text'].append({
                            'page': page['page'],
                            'text': t['text'][:100],
                        })
        return hidden


# ---------- LAYER 10: Security ----------
class SecurityExtractor(BaseExtractor):
    name         = "security"
    dependencies = []   # no hard deps — handles all file types gracefully

    def _extract(self, context):
        encrypted   = False
        permissions = None
        if context.file_type == 'pdf':
            reader = context.get_pdf_reader()
            if reader:
                try:
                    encrypted = reader.is_encrypted
                except Exception:
                    pass
                try:
                    if encrypted and hasattr(reader, 'permissions'):
                        permissions = reader.permissions
                except Exception:
                    pass
        return {'encrypted': encrypted, 'signatures': [], 'permissions': permissions}


# ---------- LAYER 13: Revision ----------
class PDFRevisionExtractor(BaseExtractor):
    name         = "pdf_revision"
    dependencies = ['get_pdf_reader']

    @staticmethod
    def applicable(context):
        return context.file_type == 'pdf' and pypdf is not None

    def _extract(self, context):
        reader = context.get_pdf_reader()
        if reader is None:
            return {}
        incremental_saves = 0
        try:
            trailer = reader.trailer
            seen    = set()
            cur     = trailer
            while cur is not None and '/Prev' in cur:
                incremental_saves += 1
                prev_offset = cur['/Prev']
                if prev_offset in seen:
                    break
                seen.add(prev_offset)
                break   # pypdf doesn't expose a clean deeper traversal
        except Exception:
            pass
        return {'incremental_saves': incremental_saves, 'objects_added': []}


# ---------- LAYER 14: Statistics ----------
class StatisticsExtractor(BaseExtractor):
    name = "statistics"

    def _extract(self, context):
        data  = context.raw_data
        freq  = [0] * 256
        for b in data:
            freq[b] += 1
        total        = len(data)
        distribution = [count / total for count in freq] if total else []
        return {
            'byte_distribution': distribution[:20],
            'entropy':           shannon_entropy(data),
        }


# ══════════════════════════════════════════════════════════════════════════════
# v8 EXTRACTORS
# ══════════════════════════════════════════════════════════════════════════════

# ---------- v8-1: JPEG Quantization Table ----------
class JPEGQuantizationExtractor(BaseExtractor):
    """Reads DQT markers from JPEG bytes → quality estimate + inconsistent-table flag."""
    name         = "jpeg_quantization"
    dependencies = []

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and context.mime_type in ('image/jpeg', 'image/jpg')

    def _extract(self, context) -> Dict[str, Any]:
        tables = self._parse_dqt(context.raw_data)
        if not tables:
            return {'tables_found': 0, 'note': 'No DQT markers found'}
        result = {'tables_found': len(tables), 'tables': []}
        for table_id, precision, values in tables:
            q = self._estimate_quality(values)
            result['tables'].append({
                'table_id':          table_id,
                'precision':         precision,
                'estimated_quality': q,
                'mean_value':        float(sum(values) / len(values)),
            })
        qualities = [t['estimated_quality'] for t in result['tables']]
        if len(qualities) >= 2:
            spread = float(max(qualities) - min(qualities))
            result['quality_spread']        = spread
            result['inconsistent_tables']   = spread > 15
        return result

    @staticmethod
    def _parse_dqt(data: bytes) -> List[Tuple[int, int, List[int]]]:
        tables, i, n = [], 2, len(data)
        while i < n - 1:
            if data[i] != 0xFF:
                i += 1; continue
            marker = data[i + 1]
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                i += 2; continue
            if marker == 0xD9:
                break
            if i + 4 > n:
                break
            seg_len = struct.unpack('>H', data[i + 2:i + 4])[0]
            if marker == 0xDB:
                payload, p = data[i + 4:i + 2 + seg_len], 0
                while p < len(payload):
                    pq_tq     = payload[p]
                    precision = pq_tq >> 4
                    table_id  = pq_tq & 0x0F
                    p += 1
                    count = 64 * (2 if precision else 1)
                    vals  = list(struct.unpack(f'>{64}H', payload[p:p + count])) if precision \
                            else list(payload[p:p + count])
                    tables.append((table_id, precision, vals))
                    p += count
            if marker == 0xDA:
                break
            i += 2 + seg_len
        return tables

    @staticmethod
    def _estimate_quality(values: List[int]) -> int:
        avg = sum(values) / len(values) if values else 1
        if avg <= 0: return 100
        q = 5000 / avg if avg < 100 else 200 - avg * 2
        return int(max(1, min(100, q)))


# ---------- v8-2: Compression History / Double-JPEG ----------
class CompressionHistoryExtractor(BaseExtractor):
    """AC(1,1) DCT coefficient histogram periodicity → DQ / double-compression signal."""
    name         = "compression_history"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return (context.file_type == 'image'
                and context.mime_type in ('image/jpeg', 'image/jpg')
                and cv2 is not None and np is not None)

    def _extract(self, context) -> Dict[str, Any]:
        if not _SCIPY_OK:
            return {'error': 'scipy required for DQ analysis'}
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        gray = np.array(img.convert('L'), dtype=np.float32)
        h, w = gray.shape
        h8, w8 = h - h % 8, w - w % 8
        gray = gray[:h8, :w8]
        coeffs = []
        for by in range(0, h8, 8):
            for bx in range(0, w8, 8):
                block = gray[by:by + 8, bx:bx + 8] - 128.0
                d = cv2.dct(block)
                coeffs.append(d[1, 1])
        if not coeffs:
            return {'error': 'No blocks extracted'}
        coeffs   = np.round(np.array(coeffs)).astype(int)
        hist_c   = Counter(coeffs.tolist())
        values   = [hist_c[k] for k in sorted(hist_c.keys())]
        ps       = self._periodicity_score(values)
        return {
            'blocks_analyzed':              len(coeffs),
            'histogram_bins':               len(hist_c),
            'periodicity_score':            ps,
            'double_compression_suspected': ps > 0.35,
            'method': 'AC(1,1) DCT coefficient histogram periodicity (DQ effect)',
        }

    @staticmethod
    def _periodicity_score(values: List[int]) -> float:
        if len(values) < 16 or not _SCIPY_OK:
            return 0.0
        arr      = np.array(values, dtype=np.float64)
        arr     -= arr.mean()
        spectrum = np.abs(sp_fft.rfft(arr))
        if len(spectrum) < 4:
            return 0.0
        spectrum[0] = 0
        total = spectrum.sum() + 1e-9
        return float(spectrum.max() / total)


# ---------- v8-3: Resampling Detection ----------
class ResamplingExtractor(BaseExtractor):
    """Popescu-Farid second-derivative FFT → periodic peaks from scaling/rotation."""
    name         = "resampling"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and np is not None

    def _extract(self, context) -> Dict[str, Any]:
        if not _SCIPY_OK:
            return {'error': 'scipy required for resampling analysis'}
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        gray     = np.array(img.convert('L'), dtype=np.float64)
        d2       = ndimage.laplace(gray)
        spectrum = np.abs(sp_fft.fftshift(sp_fft.fft2(d2)))
        h, w     = spectrum.shape
        cy, cx   = h // 2, w // 2
        r        = max(2, min(h, w) // 100)
        spectrum[cy - r:cy + r, cx - r:cx + r] = 0
        flat        = spectrum.flatten()
        threshold   = flat.mean() + 6 * flat.std()
        peak_count  = int(np.sum(flat > threshold))
        peak_ratio  = peak_count / flat.size
        return {
            'periodic_peak_count':   peak_count,
            'peak_ratio':            float(peak_ratio),
            'resampling_suspected':  peak_ratio > 0.0008,
            'method': 'Popescu-Farid second-derivative FFT peak detection',
        }


# ---------- v8-4: CFA Consistency ----------
class CFAExtractor(BaseExtractor):
    """Block-wise Bayer CFA demosaicing correlation — absent in AI-gen/composited regions."""
    name         = "cfa_consistency"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and np is not None and cv2 is not None

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        rgb    = np.array(img.convert('RGB'), dtype=np.float64)
        h, w   = rgb.shape[:2]
        block  = 32
        scores = []
        for by in range(0, h - block, block):
            row = []
            for bx in range(0, w - block, block):
                row.append(self._cfa_score(rgb[by:by + block, bx:bx + block, :]))
            if row:
                scores.append(row)
        if not scores:
            return {'error': 'Image too small for block analysis'}
        arr = np.array(scores)
        return {
            'grid_shape':                  list(arr.shape),
            'mean_cfa_score':              float(arr.mean()),
            'std_cfa_score':               float(arr.std()),
            'inconsistency_ratio':         float(
                np.sum(np.abs(arr - arr.mean()) > 2 * arr.std()) / arr.size
            ) if arr.std() > 0 else 0.0,
            'cfa_absent_or_inconsistent':  bool(arr.mean() < 0.15),
            'method': 'Green-channel bilinear-interpolation correlation heuristic',
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


# ---------- v8-5: PRNU Residual ----------
class PRNUExtractor(BaseExtractor):
    """Wavelet-denoising residual spatial-inconsistency map (single-image splice signal)."""
    name         = "prnu_residual"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and np is not None and cv2 is not None

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        gray     = np.array(img.convert('L'), dtype=np.float32)
        residual = self._denoise_residual(gray)
        h, w     = residual.shape
        block    = 64
        energies = []
        for by in range(0, h - block, block):
            for bx in range(0, w - block, block):
                energies.append(float(np.var(residual[by:by + block, bx:bx + block])))
        if not energies:
            return {'error': 'Image too small for PRNU block analysis'}
        arr    = np.array(energies)
        mean_e = float(arr.mean())
        std_e  = float(arr.std())
        cv_    = std_e / mean_e if mean_e > 0 else 0.0
        return {
            'blocks_analyzed':                 len(energies),
            'mean_residual_energy':            mean_e,
            'residual_energy_cv':              cv_,
            'spatial_inconsistency_suspected': cv_ > 0.8,
            'note': (
                'Single-image PRNU detects spatial noise-texture inconsistency '
                '(possible splice boundary). Camera attribution requires a '
                'reference fingerprint from multiple known-source images.'
            ),
        }

    @staticmethod
    def _denoise_residual(gray: np.ndarray) -> np.ndarray:
        denoised = cv2.fastNlMeansDenoising(gray.astype(np.uint8), h=6).astype(np.float32)
        return gray - denoised


# ---------- v8-6: Noise Inconsistency Map ----------
class NoiseInconsistencyExtractor(BaseExtractor):
    """Block-wise Laplacian-variance MAD outlier map — upgraded NoiseExtractor."""
    name         = "noise_inconsistency"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and np is not None and cv2 is not None

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        gray      = np.array(img.convert('L'), dtype=np.float32)
        h, w      = gray.shape
        block     = 32
        variances = []
        for by in range(0, h - block, block):
            for bx in range(0, w - block, block):
                lap = cv2.Laplacian(gray[by:by + block, bx:bx + block], cv2.CV_32F)
                variances.append(float(lap.var()))
        if not variances:
            return {'error': 'Image too small for block analysis'}
        arr      = np.array(variances)
        median   = float(np.median(arr))
        mad      = float(np.median(np.abs(arr - median))) + 1e-9
        outliers = int(np.sum(np.abs(arr - median) > 6 * mad))
        ratio    = outliers / len(variances)
        return {
            'blocks_analyzed':             len(variances),
            'median_block_variance':       median,
            'outlier_block_count':         outliers,
            'outlier_ratio':               ratio,
            'inconsistent_noise_suspected': ratio > 0.03,
            'method': 'Block-wise Laplacian-variance MAD outlier detection',
        }


# ---------- v8-7: Advanced Steganalysis (RS) ----------
class AdvancedSteganalysisExtractor(BaseExtractor):
    """Simplified RS (Regular/Singular) analysis — more sensitive than chi-square."""
    name         = "advanced_steganalysis"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and np is not None

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        gray = np.array(img.convert('L'), dtype=np.int16)
        h, w = gray.shape
        h4, w4 = h - h % 4, w - w % 4
        gray   = gray[:h4, :w4]
        groups = gray.reshape(h4 // 4, 4, w4 // 4, 4).transpose(0, 2, 1, 3).reshape(-1, 4, 4)
        mask   = np.array([[1, 0, 1, 0], [0, 1, 0, 1], [1, 0, 1, 0], [0, 1, 0, 1]])

        def disc(g):
            return np.sum(np.abs(np.diff(g.flatten())))

        r, s, r_neg, s_neg = 0, 0, 0, 0
        for g in groups:
            f      = disc(g)
            f_flip = disc(g ^ 1)
            if f_flip > f: r += 1
            elif f_flip < f: s += 1
            ng      = g.copy(); ng[mask == 1] ^= 1
            f_ng    = disc(ng)
            if f_ng > f: r_neg += 1
            elif f_ng < f: s_neg += 1

        total      = max(len(groups), 1)
        rs_ratio   = (r - s) / total
        rs_neg     = (r_neg - s_neg) / total
        asymmetry  = abs(rs_ratio - rs_neg)
        return {
            'groups_analyzed':     int(total),
            'rm_minus_sm':         float(rs_ratio),
            'rm_minus_sm_negmask': float(rs_neg),
            'rs_asymmetry':        float(asymmetry),
            'embedding_suspected': asymmetry > 0.03,
            'method': 'Simplified RS (Regular/Singular) analysis',
        }


# ---------- v8-8: Font Consistency (PDF) ----------
class FontConsistencyExtractor(BaseExtractor):
    """Per-page minority-font anomaly detection — localized PDF text-edit signal."""
    name         = "font_consistency"
    dependencies = ['get_pdf_text_with_positions']

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'pdf' and _PDFMINER_OK and np is not None

    def _extract(self, context) -> Dict[str, Any]:
        layout = context.get_pdf_text_with_positions()
        if not layout:
            return {'error': 'Layout extraction unavailable'}
        font_counter = Counter()
        size_values  = []
        anomalies    = []
        for page in layout.get('pages', []):
            texts      = page.get('texts', [])
            page_fonts = Counter(t['fontname'] for t in texts if t.get('fontname'))
            for t in texts:
                if t.get('fontname'): font_counter[t['fontname']] += 1
                if t.get('size'):     size_values.append(t['size'])
            if len(page_fonts) > 1:
                dominant = page_fonts.most_common(1)[0]
                for font, count in page_fonts.items():
                    if font != dominant[0] and count * 10 < dominant[1]:
                        anomalies.append({
                            'page':            page['page'],
                            'minority_font':   font,
                            'minority_count':  count,
                            'dominant_font':   dominant[0],
                            'dominant_count':  dominant[1],
                        })
        size_arr     = np.array(size_values) if size_values else np.array([0.0])
        size_outliers = int(np.sum(
            np.abs(size_arr - np.median(size_arr)) > 3
        )) if len(size_arr) > 1 else 0
        return {
            'distinct_fonts':              len(font_counter),
            'font_usage':                  dict(font_counter.most_common(10)),
            'font_anomalies':              anomalies,
            'size_outlier_count':          size_outliers,
            'inconsistent_fonts_suspected': len(anomalies) > 0,
        }


# ---------- v8-9: OCR Image Consistency ----------
class OCRImageConsistencyExtractor(BaseExtractor):
    """Glyph-height + OCR-confidence outlier analysis for image-of-text tampering."""
    name         = "ocr_image_consistency"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return (context.file_type in ('image', 'pdf')
                and pytesseract is not None
                and np is not None
                and context.options.mode != 'light')

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'No decodable image available'}
        try:
            data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
        except Exception as e:
            return {'error': str(e)}
        heights, confidences = [], []
        for i in range(len(data.get('text', []))):
            if not str(data['text'][i]).strip():
                continue
            heights.append(data['height'][i])
            conf = data['conf'][i]
            if conf not in ('-1', -1):
                confidences.append(float(conf))
        if not heights:
            return {'word_count': 0, 'note': 'No text detected'}
        h_arr = np.array(heights, dtype=np.float64)
        c_arr = np.array(confidences) if confidences else np.array([0.0])
        h_out = int(np.sum(np.abs(h_arr - np.median(h_arr)) > 2 * (h_arr.std() + 1e-6)))
        lc    = float(np.sum(c_arr < 50) / len(c_arr)) if len(c_arr) else 0.0
        return {
            'word_count':                     len(heights),
            'height_outlier_count':           h_out,
            'height_outlier_ratio':           h_out / len(heights),
            'mean_ocr_confidence':            float(c_arr.mean()),
            'low_confidence_ratio':           lc,
            'rendering_inconsistency_suspected': (h_out / len(heights) > 0.08 or lc > 0.25),
            'method': 'Glyph-height outlier + localised OCR-confidence analysis',
        }


# ---------- v8-10: Copy-Move V2 (SIFT + RANSAC) ----------
class CopyMoveExtractorV2(BaseExtractor):
    """SIFT keypoints + BFMatcher knn + RANSAC homography — replaces trivial ORB self-match."""
    name         = "copy_move_v2"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return (context.file_type == 'image'
                and cv2 is not None and np is not None
                and context.options.mode != 'light')

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        img_cv = cv2.cvtColor(np.array(img.convert('RGB')), cv2.COLOR_RGB2BGR)
        gray   = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
        sift   = cv2.SIFT_create(nfeatures=2000)
        kp, des = sift.detectAndCompute(gray, None)
        if des is None or len(kp) < 8:
            return {'detected': False, 'match_count': 0, 'note': 'Insufficient keypoints'}
        bf      = cv2.BFMatcher()
        matches = bf.knnMatch(des, des, k=3)
        good    = []
        for grp in matches:
            for m in grp[1:]:
                if m.queryIdx == m.trainIdx:
                    continue
                p1, p2 = np.array(kp[m.queryIdx].pt), np.array(kp[m.trainIdx].pt)
                if np.linalg.norm(p1 - p2) > 16:
                    good.append(m)
                break
        if len(good) < 8:
            return {'detected': False, 'match_count': len(good), 'ransac_inliers': 0}
        src = np.float32([kp[m.queryIdx].pt for m in good]).reshape(-1, 1, 2)
        dst = np.float32([kp[m.trainIdx].pt for m in good]).reshape(-1, 1, 2)
        H, mask   = cv2.findHomography(src, dst, cv2.RANSAC, 5.0)
        inliers   = int(mask.sum()) if mask is not None else 0
        return {
            'raw_match_count': len(good),
            'ransac_inliers':  inliers,
            'detected':        inliers >= 8,
            'method': 'SIFT + BFMatcher knn + RANSAC homography verification',
        }


# ---------- v8-11: Multi-Quality ELA ----------
class ELAExtractorV2(BaseExtractor):
    """Multi-quality (60/75/90) JPEG recompression ELA with per-block hot-spot ratio."""
    name         = "ela_v2"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and Image is not None and np is not None

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        rgb     = img.convert('RGB')
        rgb_arr = np.array(rgb, dtype=np.int16)
        h_img, w_img = rgb_arr.shape[:2]
        block   = 32
        scores  = {}
        regions = {}
        for q in (60, 75, 90):
            buf = io.BytesIO()
            rgb.save(buf, 'JPEG', quality=q)
            buf.seek(0)
            recomp = np.array(Image.open(buf).convert('RGB'), dtype=np.int16)
            diff   = np.abs(rgb_arr - recomp).sum(axis=2)
            scores[q] = float(diff.mean())
            block_means = []
            for by in range(0, h_img - block, block):
                for bx in range(0, w_img - block, block):
                    block_means.append(float(diff[by:by + block, bx:bx + block].mean()))
            gm   = scores[q]
            hr   = sum(1 for b in block_means if b > gm * 2.5) / len(block_means) \
                   if block_means else 0.0
            regions[q] = {
                'max_block_mean':  max(block_means) if block_means else 0.0,
                'global_mean':     gm,
                'hot_block_ratio': hr,
            }
        loc_edit = any(regions[q]['hot_block_ratio'] > 0.02 for q in regions)
        return {
            'scores_by_quality':        scores,
            'region_analysis':          regions,
            'localized_editing_suspected': loc_edit,
            'method': 'Multi-quality JPEG recompression ELA with block hot-spot ratio',
        }


# ---------- v8-12: AI-Generated Image Heuristics ----------
class AIGeneratedImageExtractor(BaseExtractor):
    """
    Frequency-domain + noise-floor + channel-correlation + saturation-uniformity
    heuristics for AI-generated image detection. Combine with CFAExtractor and
    NoiseInconsistencyExtractor; route through a trained classifier for production.
    """
    name         = "ai_generated_heuristics"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and np is not None and cv2 is not None

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        rgb  = np.array(img.convert('RGB'), dtype=np.float64)
        gray = np.array(img.convert('L'),   dtype=np.float64)

        spectral  = self._spectral_periodicity(gray)
        noise_fl  = self._noise_floor(gray)
        ch_corr   = self._channel_corr(rgb)
        sat_uni   = self._saturation_uniformity(img)

        signals   = {
            'spectral_periodicity':   spectral,
            'high_freq_noise_floor':  noise_fl,
            'rg_channel_correlation': ch_corr['rg'],
            'rb_channel_correlation': ch_corr['rb'],
            'saturation_uniformity':  sat_uni,
        }
        reasons, cnt = [], 0
        if spectral > 0.02:
            cnt += 1; reasons.append('Periodic spectral peaks (possible upsampling artifact).')
        if noise_fl < 1.2:
            cnt += 1; reasons.append('Unusually low high-frequency noise floor (lacks sensor noise).')
        if ch_corr['rg'] > 0.98 and ch_corr['rb'] > 0.98:
            cnt += 1; reasons.append('Very high inter-channel correlation (atypical of camera sensor).')
        if sat_uni > 0.85:
            cnt += 1; reasons.append('Unusually uniform color saturation distribution.')

        return {
            'signals':              signals,
            'indicator_count':      cnt,
            'indicators_triggered': reasons,
            'ai_generated_suspected': cnt >= 2,
            'confidence_caveat': (
                'Heuristic-only. Use a trained classifier for production-grade detection.'
            ),
        }

    @staticmethod
    def _spectral_periodicity(gray: np.ndarray) -> float:
        if not _SCIPY_OK: return 0.0
        f    = sp_fft.fft2(gray)
        mag  = np.abs(sp_fft.fftshift(f))
        h, w = mag.shape
        r    = max(2, min(h, w) // 50)
        cy, cx = h // 2, w // 2
        mag[cy - r:cy + r, cx - r:cx + r] = 0
        flat  = mag.flatten()
        thr   = flat.mean() + 8 * flat.std()
        return float(np.sum(flat > thr) / flat.size)

    @staticmethod
    def _noise_floor(gray: np.ndarray) -> float:
        if cv2 is None: return 0.0
        blurred  = cv2.GaussianBlur(gray, (5, 5), 0)
        residual = gray - blurred
        return float(np.std(residual))

    @staticmethod
    def _channel_corr(rgb: np.ndarray) -> Dict[str, float]:
        r, g, b = rgb[:, :, 0].flatten(), rgb[:, :, 1].flatten(), rgb[:, :, 2].flatten()
        idx     = np.random.choice(len(r), size=min(20_000, len(r)), replace=False)
        rg = float(np.corrcoef(r[idx], g[idx])[0, 1])
        rb = float(np.corrcoef(r[idx], b[idx])[0, 1])
        return {
            'rg': 0.0 if math.isnan(rg) else rg,
            'rb': 0.0 if math.isnan(rb) else rb,
        }

    @staticmethod
    def _saturation_uniformity(img) -> float:
        if Image is None: return 0.0
        try:
            hsv  = np.array(img.convert('HSV'))
        except Exception:
            return 0.0
        sat  = hsv[:, :, 1].astype(np.float64)
        hist, _ = np.histogram(sat, bins=32, range=(0, 255), density=True)
        hist  = hist / (hist.sum() + 1e-9)
        ent   = -np.sum(hist * np.log2(hist + 1e-12))
        max_e = math.log2(len(hist))
        return float(1.0 - (ent / max_e if max_e > 0 else 0))


# ---------- v8-13: AI Manipulation Heuristic ----------
class AIManipulationExtractor(BaseExtractor):
    """
    Combined low-CFA-correlation + noise-level-deviation block map.
    Flags regions inconsistent with the rest of the image's capture pipeline
    — primary signal for localized AI inpainting / compositing.
    """
    name         = "ai_manipulation_heuristic"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and np is not None and cv2 is not None

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        gray  = np.array(img.convert('L'), dtype=np.float32)
        rgb   = np.array(img.convert('RGB'), dtype=np.float64)
        h, w  = gray.shape
        block = 32
        noise_grid, cfa_grid = [], []
        for by in range(0, h - block, block):
            for bx in range(0, w - block, block):
                lap_var = float(cv2.Laplacian(
                    gray[by:by + block, bx:bx + block], cv2.CV_32F
                ).var())
                noise_grid.append(lap_var)
                cfa_grid.append(
                    CFAExtractor._cfa_score(rgb[by:by + block, bx:bx + block, :])
                )
        if not noise_grid:
            return {'error': 'Image too small for block analysis'}
        n_arr    = np.array(noise_grid)
        c_arr    = np.array(cfa_grid)
        n_med    = np.median(n_arr)
        c_med    = np.median(c_arr)
        suspect  = int(np.sum(
            (c_arr < c_med * 0.5) & (np.abs(n_arr - n_med) > n_med * 0.75)
        ))
        ratio    = suspect / len(noise_grid)
        return {
            'blocks_analyzed':          len(noise_grid),
            'suspect_block_count':      suspect,
            'suspect_block_ratio':      float(ratio),
            'localized_ai_edit_suspected': ratio > 0.05,
            'method': (
                'Combined low-CFA-correlation + noise-deviation block analysis '
                '— candidate AI-inpainted / composited region.'
            ),
            'confidence_caveat': 'Heuristic corroborating signal, not a standalone verdict.',
        }


# ══════════════════════════════════════════════════════════════════════════════
# END v8 EXTRACTORS
# ══════════════════════════════════════════════════════════════════════════════


# ---------- Evidence Pipeline ----------
class EvidencePipeline:
    def __init__(self, name: str, extractors: List[BaseExtractor]):
        self.name       = name
        self.extractors = extractors

    def run(self, context: ExtractionContext, verbose: bool = False) -> Dict[str, Any]:
        results = []
        for ext in self.extractors:
            if ext.applicable(context):
                log(f"  extractor: {ext.name}", verbose)
                try:
                    results.append(ext.extract(context))
                except Exception as e:
                    results.append({
                        "extractor":      ext.name,
                        "version":        ext.version,
                        "execution_time": 0.0,
                        "confidence":     0.0,
                        "evidence":       {"error": str(e)},
                    })
        return {self.name: results}


# ---------- Risk / Correlation Engine (v7) ----------
class RiskCorrelationEngine:
    """
    Walks all evidence, produces:
      risk_score        — 0-100
      risk_level        — none / low / medium / high
      flags             — list of human-readable explanations
      explanation_summary — single string suitable for a DB preview column
    """

    _PDF_META_KEYS = ('CreationDate', 'ModDate', 'Author', 'Creator', 'Producer')

    def score(
        self,
        evidence:  Dict[str, List[Dict[str, Any]]],
        file_type: str,
    ) -> Dict[str, Any]:
        flags: List[str] = []
        points = 0
        now    = datetime.now(timezone.utc)

        def find(category: str, name: str) -> Optional[dict]:
            for res in evidence.get(category, []):
                if res.get('extractor') == name:
                    return res.get('evidence', {})
            return None

        # ── File-level ────────────────────────────────────────────────────────
        fe = find('file', 'file_evidence')
        entropy = 0.0
        if fe:
            if fe.get('corrupted'):
                points += 15
                flags.append('File failed structural validation — appears corrupted or malformed.')
            if fe.get('duplicate'):
                points += 10
                flags.append('File SHA-256 matches a previously-seen / known file.')
            entropy = fe.get('entropy', 0.0)
            if entropy > 7.9:
                points += 5
                flags.append(
                    f'Overall file entropy is very high ({entropy:.2f}/8) — consistent with '
                    f'encryption, compression, or embedded packed data.'
                )

        # ── Metadata date anomalies ───────────────────────────────────────────
        pdf_meta = find('metadata', 'pdf_metadata')
        if pdf_meta:
            # Future date
            for key in ('CreationDate', 'ModDate'):
                val = pdf_meta.get(key) or pdf_meta.get(key.lower())
                if val:
                    dt = parse_pdf_date(str(val))
                    if dt and (dt - now).days > _FUTURE_THRESHOLD_DAYS:
                        points += 20
                        flags.append(
                            f'PDF {key} is set in the future '
                            f'({dt.strftime("%Y-%m-%d")}) — metadata likely tampered.'
                        )
                        break
            # No metadata at all
            has_any = any(pdf_meta.get(k) for k in self._PDF_META_KEYS)
            if not has_any and file_type == 'pdf':
                points += 5
                flags.append(
                    'PDF has no standard metadata fields — may have been stripped to hide origin.'
                )

        exif = find('metadata', 'exif')
        if exif:
            for key in ('EXIF DateTimeOriginal', 'Image DateTime', 'EXIF DateTimeDigitized'):
                val = exif.get(key)
                if val:
                    dt = parse_exif_date(str(val))
                    if dt and (dt - now).days > _FUTURE_THRESHOLD_DAYS:
                        points += 15
                        flags.append(
                            f'EXIF {key} is set in the future '
                            f'({dt.strftime("%Y-%m-%d")}) — timestamp likely tampered.'
                        )
                        break

        # ── Image forensics ───────────────────────────────────────────────────
        ela   = find('visual', 'ela')
        clone = find('visual', 'clone_detection')

        ela_suspicious   = ela   is not None and ela.get('ela_score', 0) > 15
        clone_suspicious = clone is not None and clone.get('detected')

        if ela_suspicious:
            points += 20
            flags.append(
                f"ELA score is elevated ({ela['ela_score']:.1f}) — possible localised "
                f"recompression or editing artefact."
            )
        if clone_suspicious:
            points += 15
            flags.append(
                f"Clone-detection found {clone.get('match_count', 0)} repeated feature matches "
                f"— possible copy-move manipulation."
            )
        # Combined ELA + clone bonus
        if ela_suspicious and clone_suspicious:
            points += 10
            flags.append(
                'Both ELA and clone detection raised flags simultaneously — '
                'elevated confidence of deliberate image manipulation.'
            )

        stego = find('visual', 'steganography')
        if stego:
            if stego.get('hidden_zip_signature'):
                points += 20
                flags.append('A ZIP file signature was found embedded in the image bytes.')
            if stego.get('suspicious_lsb_uniformity'):
                points += 10
                flags.append(
                    'LSB distribution is unusually uniform — possible steganographic payload '
                    '(heuristic signal, not conclusive).'
                )

        # ── PDF forensics ─────────────────────────────────────────────────────
        sec = find('security', 'security')
        if sec and sec.get('encrypted'):
            points += 5
            flags.append('PDF is encrypted / password-protected.')

        hidden = find('hidden', 'pdf_hidden')
        hidden_text_count = 0
        if hidden:
            white_text = hidden.get('white_text', [])
            if white_text:
                hidden_text_count = len(white_text)
                points += 15
                flags.append(
                    f'Found {hidden_text_count} block(s) of near-white (likely invisible) text — '
                    f'often used to conceal content from visual review or manipulate OCR output.'
                )
            if hidden.get('annotations'):
                points += 5
                flags.append(
                    f"{len(hidden['annotations'])} annotation(s) with no visible appearance stream."
                )

        # Combined high-entropy + hidden-text bonus
        if entropy > 7.5 and hidden_text_count > 0:
            points += 10
            flags.append(
                'High file entropy combined with hidden near-white text — '
                'multiple simultaneous concealment signals.'
            )

        rev = find('revision', 'pdf_revision')
        if rev and rev.get('incremental_saves', 0) > 0:
            points += 5
            flags.append(
                f"PDF contains {rev['incremental_saves']} incremental-save chain link(s) — "
                f"document was re-saved after initial creation."
            )

        fonts = find('embedded', 'pdf_fonts')
        if fonts and fonts.get('missing'):
            points += 5
            flags.append(
                f"{len(fonts['missing'])} font(s) referenced but not embedded — "
                f"may render differently across viewers; sometimes used to obscure edits."
            )

        # ── v8: Compression history ───────────────────────────────────────────
        comp = find('quantization', 'compression_history')
        if comp and comp.get('double_compression_suspected'):
            points += 15
            flags.append(
                f'Double-JPEG compression artifact detected (DQ histogram periodicity score '
                f'{comp.get("periodicity_score", 0):.2f}) — image may have been re-saved '
                f'after editing.'
            )

        quant = find('quantization', 'jpeg_quantization')
        if quant and quant.get('inconsistent_tables'):
            points += 10
            flags.append(
                f'JPEG quantization tables imply inconsistent quality levels '
                f'(spread {quant.get("quality_spread", 0):.0f} pts) — possible '
                f'encoder mismatch from re-saving.'
            )

        # ── v8: Resampling ────────────────────────────────────────────────────
        resamp = find('resampling', 'resampling')
        if resamp and resamp.get('resampling_suspected'):
            points += 10
            flags.append(
                f'Periodic FFT peaks detected in second-derivative '
                f'(peak ratio {resamp.get("peak_ratio", 0):.5f}) — image or a '
                f'composited region was likely scaled, rotated, or warped.'
            )

        # ── v8: Sensor / CFA ─────────────────────────────────────────────────
        cfa = find('sensor', 'cfa_consistency')
        if cfa and cfa.get('cfa_absent_or_inconsistent'):
            points += 10
            flags.append(
                f'CFA demosaicing pattern weak or absent (mean score '
                f'{cfa.get("mean_cfa_score", 0):.3f}) — atypical of genuine '
                f'camera capture; consistent with AI generation or compositing.'
            )

        prnu = find('sensor', 'prnu_residual')
        if prnu and prnu.get('spatial_inconsistency_suspected'):
            points += 10
            flags.append(
                f'PRNU residual energy is spatially inconsistent across the image '
                f'(CV={prnu.get("residual_energy_cv", 0):.2f}) — possible splice '
                f'boundary between regions from different capture pipelines.'
            )

        # ── v8: Noise inconsistency ───────────────────────────────────────────
        noise_inc = find('visual2', 'noise_inconsistency')
        if noise_inc and noise_inc.get('inconsistent_noise_suspected'):
            points += 10
            flags.append(
                f'Block-wise noise variance outliers: '
                f'{noise_inc.get("outlier_block_count", 0)} blocks '
                f'({noise_inc.get("outlier_ratio", 0):.1%}) deviate strongly '
                f'from the image median — inconsistent noise texture across regions.'
            )

        # ── v8: Advanced steganography ────────────────────────────────────────
        rs = find('visual2', 'advanced_steganalysis')
        if rs and rs.get('embedding_suspected'):
            points += 15
            flags.append(
                f'RS steganalysis asymmetry {rs.get("rs_asymmetry", 0):.3f} exceeds '
                f'threshold — possible LSB steganographic payload (more sensitive '
                f'than chi-square; still a statistical signal, not proof).'
            )

        # ── v8: Copy-move V2 ──────────────────────────────────────────────────
        cm2 = find('visual2', 'copy_move_v2')
        if cm2 and cm2.get('detected'):
            points += 15
            flags.append(
                f'SIFT + RANSAC copy-move: {cm2.get("ransac_inliers", 0)} inliers '
                f'surviving geometric verification — high-confidence copy-paste '
                f'manipulation (false-positive rate much lower than basic ORB).'
            )

        # ── v8: Multi-quality ELA ─────────────────────────────────────────────
        ela2 = find('visual2', 'ela_v2')
        if ela2 and ela2.get('localized_editing_suspected'):
            hot_ratios = [
                ela2.get('region_analysis', {}).get(q, {}).get('hot_block_ratio', 0)
                for q in (60, 75, 90)
            ]
            points += 15
            flags.append(
                f'Multi-quality ELA detected localised hot-spot regions '
                f'(max hot-block ratio {max(hot_ratios):.1%}) — consistent with '
                f'a composited or selectively re-compressed area.'
            )
        # Bonus: ELAv2 AND clone_detection both triggered (higher confidence)
        ela2_suspicious = ela2 is not None and ela2.get('localized_editing_suspected')
        if ela2_suspicious and clone_suspicious:
            points += 5
            flags.append(
                'Multi-quality ELA and clone-detection both flagged '
                '— corroborating evidence of image manipulation.'
            )

        # ── v8: AI-generated ──────────────────────────────────────────────────
        ai_gen = find('visual2', 'ai_generated_heuristics')
        if ai_gen and ai_gen.get('ai_generated_suspected'):
            points += 20
            reasons = ai_gen.get('indicators_triggered', [])
            flags.append(
                f'{ai_gen.get("indicator_count", 0)}/4 AI-generation frequency/'
                f'noise/color signals triggered: '
                + (' | '.join(reasons[:2]) if reasons else 'see evidence.')
            )

        # ── v8: AI manipulation ───────────────────────────────────────────────
        ai_edit = find('visual2', 'ai_manipulation_heuristic')
        if ai_edit and ai_edit.get('localized_ai_edit_suspected'):
            points += 20
            flags.append(
                f'{ai_edit.get("suspect_block_ratio", 0):.1%} of image blocks show '
                f'both low CFA correlation and anomalous noise level — candidate '
                f'AI-inpainted or composited region(s).'
            )

        # ── v8: Font consistency (PDF) ────────────────────────────────────────
        font_c = find('document_consistency', 'font_consistency')
        if font_c and font_c.get('inconsistent_fonts_suspected'):
            points += 10
            n_anom = len(font_c.get('font_anomalies', []))
            flags.append(
                f'Font consistency: {n_anom} page(s) have minority fonts '
                f'appearing only 1-2× while another dominates — consistent '
                f'with localised PDF text replacement.'
            )

        # ── v8: OCR image consistency ─────────────────────────────────────────
        ocr_c = find('document_consistency', 'ocr_image_consistency')
        if ocr_c and ocr_c.get('rendering_inconsistency_suspected'):
            points += 10
            flags.append(
                f'OCR image analysis: glyph-height outlier ratio '
                f'{ocr_c.get("height_outlier_ratio", 0):.1%}, '
                f'low-confidence word ratio '
                f'{ocr_c.get("low_confidence_ratio", 0):.1%} — '
                f'inconsistent text rendering suggestive of localised editing.'
            )

        # ── Clamp + level ─────────────────────────────────────────────────────
        points = min(points, 100)
        level  = (
            'high'   if points >= 60 else
            'medium' if points >= 30 else
            'low'    if points >  0  else
            'none'
        )

        # ── explanation_summary ───────────────────────────────────────────────
        if flags:
            top   = flags[:3]
            extra = len(flags) - 3
            summary = f"[{level.upper()}] {points}/100 — " + " | ".join(top)
            if extra > 0:
                summary += f" (+{extra} more flag{'s' if extra > 1 else ''})"
        else:
            summary = f"[{level.upper()}] {points}/100 — No anomalies detected."

        return {
            'risk_score':          points,
            'risk_level':          level,
            'flags':               flags,
            'explanation_summary': summary,
            'note': (
                'Heuristic triage aid only — not a forensic determination. '
                'A human examiner should review flagged items directly.'
            ),
        }


# ---------- Evidence Assembler ----------
class EvidenceAssembler:
    @staticmethod
    def assemble(
        pipeline_results: Dict[str, Any],
        context:          ExtractionContext,
        report_id:        Optional[str] = None,
        user_id:          Optional[str] = None,
    ) -> Dict[str, Any]:
        package: Dict[str, Any] = {
            "report_id": report_id,
            "user_id":   user_id,
            "file_path": context.file_path,
            "file_type": context.file_type,
            "mime_type": context.mime_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "evidence":  {},
            "summary":   {
                "total_extractors":      0,
                "successful_extractors": 0,
                "total_execution_time":  0.0,
            },
        }
        if context._warning:
            package["warning"] = context._warning

        for category, results in pipeline_results.items():
            package["evidence"][category] = results
            for res in results:
                package["summary"]["total_extractors"]      += 1
                if res["confidence"] > 0.5:
                    package["summary"]["successful_extractors"] += 1
                package["summary"]["total_execution_time"] += res["execution_time"]

        risk_engine             = RiskCorrelationEngine()
        package["risk_assessment"] = risk_engine.score(package["evidence"], context.file_type)
        return package


# ---------- Engine ----------
class ForensicEngine:
    def __init__(self):
        self.pipelines = {
            # ── v7 original pipelines ──────────────────────────────────────────
            'file':      EvidencePipeline('file',      [FileEvidenceExtractor()]),
            'metadata':  EvidencePipeline('metadata',  [
                EXIFExtractor(), XMPExtractor(), IPTCExtractor(), PDFMetadataExtractor()
            ]),
            'structure': EvidencePipeline('structure', [StructureExtractor()]),
            'statistics': EvidencePipeline('statistics', [StatisticsExtractor()]),
            'visual':    EvidencePipeline('visual',    [
                NoiseExtractor(), ELAExtractor(), CloneExtractor(),
                SteganographyExtractor(), PerceptualHashExtractor()
            ]),
            'text':      EvidencePipeline('text',      [OCRExtractor()]),
            'embedded':  EvidencePipeline('embedded',  [PDFEmbeddedExtractor(), PDFFontExtractor()]),
            'security':  EvidencePipeline('security',  [SecurityExtractor()]),
            'hidden':    EvidencePipeline('hidden',    [PDFHiddenExtractor()]),
            'revision':  EvidencePipeline('revision',  [PDFRevisionExtractor()]),
            'layout':    EvidencePipeline('layout',    [PDFLayoutExtractor()]),
            # ── v8 new pipelines ───────────────────────────────────────────────
            'quantization': EvidencePipeline('quantization', [
                JPEGQuantizationExtractor(),
                CompressionHistoryExtractor(),
            ]),
            'resampling': EvidencePipeline('resampling', [
                ResamplingExtractor(),
            ]),
            'sensor': EvidencePipeline('sensor', [
                CFAExtractor(),
                PRNUExtractor(),
            ]),
            'visual2': EvidencePipeline('visual2', [
                NoiseInconsistencyExtractor(),
                AdvancedSteganalysisExtractor(),
                CopyMoveExtractorV2(),
                ELAExtractorV2(),
                AIGeneratedImageExtractor(),
                AIManipulationExtractor(),
            ]),
            'document_consistency': EvidencePipeline('document_consistency', [
                FontConsistencyExtractor(),
                OCRImageConsistencyExtractor(),
            ]),
        }

    def run(
        self,
        file_path:  str,
        options:    RunOptions  = None,
        report_id:  Optional[str] = None,
        user_id:    Optional[str] = None,
    ) -> Dict[str, Any]:
        options    = options or RunOptions()
        start      = time.perf_counter()
        with open(file_path, 'rb') as f:
            raw_data = f.read()
        context         = ExtractionContext(file_path, raw_data, options)
        pipeline_results: Dict[str, Any] = {}
        for name, pipeline in self.pipelines.items():
            log(f"pipeline: {name}", options.verbose)
            result = pipeline.run(context, verbose=options.verbose)
            if result[name]:
                pipeline_results.update(result)
        package = EvidenceAssembler.assemble(pipeline_results, context, report_id, user_id)
        package["summary"]["engine_execution_time"] = time.perf_counter() - start
        return package


# ---------- Callback ----------
def send_callback(url: str, secret: str, payload: dict):
    """POST the result payload to the callback URL (Supabase receive-results function)."""
    data = json.dumps(payload, default=str).encode('utf-8')

    headers = {
        'Content-Type':      'application/json',
        'x-callback-secret': secret,
        # Default urllib UA ("Python-urllib/3.x") is a known bot signature that
        # Cloudflare / Supabase's edge WAF frequently blocks silently (403/dropped).
        'User-Agent':        'forensic-engine/8.0 (+github-actions)',
        'Accept':            'application/json',
    }

    callback_auth = os.getenv('CALLBACK_AUTH')
    if callback_auth:
        headers['Authorization'] = f'Bearer {callback_auth}'

    req = urllib.request.Request(url, data=data, headers=headers, method='POST')

    try:
        # Cold-start Edge Functions + a multi-KB JSON payload can take longer than 30s.
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp_body = resp.read().decode('utf-8', errors='replace')
            print(f"[callback] HTTP {resp.status}: {resp_body[:500]}", file=sys.stderr)
    except urllib.error.HTTPError as e:
        # Read the body — this is where the *real* reason usually is
        # (e.g. Supabase's own JSON error, or a Cloudflare HTML challenge page).
        try:
            err_body = e.read().decode('utf-8', errors='replace')
        except Exception:
            err_body = '<no body>'
        print(f"[callback] HTTP error {e.code}: {e.reason}\nBody: {err_body[:1000]}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"[callback] URL/connection error: {e.reason}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[callback] Failed: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)

# ---------- Known-hash loader ----------
def load_known_hashes(path: Optional[str]) -> set:
    if not path:
        return set()
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            return {h.lower() for h in data}
        if isinstance(data, dict) and 'sha256' in data:
            return {h.lower() for h in data['sha256']}
    except Exception as e:
        print(f"Warning: could not load known-hashes '{path}': {e}", file=sys.stderr)
    return set()


# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(
        description="Forensic Engine v8 – File forensics for images and PDFs. "
                    "27 extractors across 16 pipelines."
    )
    parser.add_argument('file',               help='Path to file to analyse')
    parser.add_argument('-o', '--output',     help='Output JSON file (default: stdout)')
    parser.add_argument('--pretty',           action='store_true', help='Pretty-print JSON')
    parser.add_argument('--mode',             choices=['light', 'full'], default='full',
                        help='light = skip OCR + clone-detection; full = everything')
    parser.add_argument('--include-images',   action='store_true',
                        help='Embed extracted PDF images as base64 in output')
    parser.add_argument('--pdf-dpi',          type=int, default=PDF_IMAGE_RESOLUTION,
                        help=f'DPI for PDF→image rasterisation (default {PDF_IMAGE_RESOLUTION})')
    parser.add_argument('--known-hashes',     help='JSON file of known sha256 hashes')
    parser.add_argument('--report-id',        help='Report ID to embed in output and callback')
    parser.add_argument('--user-id',          help='User ID to embed in output and callback')
    parser.add_argument('--callback-url',     help='URL to POST results to (Supabase edge fn)')
    parser.add_argument('--callback-secret',  help='Bearer/header secret for callback URL',
                        default='')
    parser.add_argument('-v', '--verbose',    action='store_true', help='Progress to stderr')
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"Error: '{args.file}' not found.", file=sys.stderr)
        if args.callback_url and args.report_id:
            send_callback(args.callback_url, args.callback_secret, {
                'report_id': args.report_id,
                'error':     f"File not found: {args.file}",
                'report':    None,
            })
        sys.exit(1)

    options = RunOptions(
        mode           = args.mode,
        include_images = args.include_images,
        pdf_dpi        = args.pdf_dpi,
        known_hashes   = load_known_hashes(args.known_hashes),
        verbose        = args.verbose,
    )

    engine = ForensicEngine()
    try:
        package = engine.run(args.file, options,
                             report_id=args.report_id, user_id=args.user_id)
    except Exception as e:
        if args.callback_url and args.report_id:
            send_callback(args.callback_url, args.callback_secret, {
                'report_id': args.report_id,
                'error':     str(e),
                'report':    None,
            })
        raise

    indent      = 2 if args.pretty else None
    json_output = json.dumps(package, indent=indent, default=str)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(json_output)
        log(f"wrote output to {args.output}", args.verbose)
    else:
        print(json_output)

    if args.callback_url and args.report_id:
        send_callback(args.callback_url, args.callback_secret, {
            'report_id': args.report_id,
            'report':    package,
        })


if __name__ == '__main__':
    main()
