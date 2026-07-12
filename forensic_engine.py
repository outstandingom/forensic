#!/usr/bin/env python3
"""
Forensic Engine v8 – Complete Implementation (Detailed Report Edition)
All original layers + 13 advanced v8 extractors, fully integrated.
Graceful fallbacks for missing dependencies.

CHANGES vs original v8:
  - REMOVED: RiskCorrelationEngine (aggregate scoring)
  - ADDED:   DetailedReportBuilder — translates every extractor's raw output
             into human-readable findings and notable highlights.
             All evidence is presented directly; no score is computed.
  - OUTPUT:  JSON gains "detailed_assessment" key (replaces "risk_assessment")
             containing per-category findings, per-extractor findings, and
             an "all_notable_findings" list of anomalies worth attention.
  - CLI:     --text-report  flag writes a plain-text version of the report
             (to stdout or --output path with .txt extension).
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
        mode           = 'full',
        include_images = False,
        pdf_dpi        = PDF_IMAGE_RESOLUTION,
        known_hashes   = None,
        verbose        = False,
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
    m = re.search(r'D:(\d{4})(\d{2})(\d{2})', str(date_str))
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                            tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def parse_exif_date(date_str: str) -> Optional[datetime]:
    m = re.match(r'(\d{4}):(\d{2}):(\d{2})', str(date_str))
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                            tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


# ══════════════════════════════════════════════════════════════════════════════
# EXTRACTORS (all unchanged from v8)
# ══════════════════════════════════════════════════════════════════════════════

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


class StructureExtractor(BaseExtractor):
    name         = "structure"
    dependencies = []

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
            ef_names = None
            if hasattr(ef, 'get'):
                ef_names = ef.get('/Names')
            if ef_names is None:
                return True
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
                'lsb_bits_sampled':          len(lsb_bits),
                'lsb_ones_ratio':            ones_ratio,
                'lsb_chi_square':            chi2,
                'suspicious_lsb_uniformity': suspicious,
                'hidden_zip_signature':      hidden_zip,
                'hidden_files':              [],
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
                'page':                  page['page'],
                'text_count':            len(page['texts']),
                'rect_count':            len(page['rects']),
                'near_white_text_count': near_white_count,
            })
        return {'pages': pages, 'margins': layout.get('margins', {})}


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


class SecurityExtractor(BaseExtractor):
    name         = "security"
    dependencies = []

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
                break
        except Exception:
            pass
        return {'incremental_saves': incremental_saves, 'objects_added': []}


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


# ── v8 Extractors ─────────────────────────────────────────────────────────────

class JPEGQuantizationExtractor(BaseExtractor):
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
            result['quality_spread']      = spread
            result['inconsistent_tables'] = spread > 15
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


class CompressionHistoryExtractor(BaseExtractor):
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


class ResamplingExtractor(BaseExtractor):
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
            'periodic_peak_count':  peak_count,
            'peak_ratio':           float(peak_ratio),
            'resampling_suspected': peak_ratio > 0.0008,
            'method': 'Popescu-Farid second-derivative FFT peak detection',
        }


class CFAExtractor(BaseExtractor):
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
            'grid_shape':                 list(arr.shape),
            'mean_cfa_score':             float(arr.mean()),
            'std_cfa_score':              float(arr.std()),
            'inconsistency_ratio':        float(
                np.sum(np.abs(arr - arr.mean()) > 2 * arr.std()) / arr.size
            ) if arr.std() > 0 else 0.0,
            'cfa_absent_or_inconsistent': bool(arr.mean() < 0.15),
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


class PRNUExtractor(BaseExtractor):
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


class NoiseInconsistencyExtractor(BaseExtractor):
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
            'blocks_analyzed':              len(variances),
            'median_block_variance':        median,
            'outlier_block_count':          outliers,
            'outlier_ratio':                ratio,
            'inconsistent_noise_suspected': ratio > 0.03,
            'method': 'Block-wise Laplacian-variance MAD outlier detection',
        }


class AdvancedSteganalysisExtractor(BaseExtractor):
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


class FontConsistencyExtractor(BaseExtractor):
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
                            'page':           page['page'],
                            'minority_font':  font,
                            'minority_count': count,
                            'dominant_font':  dominant[0],
                            'dominant_count': dominant[1],
                        })
        size_arr      = np.array(size_values) if size_values else np.array([0.0])
        size_outliers = int(np.sum(
            np.abs(size_arr - np.median(size_arr)) > 3
        )) if len(size_arr) > 1 else 0
        return {
            'distinct_fonts':               len(font_counter),
            'font_usage':                   dict(font_counter.most_common(10)),
            'font_anomalies':               anomalies,
            'size_outlier_count':           size_outliers,
            'inconsistent_fonts_suspected': len(anomalies) > 0,
        }


class OCRImageConsistencyExtractor(BaseExtractor):
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
            'word_count':                        len(heights),
            'height_outlier_count':              h_out,
            'height_outlier_ratio':              h_out / len(heights),
            'mean_ocr_confidence':               float(c_arr.mean()),
            'low_confidence_ratio':              lc,
            'rendering_inconsistency_suspected': (h_out / len(heights) > 0.08 or lc > 0.25),
            'method': 'Glyph-height outlier + localised OCR-confidence analysis',
        }


class CopyMoveExtractorV2(BaseExtractor):
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


class ELAExtractorV2(BaseExtractor):
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
            'scores_by_quality':          scores,
            'region_analysis':            regions,
            'localized_editing_suspected': loc_edit,
            'method': 'Multi-quality JPEG recompression ELA with block hot-spot ratio',
        }


class AIGeneratedImageExtractor(BaseExtractor):
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

        signals = {
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
            'signals':               signals,
            'indicator_count':       cnt,
            'indicators_triggered':  reasons,
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


class AIManipulationExtractor(BaseExtractor):
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
            'blocks_analyzed':           len(noise_grid),
            'suspect_block_count':       suspect,
            'suspect_block_ratio':       float(ratio),
            'localized_ai_edit_suspected': ratio > 0.05,
            'method': (
                'Combined low-CFA-correlation + noise-deviation block analysis '
                '— candidate AI-inpainted / composited region.'
            ),
            'confidence_caveat': 'Heuristic corroborating signal, not a standalone verdict.',
        }


# ══════════════════════════════════════════════════════════════════════════════
# DETAILED REPORT BUILDER  (replaces RiskCorrelationEngine)
# ══════════════════════════════════════════════════════════════════════════════

class DetailedReportBuilder:
    """
    Translates every extractor's raw evidence dict into human-readable findings
    and notable highlights.  No aggregate score is computed — all data is shown.

    Output structure
    ----------------
    {
      "categories": [
        {
          "category": "file",
          "label":    "File Overview",
          "extractors": [
            {
              "extractor":        "file_evidence",
              "version":          "1.0",
              "status":           "ok" | "unavailable",
              "execution_time_s": 0.012,
              "findings":         ["File size: 4,321 bytes", ...],
              "notable_findings": ["⚠ Corrupted file structure detected.", ...],
              "raw_evidence":     { ... }
            }
          ]
        }, ...
      ],
      "all_notable_findings": [ "⚠ ...", ... ],
      "total_notable":        7,
      "disclaimer":           "..."
    }
    """

    CATEGORY_LABELS: Dict[str, str] = {
        'file':                 'File Overview',
        'metadata':             'Metadata Analysis',
        'structure':            'File Structure',
        'statistics':           'Statistical Analysis',
        'visual':               'Visual Forensics — Core',
        'text':                 'OCR / Text Extraction',
        'embedded':             'Embedded Objects',
        'security':             'Security & Encryption',
        'hidden':               'Hidden Content Detection',
        'revision':             'Revision & Edit History',
        'layout':               'Document Layout',
        'quantization':         'JPEG Compression Analysis',
        'resampling':           'Resampling / Geometric Transform Detection',
        'sensor':               'Camera Sensor Fingerprint',
        'visual2':              'Advanced Visual Forensics',
        'document_consistency': 'Document Consistency Analysis',
    }

    def build(
        self,
        evidence:  Dict[str, List[Dict[str, Any]]],
        file_type: str,
    ) -> Dict[str, Any]:
        all_notable: List[str] = []
        categories:  List[Dict] = []

        for cat_key, results in evidence.items():
            label   = self.CATEGORY_LABELS.get(cat_key, cat_key.replace('_', ' ').title())
            entries = []
            for res in results:
                entry = self._process(res)
                entries.append(entry)
                all_notable.extend(entry.get('notable_findings', []))
            categories.append({
                'category':   cat_key,
                'label':      label,
                'extractors': entries,
            })

        return {
            'categories':          categories,
            'all_notable_findings': all_notable,
            'total_notable':       len(all_notable),
            'disclaimer': (
                'All findings are the direct output of each extractor — '
                'no aggregate scoring is applied. '
                'Results should be reviewed by a qualified examiner in context.'
            ),
        }

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _process(self, res: Dict[str, Any]) -> Dict[str, Any]:
        name      = res.get('extractor', 'unknown')
        evidence  = res.get('evidence', {})
        conf      = res.get('confidence', 0.0)
        exec_time = res.get('execution_time', 0.0)
        version   = res.get('version', '?')

        if conf == 0.0 or 'error' in evidence:
            return {
                'extractor':        name,
                'version':          version,
                'status':           'unavailable',
                'reason':           evidence.get('error', 'Dependency not installed or not applicable'),
                'execution_time_s': round(exec_time, 4),
                'findings':         [],
                'notable_findings': [],
                'raw_evidence':     {},
            }

        findings, notable = self._interpret(name, evidence)
        return {
            'extractor':        name,
            'version':          version,
            'status':           'ok',
            'execution_time_s': round(exec_time, 4),
            'findings':         findings,
            'notable_findings': notable,
            'raw_evidence':     evidence,
        }

    def _interpret(self, name: str, ev: Dict[str, Any]) -> Tuple[List[str], List[str]]:
        method = getattr(self, f'_interp_{name}', None)
        if method:
            return method(ev)
        # Generic fallback for any extractor without a dedicated interpreter
        findings = []
        for k, v in ev.items():
            if isinstance(v, (dict, list)) and not v:
                continue
            label = k.replace('_', ' ').title()
            if isinstance(v, float):
                findings.append(f'{label}: {v:.6f}')
            else:
                findings.append(f'{label}: {v}')
        return findings, []

    # ── Per-extractor interpreters ─────────────────────────────────────────────

    def _interp_file_evidence(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        size = ev.get('file_size', 0)
        f.append(f'File size         : {size:,} bytes  ({size / 1024:.2f} KB)')
        f.append(f'MIME type         : {ev.get("mime_type", "unknown")}')
        f.append(f'Extension         : {ev.get("extension", "unknown")}')
        entropy = ev.get('entropy', 0.0)
        f.append(f'Byte entropy      : {entropy:.5f} / 8.0')
        hashes = ev.get('hashes', {})
        if hashes:
            f.append(f'MD5               : {hashes.get("md5", "n/a")}')
            f.append(f'SHA-1             : {hashes.get("sha1", "n/a")}')
            f.append(f'SHA-256           : {hashes.get("sha256", "n/a")}')
            f.append(f'CRC-32            : {hashes.get("crc32", "n/a")}')
        struct_ok = not ev.get('corrupted', False)
        f.append(f'Structure valid   : {"YES" if struct_ok else "NO — see notable findings"}')
        f.append(f'Known-hash match  : {"YES" if ev.get("duplicate") else "no"}')

        if entropy > 7.9:
            n.append(f'⚠ Extremely high byte entropy ({entropy:.4f}/8.0) — file may be encrypted, '
                     f'compressed, or contain densely packed/packed-binary data.')
        elif entropy > 7.5:
            n.append(f'↑ Elevated byte entropy ({entropy:.4f}/8.0) — notable but not conclusive on its own.')
        if ev.get('corrupted'):
            n.append('⚠ File failed structural validation — appears corrupted or malformed.')
        if ev.get('duplicate'):
            n.append('⚠ SHA-256 matches a hash in the known-files list — possible duplicate or re-used file.')
        return f, n

    def _interp_exif(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        if not ev:
            f.append('No EXIF data found in this image.')
            return f, n
        priority = [
            'Image Make', 'Image Model', 'EXIF DateTimeOriginal', 'Image DateTime',
            'EXIF DateTimeDigitized', 'EXIF Software', 'EXIF ExifImageWidth',
            'EXIF ExifImageLength', 'Image Orientation', 'EXIF Flash',
            'EXIF FocalLength', 'EXIF ISOSpeedRatings', 'EXIF ExposureTime',
            'EXIF FNumber', 'GPS GPSLatitude', 'GPS GPSLongitude', 'GPS GPSAltitude',
        ]
        shown = set()
        for key in priority:
            if key in ev:
                f.append(f'{key:<35}: {ev[key]}')
                shown.add(key)
        remainder = {k: v for k, v in ev.items() if k not in shown}
        if remainder:
            f.append(f'--- Additional EXIF tags ({len(remainder)}) ---')
            for k, v in list(remainder.items())[:30]:
                f.append(f'  {k:<33}: {v}')
            if len(remainder) > 30:
                f.append(f'  ... and {len(remainder) - 30} more tag(s) (see raw_evidence)')

        if ev.get('Image Make') or ev.get('Image Model'):
            n.append(f'Camera/Device     : {ev.get("Image Make", "").strip()} {ev.get("Image Model", "").strip()}'.strip())
        if ev.get('EXIF DateTimeOriginal'):
            n.append(f'Capture timestamp : {ev["EXIF DateTimeOriginal"]}')
        if ev.get('EXIF Software'):
            n.append(f'Processing software present in EXIF: {ev["EXIF Software"]}')
        if ev.get('GPS GPSLatitude') and ev.get('GPS GPSLongitude'):
            n.append(f'GPS coordinates embedded — latitude: {ev["GPS GPSLatitude"]}, '
                     f'longitude: {ev["GPS GPSLongitude"]}')
        return f, n

    def _interp_xmp(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        if ev.get('raw_xmp_present'):
            f.append('XMP metadata block  : PRESENT')
            snippet = ev.get('xmp_snippet', '')
            if snippet:
                f.append(f'XMP snippet (≤500 ch):\n{snippet}')
            n.append('XMP metadata is present — may contain full editing history, software chain, '
                     'or creator/rights information that is absent in core EXIF.')
        else:
            f.append('XMP metadata block  : not found')
        return f, n

    def _interp_iptc(self, ev: Dict) -> Tuple[List[str], List[str]]:
        note = ev.get('note', '')
        return ([note] if note else ['IPTC: no data or parser not available']), []

    def _interp_pdf_metadata(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        if not ev:
            n.append('⚠ PDF contains no standard metadata fields — may have been deliberately stripped '
                     'to obscure its origin or creation toolchain.')
            return ['No PDF metadata found.'], n
        field_map = {
            'Title':        'Title',
            'Author':       'Author',
            'Subject':      'Subject',
            'Keywords':     'Keywords',
            'Creator':      'Creating application',
            'Producer':     'PDF producer library',
            'CreationDate': 'Creation date',
            'ModDate':      'Last-modified date',
            'Trapped':      'Trapped flag',
        }
        for raw_key, label in field_map.items():
            val = ev.get(raw_key) or ev.get(raw_key.lower())
            if val:
                f.append(f'{label:<25}: {val}')
        other = {k: v for k, v in ev.items()
                 if k not in field_map and k.lower() not in [x.lower() for x in field_map]}
        for k, v in other.items():
            f.append(f'{k:<25}: {v}')

        cd = ev.get('CreationDate') or ev.get('creationdate')
        md = ev.get('ModDate') or ev.get('moddate')
        if cd:
            n.append(f'PDF creation date : {cd}')
        if md:
            n.append(f'PDF modified date : {md}')
        if cd and md and str(cd) != str(md):
            n.append('↑ CreationDate and ModDate differ — the PDF was modified after initial creation.')
        if ev.get('Author'):
            n.append(f'Author field      : {ev["Author"]}')
        if ev.get('Creator'):
            n.append(f'Created with      : {ev["Creator"]}')
        if ev.get('Producer'):
            n.append(f'PDF producer      : {ev["Producer"]}')
        return f, n

    def _interp_structure(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        markers = ev.get('jpeg_markers')
        if markers is not None:
            f.append(f'JPEG markers (first 20): {", ".join(markers)}')
            marker_desc = {
                '0xe0': 'APP0 (JFIF header)',   '0xe1': 'APP1 (EXIF / XMP)',
                '0xe2': 'APP2 (ICC profile)',   '0xed': 'APP13 (IPTC / Photoshop)',
                '0xdb': 'DQT (quantization table)', '0xc0': 'SOF0 (baseline JPEG)',
                '0xc2': 'SOF2 (progressive JPEG)', '0xda': 'SOS (start of scan)',
                '0xfe': 'COM (comment segment)',
            }
            for m in markers:
                desc = marker_desc.get(m)
                if desc:
                    f.append(f'  {m} → {desc}')
        pdf = ev.get('pdf', {})
        if pdf:
            f.append(f'PDF pages         : {pdf.get("num_pages", "unknown")}')
            f.append(f'Cross-ref table   : {pdf.get("xref_table", "unknown")}')
            if pdf.get('xref_table') == 'missing':
                n.append('⚠ PDF cross-reference table is missing or unreadable — file may be malformed or rebuilt.')
        return f, n

    def _interp_statistics(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        entropy = ev.get('entropy', 0.0)
        f.append(f'File entropy      : {entropy:.5f} / 8.0')
        dist = ev.get('byte_distribution', [])
        if dist:
            zero_f = dist[0]
            f.append(f'Null-byte freq    : {zero_f:.4f}  ({zero_f * 100:.1f}% of file bytes)')
            f.append(f'Byte freq[0–19]   : {[round(x, 4) for x in dist]}')
            if zero_f > 0.30:
                n.append(f'⚠ Null bytes account for {zero_f * 100:.1f}% of the file — '
                         f'may indicate sparse data, padding, or structured binary content.')
        return f, n

    def _interp_noise(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        var = ev.get('noise_variance')
        if var is not None:
            f.append(f'Laplacian noise variance: {var:.4f}')
            f.append(f'Method                 : {ev.get("method", "")}')
            if var < 10:
                n.append(f'↓ Very low noise variance ({var:.2f}) — image appears unusually smooth; '
                         f'consistent with synthetic/AI-generated content or heavy post-processing.')
            elif var > 2000:
                n.append(f'↑ Very high noise variance ({var:.2f}) — strong texture, extreme noise, '
                         f'or motion blur present.')
            else:
                f.append(f'Noise variance is within a typical photographic range.')
        return f, n

    def _interp_ela(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        score = ev.get('ela_score')
        max_d = ev.get('max_diff')
        if score is not None:
            f.append(f'ELA mean error (q=90)  : {score:.4f}')
            f.append(f'Method                 : {ev.get("method", "")}')
            if max_d is not None:
                f.append(f'Maximum pixel diff     : {max_d}')
            if score > 15:
                n.append(f'⚠ Elevated ELA score ({score:.2f}) — '
                         f'possible localised recompression artefact or image editing. '
                         f'Verify against multi-quality ELA (ela_v2) for confirmation.')
            elif score > 8:
                n.append(f'↑ Moderate ELA score ({score:.2f}) — worth closer inspection, '
                         f'especially if other extractors also flag the image.')
            else:
                f.append(f'ELA score is within the typical range for this compression level.')
        return f, n

    def _interp_clone_detection(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        detected    = ev.get('detected', False)
        match_count = ev.get('match_count', 0)
        f.append(f'Method             : ORB feature matching (displaced >10 px)')
        f.append(f'Positive detection : {"YES" if detected else "no"}')
        f.append(f'Displaced matches  : {match_count}')
        if detected:
            n.append(f'⚠ ORB clone detection triggered ({match_count} displaced feature matches) — '
                     f'possible copy-move region. See copy_move_v2 (SIFT+RANSAC) for a more '
                     f'geometrically rigorous confirmation.')
        else:
            f.append('No significant copy-move pattern found at this sensitivity level.')
        return f, n

    def _interp_steganography(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        sampled = ev.get('lsb_bits_sampled', 0)
        ratio   = ev.get('lsb_ones_ratio', 0.5)
        chi2    = ev.get('lsb_chi_square')
        susp    = ev.get('suspicious_lsb_uniformity', False)
        zip_sig = ev.get('hidden_zip_signature')

        f.append(f'LSB bits sampled         : {sampled:,}')
        f.append(f'LSB ones ratio           : {ratio:.5f}  (0.5000 = perfect uniformity)')
        if chi2 is not None:
            f.append(f'Chi-square statistic     : {chi2:.5f}  (< 0.5 with >5000 bits = suspicious)')
        if susp:
            n.append(f'⚠ LSB distribution is unusually uniform (chi²={chi2:.4f}) — '
                     f'consistent with a steganographic payload replacing LSBs. '
                     f'Statistical signal only; does not reveal payload content. '
                     f'See advanced_steganalysis (RS method) for a more sensitive test.')
        else:
            f.append('LSB uniformity within normal bounds — no chi-square signal.')
        if zip_sig:
            n.append('⚠ ZIP file signature (PK\\x03\\x04) detected in raw image bytes — '
                     'file may be a polyglot or contain a hidden archive.')
        hidden_files = ev.get('hidden_files', [])
        if hidden_files:
            n.append(f'⚠ {len(hidden_files)} hidden file(s) detected: {hidden_files}')
        return f, n

    def _interp_perceptual_hash(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        if ev.get('phash'):
            f.append(f'pHash (perceptual) : {ev["phash"]}')
            f.append(f'dHash (difference) : {ev.get("dhash", "n/a")}')
            f.append(f'aHash (average)    : {ev.get("ahash", "n/a")}')
            n.append('Perceptual hashes computed — can be used for near-duplicate or '
                     'modified-copy detection against a reference image database.')
        else:
            f.append('Perceptual hashing: not available (imagehash not installed).')
        return f, n

    def _interp_ocr(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        text = ev.get('text', '')
        lang = ev.get('language', 'eng')
        f.append(f'OCR language   : {lang}')
        f.append(f'Characters extracted: {len(text)}')
        if text.strip():
            f.append(f'--- Extracted text (first 500 chars) ---\n{text[:500]}')
            if len(text) > 500:
                f.append(f'... [{len(text) - 500} more chars — see raw_evidence for full text]')
            n.append(f'OCR succeeded — {len(text)} characters of text extracted.')
        else:
            f.append('OCR produced no text.')
        return f, n

    def _interp_pdf_embedded(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        images = ev.get('images', [])
        f.append(f'Embedded images      : {len(images)}')
        for img in images[:15]:
            f.append(f'  Page {img.get("page", "?"):<4} | format: {img.get("format", "?"):<5} '
                     f'| size: {img.get("size", 0):,} bytes')
        if len(images) > 15:
            f.append(f'  ... and {len(images) - 15} more image(s)')
        if images:
            n.append(f'{len(images)} image(s) embedded in PDF '
                     f'(total size not separately accounted for in file entropy).')

        attachments = ev.get('attachments', [])
        f.append(f'File attachments     : {"FOUND" if attachments else "none"}')
        if attachments:
            n.append('⚠ Embedded file attachments detected in PDF — '
                     'examine attachment content separately for malicious or hidden material.')

        js = ev.get('javascript', [])
        f.append(f'JavaScript actions   : {"FOUND" if js else "none"}')
        if js:
            n.append('⚠ JavaScript actions detected in PDF — '
                     'potential security risk or automated behaviour trigger.')

        forms = ev.get('forms', [])
        f.append(f'AcroForm / forms     : {"FOUND" if forms else "none"}')
        if forms:
            n.append('Interactive AcroForm fields present — '
                     'form data may be submitted to a remote server.')
        return f, n

    def _interp_pdf_fonts(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        embedded = ev.get('embedded', [])
        missing  = ev.get('missing', [])
        subsets  = ev.get('subsets', [])
        f.append(f'Embedded fonts ({len(embedded)}): {", ".join(embedded[:10]) or "none"}')
        f.append(f'Non-embedded fonts ({len(missing)}): {", ".join(missing[:10]) or "none"}')
        f.append(f'Subset fonts  ({len(subsets)}): {", ".join(subsets[:10]) or "none"}')
        if missing:
            n.append(f'⚠ {len(missing)} font(s) referenced but not embedded: '
                     f'{", ".join(missing[:5])}. '
                     f'Rendering may differ across viewers; can also indicate text that was '
                     f'replaced without proper font re-embedding.')
        return f, n

    def _interp_security(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        enc  = ev.get('encrypted', False)
        sigs = ev.get('signatures', [])
        perm = ev.get('permissions')
        f.append(f'Encrypted          : {"YES" if enc else "no"}')
        if enc:
            n.append('⚠ PDF is encrypted / password-protected — '
                     'full content analysis is limited to unencrypted structural data.')
        if perm is not None:
            f.append(f'Permission flags   : {perm}')
        f.append(f'Digital signatures : {len(sigs)} found')
        if sigs:
            n.append(f'{len(sigs)} digital signature(s) present — '
                     f'verify signature validity and certificate chain independently.')
        return f, n

    def _interp_pdf_hidden(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        wt = ev.get('white_text', [])
        an = ev.get('annotations', [])
        do = ev.get('deleted_objects', [])

        f.append(f'Near-white text blocks    : {len(wt)}')
        if wt:
            for item in wt[:10]:
                f.append(f'  Page {item.get("page", "?")}: "{item.get("text", "")[:80]}"')
            if len(wt) > 10:
                f.append(f'  ... and {len(wt) - 10} more block(s)')
            n.append(f'⚠ {len(wt)} block(s) of near-white (nearly invisible) text found. '
                     f'This technique is commonly used to hide content from visual review, '
                     f'manipulate OCR output, or stuff keywords for deceptive indexing.')
        else:
            f.append('No near-white hidden text detected.')

        f.append(f'Invisible annotations     : {len(an)}')
        if an:
            for a in an[:5]:
                f.append(f'  Page {a.get("page", "?")}: subtype {a.get("subtype", "?")} (no appearance stream)')
            n.append(f'⚠ {len(an)} annotation(s) with no visible appearance stream — '
                     f'may carry hidden data or metadata.')
        else:
            f.append('No invisible-appearance annotations detected.')

        if do:
            f.append(f'Deleted/orphaned objects  : {do}')
        return f, n

    def _interp_pdf_revision(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        inc = ev.get('incremental_saves', 0)
        f.append(f'Incremental saves : {inc}')
        if inc > 0:
            n.append(f'⚠ PDF has {inc} incremental-save link(s) — '
                     f'the document was re-saved after its initial creation. '
                     f'Content from earlier versions may be recoverable from the file body.')
        else:
            f.append('No incremental-save chain detected.')
        added = ev.get('objects_added', [])
        if added:
            f.append(f'Objects added in incremental save(s): {added}')
        return f, n

    def _interp_pdf_layout(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        pages = ev.get('pages', [])
        f.append(f'Pages analysed      : {len(pages)}')
        for p in pages[:10]:
            nwc = p.get('near_white_text_count', 0)
            f.append(f'  Page {p.get("page", "?"):<3} | '
                     f'text lines: {p.get("text_count", 0):<5} | '
                     f'rectangles: {p.get("rect_count", 0):<5} | '
                     f'near-white items: {nwc}')
            if nwc > 0:
                n.append(f'⚠ Page {p.get("page", "?")}: {nwc} near-white text item(s) detected in layout.')
        margins = ev.get('margins', {})
        if margins:
            f.append(f'First-page margins  — '
                     f'left: {margins.get("left", 0):.1f} | '
                     f'right: {margins.get("right", 0):.1f} | '
                     f'top: {margins.get("top", 0):.1f} | '
                     f'bottom: {margins.get("bottom", 0):.1f}')
        return f, n

    def _interp_jpeg_quantization(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        count = ev.get('tables_found', 0)
        f.append(f'DQT tables found : {count}')
        for t in ev.get('tables', []):
            f.append(f'  Table {t.get("table_id", "?")} | '
                     f'precision: {t.get("precision", "?")} | '
                     f'estimated quality: ~{t.get("estimated_quality", "?")} | '
                     f'mean coeff: {t.get("mean_value", 0):.2f}')
        spread = ev.get('quality_spread')
        if spread is not None:
            f.append(f'Quality spread across tables: {spread:.1f} pts')
        if ev.get('inconsistent_tables'):
            n.append(f'⚠ JPEG quantization tables are inconsistent (quality spread {spread:.0f} pts). '
                     f'This suggests the image was re-saved with a different encoder or at a different '
                     f'quality setting — a common artefact of editing and re-saving.')
        note = ev.get('note')
        if note:
            f.append(f'Note: {note}')
        return f, n

    def _interp_compression_history(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        f.append(f'DCT blocks analysed          : {ev.get("blocks_analyzed", 0):,}')
        f.append(f'Histogram bins (unique AC11) : {ev.get("histogram_bins", 0)}')
        ps = ev.get('periodicity_score', 0.0)
        f.append(f'Histogram periodicity score  : {ps:.5f}  (threshold > 0.35)')
        f.append(f'Method                       : {ev.get("method", "")}')
        if ev.get('double_compression_suspected'):
            n.append(f'⚠ Double-JPEG compression artefact detected (periodicity {ps:.4f}). '
                     f'The AC(1,1) DCT coefficient histogram shows periodic gaps characteristic '
                     f'of quantisation-then-requantisation — a strong signal that the image was '
                     f're-saved at a different quality after an initial JPEG compression.')
        else:
            f.append('No significant double-compression periodicity pattern detected.')
        return f, n

    def _interp_resampling(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        peaks = ev.get('periodic_peak_count', 0)
        ratio = ev.get('peak_ratio', 0.0)
        f.append(f'Periodic FFT peaks above threshold : {peaks:,}')
        f.append(f'Peak ratio (peaks / total spectrum) : {ratio:.7f}  (threshold > 0.0008000)')
        f.append(f'Method                              : {ev.get("method", "")}')
        if ev.get('resampling_suspected'):
            n.append(f'⚠ Resampling artefact detected (peak ratio {ratio:.6f}). '
                     f'Periodic peaks in the second-derivative FFT spectrum indicate the image '
                     f'(or a composited region within it) was geometrically transformed — '
                     f'likely scaled, rotated, or warped — before saving.')
        else:
            f.append('No periodic FFT peaks consistent with resampling detected.')
        return f, n

    def _interp_cfa_consistency(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        f.append(f'Analysis grid               : {ev.get("grid_shape", [])}')
        f.append(f'Mean CFA correlation score  : {ev.get("mean_cfa_score", 0):.5f}  (>0.15 = consistent camera demosaicing)')
        f.append(f'Std dev across blocks       : {ev.get("std_cfa_score", 0):.5f}')
        f.append(f'Block inconsistency ratio   : {ev.get("inconsistency_ratio", 0):.4f}')
        f.append(f'Method                      : {ev.get("method", "")}')
        if ev.get('cfa_absent_or_inconsistent'):
            n.append(f'⚠ CFA demosaicing correlation is weak or absent '
                     f'(mean score {ev.get("mean_cfa_score", 0):.4f}). '
                     f'Genuine camera images carry a characteristic Bayer-interpolation '
                     f'pattern in the green channel; its absence is consistent with '
                     f'AI-generated images, screenshots, or composited regions.')
        else:
            f.append('CFA demosaicing pattern is present — consistent with genuine camera capture.')
        return f, n

    def _interp_prnu_residual(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        f.append(f'Blocks analysed             : {ev.get("blocks_analyzed", 0)}')
        f.append(f'Mean residual energy        : {ev.get("mean_residual_energy", 0):.5f}')
        cv_ = ev.get('residual_energy_cv', 0.0)
        f.append(f'Residual energy CV          : {cv_:.5f}  (threshold > 0.8 = inconsistent)')
        f.append(f'Note                        : {ev.get("note", "")}')
        if ev.get('spatial_inconsistency_suspected'):
            n.append(f'⚠ PRNU residual energy is spatially inconsistent across the image (CV={cv_:.3f}). '
                     f'Regions with markedly different noise residuals suggest content from different '
                     f'capture pipelines has been composited. Full camera attribution requires '
                     f'a reference fingerprint bank of known-source images.')
        else:
            f.append('PRNU residual energy is spatially consistent — no obvious splice boundary detected.')
        return f, n

    def _interp_noise_inconsistency(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        f.append(f'Blocks analysed            : {ev.get("blocks_analyzed", 0)}')
        f.append(f'Median block variance      : {ev.get("median_block_variance", 0):.4f}')
        out_c = ev.get('outlier_block_count', 0)
        out_r = ev.get('outlier_ratio', 0.0)
        f.append(f'Outlier blocks (>6× MAD)   : {out_c}  ({out_r:.2%} of total)')
        f.append(f'Method                     : {ev.get("method", "")}')
        if ev.get('inconsistent_noise_suspected'):
            n.append(f'⚠ Block-wise noise inconsistency detected: {out_c} blocks ({out_r:.1%}) '
                     f'deviate strongly from the image-wide noise median. '
                     f'Isolated regions of very different noise texture are a classic indicator '
                     f'of image splicing, inpainting, or compositing.')
        else:
            f.append('Block noise variance is consistent across the image — no outlier regions.')
        return f, n

    def _interp_advanced_steganalysis(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        f.append(f'4×4 pixel groups analysed  : {ev.get("groups_analyzed", 0):,}')
        f.append(f'RM−SM (positive mask)       : {ev.get("rm_minus_sm", 0):.5f}')
        f.append(f'RM−SM (negative mask)       : {ev.get("rm_minus_sm_negmask", 0):.5f}')
        asym = ev.get('rs_asymmetry', 0.0)
        f.append(f'RS asymmetry               : {asym:.5f}  (threshold > 0.03)')
        f.append(f'Method                     : {ev.get("method", "")}')
        if ev.get('embedding_suspected'):
            n.append(f'⚠ RS steganalysis: asymmetry {asym:.4f} exceeds detection threshold. '
                     f'The Regular/Singular method is substantially more sensitive than chi-square '
                     f'at low embedding rates. This is a statistical signal — it does not reveal '
                     f'payload content or the steganographic tool used.')
        else:
            f.append('RS steganalysis: no significant asymmetry detected.')
        return f, n

    def _interp_copy_move_v2(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        note = ev.get('note')
        f.append(f'Method                   : {ev.get("method", "SIFT + BFMatcher knn + RANSAC")}')
        if note:
            f.append(f'Note                     : {note}')
            return f, n
        f.append(f'Raw SIFT matches (knn)   : {ev.get("raw_match_count", 0)}')
        inliers = ev.get('ransac_inliers', 0)
        f.append(f'RANSAC geometric inliers : {inliers}  (threshold ≥ 8 = detected)')
        if ev.get('detected'):
            n.append(f'⚠ Copy-move detected by SIFT + RANSAC: {inliers} geometrically-verified inliers. '
                     f'RANSAC homography verification dramatically reduces false positives compared '
                     f'to basic ORB self-matching — this is a high-confidence manipulation signal.')
        else:
            f.append('No geometrically-verified copy-move pattern found.')
        return f, n

    def _interp_ela_v2(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        scores  = ev.get('scores_by_quality', {})
        regions = ev.get('region_analysis', {})
        f.append(f'Method : {ev.get("method", "")}')
        f.append('Per-quality ELA results:')
        for q in (60, 75, 90):
            sc  = scores.get(q) or scores.get(str(q))
            reg = regions.get(q) or regions.get(str(q), {})
            if sc is not None:
                f.append(f'  Quality {q:>3} | mean error: {sc:>8.3f} | '
                         f'max block: {reg.get("max_block_mean", 0):>8.2f} | '
                         f'hot-block ratio: {reg.get("hot_block_ratio", 0):.3%}')
        if ev.get('localized_editing_suspected'):
            max_hr = max(
                (regions.get(q) or regions.get(str(q), {})).get('hot_block_ratio', 0)
                for q in (60, 75, 90)
            )
            n.append(f'⚠ Multi-quality ELA: localised hot-spot regions detected '
                     f'(max hot-block ratio {max_hr:.2%}). '
                     f'Blocks that appear bright at multiple quality levels are '
                     f'inconsistently compressed compared to surrounding areas — '
                     f'a strong indicator of a composited or selectively re-saved region.')
        else:
            f.append('No localised ELA hot-spots detected across quality levels.')
        return f, n

    def _interp_ai_generated_heuristics(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        sigs = ev.get('signals', {})
        f.append('Signal measurements:')
        for k, v in sigs.items():
            label = k.replace('_', ' ').title()
            f.append(f'  {label:<35} : {v:.6f}' if isinstance(v, float) else f'  {label}: {v}')
        cnt     = ev.get('indicator_count', 0)
        reasons = ev.get('indicators_triggered', [])
        f.append(f'Indicators triggered : {cnt} / 4  (threshold ≥ 2 = suspected)')
        for r in reasons:
            f.append(f'  ▶ {r}')
        f.append(f'Caveat : {ev.get("confidence_caveat", "")}')
        if ev.get('ai_generated_suspected'):
            n.append(f'⚠ AI-generation heuristics: {cnt}/4 signals indicate the image may not be '
                     f'from a camera. Triggered indicators:')
            for r in reasons:
                n.append(f'   • {r}')
            n.append('   A dedicated trained classifier is required for reliable detection.')
        else:
            f.append('AI-generation heuristics: fewer than 2 signals triggered — '
                     'image characteristics are not inconsistent with camera capture.')
        return f, n

    def _interp_ai_manipulation_heuristic(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        f.append(f'Blocks analysed         : {ev.get("blocks_analyzed", 0)}')
        sc = ev.get('suspect_block_count', 0)
        sr = ev.get('suspect_block_ratio', 0.0)
        f.append(f'Suspect blocks          : {sc}  ({sr:.3%} of total)')
        f.append(f'Method                  : {ev.get("method", "")}')
        f.append(f'Caveat                  : {ev.get("confidence_caveat", "")}')
        if ev.get('localized_ai_edit_suspected'):
            n.append(f'⚠ AI manipulation heuristic: {sr:.2%} of image blocks show BOTH '
                     f'low CFA correlation AND anomalous noise level simultaneously. '
                     f'These co-occurring signals in isolated spatial regions are consistent '
                     f'with AI inpainting or compositing at those locations. '
                     f'Treat as a corroborating signal alongside other extractors.')
        else:
            f.append('No localised AI-manipulation signature detected.')
        return f, n

    def _interp_font_consistency(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        f.append(f'Distinct fonts in document : {ev.get("distinct_fonts", 0)}')
        usage = ev.get('font_usage', {})
        f.append('Font usage (top 10):')
        for font, count in list(usage.items())[:10]:
            f.append(f'  {font:<40}: {count} use(s)')
        f.append(f'Font-size outlier count    : {ev.get("size_outlier_count", 0)}')
        anomalies = ev.get('font_anomalies', [])
        if anomalies:
            f.append(f'Font anomalies detected    : {len(anomalies)}')
            for a in anomalies[:10]:
                f.append(f'  Page {a.get("page", "?")}: '
                         f'minority font "{a.get("minority_font", "?")}" ({a.get("minority_count", 0)}×) '
                         f'vs dominant "{a.get("dominant_font", "?")}" ({a.get("dominant_count", 0)}×)')
        if ev.get('inconsistent_fonts_suspected'):
            n.append(f'⚠ Font consistency: {len(anomalies)} page(s) contain minority fonts that '
                     f'appear only 1–2 times while another font dominates the page. '
                     f'This pattern is consistent with localised text replacement — '
                     f'a word or line inserted using a different font than the surrounding body text.')
        else:
            f.append('Font distribution appears consistent across pages.')
        return f, n

    def _interp_ocr_image_consistency(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        wc = ev.get('word_count', 0)
        f.append(f'Words detected               : {wc}')
        if wc == 0:
            f.append(f'Note: {ev.get("note", "No text detected")}')
            return f, n
        ho = ev.get('height_outlier_count', 0)
        hr = ev.get('height_outlier_ratio', 0.0)
        mc = ev.get('mean_ocr_confidence', 0.0)
        lc = ev.get('low_confidence_ratio', 0.0)
        f.append(f'Glyph-height outliers        : {ho}  ({hr:.3%} of words)')
        f.append(f'Mean OCR confidence          : {mc:.1f}%')
        f.append(f'Low-confidence words (<50%)  : {lc:.3%}')
        f.append(f'Method                       : {ev.get("method", "")}')
        if ev.get('rendering_inconsistency_suspected'):
            n.append(f'⚠ OCR image consistency: '
                     f'glyph-height outlier ratio {hr:.2%}, '
                     f'low-confidence word ratio {lc:.2%}. '
                     f'Unusual glyph sizes or confidence drops in specific words/lines '
                     f'suggest those characters may have been inserted from a different '
                     f'rendering source — a localised editing signal for image-of-text documents.')
        else:
            f.append('OCR consistency: glyph sizes and confidence are uniform — '
                     'no rendering inconsistency detected.')
        return f, n

    # ── Text report formatter ─────────────────────────────────────────────────

    def format_text_report(
        self,
        assessment: Dict[str, Any],
        file_path:  str,
        file_type:  str,
        mime_type:  str,
        timestamp:  str,
        report_id:  Optional[str] = None,
    ) -> str:
        SEP  = '═' * 80
        SEP2 = '─' * 80
        lines: List[str] = []

        lines.append(SEP)
        lines.append('  FORENSIC EVIDENCE REPORT  —  Detailed Direct Output')
        lines.append(f'  Engine: Forensic Engine v8 (Detailed Report Edition)')
        lines.append(SEP)
        lines.append(f'  File      : {file_path}')
        lines.append(f'  Type      : {file_type}  ({mime_type})')
        lines.append(f'  Timestamp : {timestamp}')
        if report_id:
            lines.append(f'  Report ID : {report_id}')
        lines.append(SEP)
        lines.append('')

        # Notable findings summary up front
        notable = assessment.get('all_notable_findings', [])
        lines.append(f'  NOTABLE FINDINGS SUMMARY  ({len(notable)} item(s))')
        lines.append(SEP2)
        if notable:
            for item in notable:
                for sub_line in item.split('\n'):
                    lines.append(f'  {sub_line}')
        else:
            lines.append('  No notable findings — all extractors reported within expected bounds.')
        lines.append('')

        # Per-category detail
        for cat in assessment.get('categories', []):
            label = cat.get('label', cat.get('category', ''))
            lines.append(SEP)
            lines.append(f'  CATEGORY: {label.upper()}')
            lines.append(SEP)
            for ext_entry in cat.get('extractors', []):
                name    = ext_entry.get('extractor', 'unknown')
                version = ext_entry.get('version', '?')
                status  = ext_entry.get('status', 'unknown')
                timing  = ext_entry.get('execution_time_s', 0.0)
                lines.append(f'  ┌─ Extractor: {name}  (v{version})  [{timing:.4f}s]')
                if status == 'unavailable':
                    reason = ext_entry.get('reason', 'unavailable')
                    lines.append(f'  │  STATUS   : UNAVAILABLE — {reason}')
                else:
                    lines.append(f'  │  STATUS   : OK')
                    for finding in ext_entry.get('findings', []):
                        for sub_line in finding.split('\n'):
                            lines.append(f'  │  {sub_line}')
                    nf = ext_entry.get('notable_findings', [])
                    if nf:
                        lines.append(f'  │  ── Notable ──')
                        for item in nf:
                            for sub_line in item.split('\n'):
                                lines.append(f'  │  {sub_line}')
                lines.append('  └' + '─' * 70)
            lines.append('')

        lines.append(SEP)
        lines.append(f'  DISCLAIMER')
        lines.append(SEP2)
        lines.append(f'  {assessment.get("disclaimer", "")}')
        lines.append(SEP)
        return '\n'.join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE, ASSEMBLER, ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class EvidencePipeline:
    def __init__(self, name: str, extractors: List[BaseExtractor]):
        self.name       = name
        self.extractors = extractors

    def run(self, context: ExtractionContext, verbose: bool = False) -> Dict[str, Any]:
        results = []
        for ext in self.extractors:
            if ext.applicable(context):
                log(f'  extractor: {ext.name}', verbose)
                try:
                    results.append(ext.extract(context))
                except Exception as e:
                    results.append({
                        'extractor':      ext.name,
                        'version':        ext.version,
                        'execution_time': 0.0,
                        'confidence':     0.0,
                        'evidence':       {'error': str(e)},
                    })
        return {self.name: results}


class EvidenceAssembler:
    @staticmethod
    def assemble(
        pipeline_results: Dict[str, Any],
        context:          ExtractionContext,
        report_id:        Optional[str] = None,
        user_id:          Optional[str] = None,
    ) -> Dict[str, Any]:
        package: Dict[str, Any] = {
            'report_id': report_id,
            'user_id':   user_id,
            'file_path': context.file_path,
            'file_type': context.file_type,
            'mime_type': context.mime_type,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'evidence':  {},
            'summary': {
                'total_extractors':      0,
                'successful_extractors': 0,
                'total_execution_time':  0.0,
            },
        }
        if context._warning:
            package['warning'] = context._warning

        for category, results in pipeline_results.items():
            package['evidence'][category] = results
            for res in results:
                package['summary']['total_extractors']      += 1
                if res['confidence'] > 0.5:
                    package['summary']['successful_extractors'] += 1
                package['summary']['total_execution_time'] += res['execution_time']

        # Build detailed assessment (no scoring)
        builder = DetailedReportBuilder()
        package['detailed_assessment'] = builder.build(
            package['evidence'], context.file_type
        )
        return package


class ForensicEngine:
    def __init__(self):
        self.pipelines = {
            # ── core pipelines ────────────────────────────────────────────────
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
            # ── v8 pipelines ──────────────────────────────────────────────────
            'quantization': EvidencePipeline('quantization', [
                JPEGQuantizationExtractor(),
                CompressionHistoryExtractor(),
            ]),
            'resampling': EvidencePipeline('resampling', [ResamplingExtractor()]),
            'sensor': EvidencePipeline('sensor', [CFAExtractor(), PRNUExtractor()]),
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
        options = options or RunOptions()
        start   = time.perf_counter()
        with open(file_path, 'rb') as f:
            raw_data = f.read()
        context          = ExtractionContext(file_path, raw_data, options)
        pipeline_results: Dict[str, Any] = {}
        for name, pipeline in self.pipelines.items():
            log(f'pipeline: {name}', options.verbose)
            result = pipeline.run(context, verbose=options.verbose)
            if result[name]:
                pipeline_results.update(result)
        package = EvidenceAssembler.assemble(pipeline_results, context, report_id, user_id)
        package['summary']['engine_execution_time'] = time.perf_counter() - start
        return package


# ---------- Callback ----------
def send_callback(url: str, secret: str, payload: dict):
    data = json.dumps(payload, default=str).encode('utf-8')
    headers = {
        'Content-Type':      'application/json',
        'x-callback-secret': secret,
        'User-Agent':        'forensic-engine/8.0 (+github-actions)',
        'Accept':            'application/json',
    }
    callback_auth = os.getenv('CALLBACK_AUTH')
    if callback_auth:
        headers['Authorization'] = f'Bearer {callback_auth}'
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp_body = resp.read().decode('utf-8', errors='replace')
            print(f'[callback] HTTP {resp.status}: {resp_body[:500]}', file=sys.stderr)
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode('utf-8', errors='replace')
        except Exception:
            err_body = '<no body>'
        print(f'[callback] HTTP error {e.code}: {e.reason}\nBody: {err_body[:1000]}',
              file=sys.stderr)
        sys.exit(0)
    except urllib.error.URLError as e:
        print(f'[callback] URL/connection error: {e.reason}', file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f'[callback] Failed: {type(e).__name__}: {e}', file=sys.stderr)
        sys.exit(0)


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
        print(f'Warning: could not load known-hashes "{path}": {e}', file=sys.stderr)
    return set()


# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(
        description=(
            'Forensic Engine v8 — Detailed Report Edition. '
            '27 extractors across 16 pipelines. '
            'All evidence is shown directly; no aggregate risk score is computed.'
        )
    )
    parser.add_argument('file',              help='Path to file to analyse')
    parser.add_argument('-o', '--output',    help='Output JSON file (default: stdout)')
    parser.add_argument('--pretty',          action='store_true', help='Pretty-print JSON')
    parser.add_argument('--text-report',     action='store_true',
                        help='Also write a human-readable text report. '
                             'Uses --output path with .txt extension, or stdout if no --output.')
    parser.add_argument('--mode',            choices=['light', 'full'], default='full',
                        help='light = skip OCR + clone-detection; full = everything')
    parser.add_argument('--include-images',  action='store_true',
                        help='Embed extracted PDF images as base64 in output')
    parser.add_argument('--pdf-dpi',         type=int, default=PDF_IMAGE_RESOLUTION,
                        help=f'DPI for PDF→image rasterisation (default {PDF_IMAGE_RESOLUTION})')
    parser.add_argument('--known-hashes',    help='JSON file of known sha256 hashes')
    parser.add_argument('--report-id',       help='Report ID to embed in output and callback')
    parser.add_argument('--user-id',         help='User ID to embed in output')
    parser.add_argument('--callback-url',    help='URL to POST results to')
    parser.add_argument('--callback-secret', help='Header secret for callback URL', default='')
    parser.add_argument('-v', '--verbose',   action='store_true', help='Progress to stderr')
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"Error: '{args.file}' not found.", file=sys.stderr)
        if args.callback_url and args.report_id:
            send_callback(args.callback_url, args.callback_secret, {
                'report_id': args.report_id,
                'error':     f'File not found: {args.file}',
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
        package = engine.run(
            args.file, options,
            report_id = args.report_id,
            user_id   = args.user_id,
        )
    except Exception as e:
        if args.callback_url and args.report_id:
            send_callback(args.callback_url, args.callback_secret, {
                'report_id': args.report_id,
                'error':     str(e),
                'report':    None,
            })
        raise

    # ── JSON output ────────────────────────────────────────────────────────
    indent      = 2 if args.pretty else None
    json_output = json.dumps(package, indent=indent, default=str)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(json_output)
        log(f'Wrote JSON report to {args.output}', args.verbose)
    else:
        if not args.text_report:
            print(json_output)

    # ── Optional text report ───────────────────────────────────────────────
    if args.text_report:
        builder = DetailedReportBuilder()
        text_report = builder.format_text_report(
            assessment = package['detailed_assessment'],
            file_path  = package['file_path'],
            file_type  = package['file_type'],
            mime_type  = package['mime_type'],
            timestamp  = package['timestamp'],
            report_id  = args.report_id,
        )
        if args.output:
            txt_path = os.path.splitext(args.output)[0] + '.txt'
            with open(txt_path, 'w') as f:
                f.write(text_report)
            log(f'Wrote text report to {txt_path}', args.verbose)
        else:
            print(text_report)
            if not args.output:
                print('\n' + '─' * 80)
                print('JSON data written to stdout only when --text-report is NOT set '
                      '(or use -o to save both).')

    # ── Callback ────────────────────────────────────────────────────────────
    if args.callback_url and args.report_id:
        send_callback(args.callback_url, args.callback_secret, {
            'report_id': args.report_id,
            'report':    package,
        })


if __name__ == '__main__':
    main()
