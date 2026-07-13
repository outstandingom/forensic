#!/usr/bin/env python3
"""
Forensic Engine v9 – AI-Detection Enhanced Edition
All original v8 layers + 5 new AI-detection extractors with significantly
improved heuristics, weighted confidence scoring, and local/patch analysis.

CHANGES vs v8 Detailed Report Edition:
  - NEW: WaveletConsistencyExtractor    — 4-level Haar wavelet noise-scaling + kurtosis
  - NEW: PowerSpectrumExtractor         — radial PSD slope (1/f^beta) + periodic artifact peaks
  - NEW: JPEGGhostExtractor             — multi-quality ghost detection for spatial manipulation
  - NEW: LocalPatchStatisticsExtractor  — 4×4 grid brightness / texture uniformity
  - NEW: GradientCoherenceExtractor     — gradient orientation entropy + anisotropy
  - IMPROVED: AIGeneratedImageExtractor — 8 weighted signals, adaptive thresholds, 0-1 confidence
  - IMPROVED: AIManipulationExtractor   — 4-signal co-occurrence, spatial clustering, confidence band
  - NEW pipeline: 'ai_detection'        — groups all new AI-focused extractors
  - UPDATED: DetailedReportBuilder      — interpreters for new extractors + cross-extractor AI fusion
  - All original pipelines, extractors, PDF/stego/metadata analysis unchanged.
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
    ndimage = None
    sp_fft  = None

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
PDF_IMAGE_RESOLUTION = 150
STEGO_SAMPLE_PIXELS  = 20_000

_FUTURE_THRESHOLD_DAYS = 1


def log(msg: str, verbose: bool):
    if verbose:
        print(f"[forensic-engine] {msg}", file=sys.stderr)


# ---------- Shared Context ----------
class ExtractionContext:
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
        start      = time.perf_counter()
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
# ORIGINAL EXTRACTORS (unchanged from v8)
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
    name         = "pdf_metadata"
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


# ══════════════════════════════════════════════════════════════════════════════
# v8 EXTRACTORS (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

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


# ══════════════════════════════════════════════════════════════════════════════
# v9 NEW AI-DETECTION EXTRACTORS
# ══════════════════════════════════════════════════════════════════════════════

class WaveletConsistencyExtractor(BaseExtractor):
    """
    4-level Haar wavelet decomposition for AI-generation detection.

    Natural images: HH (diagonal) subbands have heavy-tailed distributions
    (kurtosis >> 3) due to sparse edge energy. Noise energy also scales
    predictably between levels — typically 3–8× reduction per level as edges
    become sparser at coarser scales.

    AI images from diffusion/GAN models often show:
      - Lower HH kurtosis (more Gaussian subbands from denoising pipelines)
      - Inconsistent or shallow inter-level energy ratios (hallucinated
        multi-scale texture fills multiple levels uniformly)
      - Anisotropy (LH ≠ HL energy) from convolutional upsampling grids
    """
    name         = "wavelet_consistency"
    version      = "9.0"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and np is not None

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        gray = np.array(img.convert('L'), dtype=np.float64)

        subbands = []
        current  = gray.copy()
        for level in range(1, 5):
            h, w = current.shape
            if h < 16 or w < 16:
                break
            LL, LH, HL, HH = self._haar_1level(current)
            subbands.append({
                'level':        level,
                'kurtosis_HH':  self._kurtosis(HH.flatten()),
                'kurtosis_LH':  self._kurtosis(LH.flatten()),
                'energy_HH':    float(np.mean(HH ** 2)),
                'energy_LH':    float(np.mean(LH ** 2)),
                'energy_HL':    float(np.mean(HL ** 2)),
                'lh_hl_ratio':  float(np.mean(LH ** 2) / (np.mean(HL ** 2) + 1e-12)),
            })
            current = LL

        if not subbands:
            return {'error': 'Image too small for wavelet analysis'}

        l1_kurtosis = subbands[0]['kurtosis_HH']

        # Inter-level noise energy ratios
        energy_ratios = [
            subbands[i]['energy_HH'] / (subbands[i + 1]['energy_HH'] + 1e-12)
            for i in range(len(subbands) - 1)
        ]
        ratio_mean = float(np.mean(energy_ratios)) if energy_ratios else 0.0
        ratio_cv   = float(np.std(energy_ratios) / (ratio_mean + 1e-9)) if energy_ratios else 0.0

        # LH/HL anisotropy across levels (camera images ≈ isotropic → ratio ≈ 1.0)
        lh_hl_ratios = [s['lh_hl_ratio'] for s in subbands]
        lh_hl_mean   = float(np.mean(lh_hl_ratios))
        anisotropy   = abs(lh_hl_mean - 1.0)

        low_kurtosis     = l1_kurtosis < 3.5
        low_energy_ratio = ratio_mean < 2.5 and len(energy_ratios) >= 2
        high_anisotropy  = anisotropy > 0.40

        return {
            'levels_computed':    len(subbands),
            'subband_stats':      subbands,
            'l1_hh_kurtosis':     float(l1_kurtosis),
            'energy_ratios':      [float(r) for r in energy_ratios],
            'energy_ratio_mean':  float(ratio_mean),
            'energy_ratio_cv':    float(ratio_cv),
            'lh_hl_anisotropy':   float(anisotropy),
            'low_kurtosis':       bool(low_kurtosis),
            'low_energy_ratio':   bool(low_energy_ratio),
            'high_anisotropy':    bool(high_anisotropy),
            'ai_signal_detected': bool(low_kurtosis or low_energy_ratio or high_anisotropy),
            'thresholds': {
                'kurtosis':     3.5,
                'energy_ratio': 2.5,
                'anisotropy':   0.40,
            },
        }

    @staticmethod
    def _haar_1level(img: np.ndarray):
        h, w  = img.shape
        h2, w2 = h - h % 2, w - w % 2
        img   = img[:h2, :w2]
        L     = (img[:, 0::2] + img[:, 1::2]) * 0.5
        H     = (img[:, 0::2] - img[:, 1::2]) * 0.5
        LL    = (L[0::2, :] + L[1::2, :]) * 0.5
        LH    = (L[0::2, :] - L[1::2, :]) * 0.5
        HL    = (H[0::2, :] + H[1::2, :]) * 0.5
        HH    = (H[0::2, :] - H[1::2, :]) * 0.5
        return LL, LH, HL, HH

    @staticmethod
    def _kurtosis(data: np.ndarray) -> float:
        if data.size < 4:
            return 3.0
        mu    = data.mean()
        sigma = data.std() + 1e-9
        return float(np.mean(((data - mu) / sigma) ** 4))


class PowerSpectrumExtractor(BaseExtractor):
    """
    Radially-averaged power spectral density (PSD) analysis.

    Natural images follow a 1/f^beta power law (beta ≈ 2.0–3.0, Ruderman 1994).
    Deviations from this range, plus periodic spectral peaks (from tiled
    convolutional operations) and azimuthal non-uniformity, are indicators
    of AI generation or heavy post-processing.
    """
    name         = "power_spectrum"
    version      = "9.0"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and np is not None and _SCIPY_OK

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        gray = np.array(img.convert('L'), dtype=np.float64)
        h, w = gray.shape
        if h < 64 or w < 64:
            return {'error': 'Image too small for PSD analysis (need ≥ 64×64)'}

        # Hann window to suppress edge artifacts
        wy   = np.hanning(h)
        wx   = np.hanning(w)
        win  = np.outer(wy, wx)
        gray = (gray - gray.mean()) * win

        F    = sp_fft.fft2(gray)
        F    = sp_fft.fftshift(F)
        psd  = np.abs(F) ** 2

        cy, cx = h // 2, w // 2
        profile, freqs = self._radial_average(psd, cy, cx)
        if len(freqs) < 16:
            return {'error': 'Insufficient frequency resolution after radial averaging'}

        n       = len(freqs)
        lo, hi  = n // 8, 3 * n // 4
        log_f   = np.log(np.array(freqs[lo:hi], dtype=np.float64))
        log_p   = np.log(np.array(profile[lo:hi], dtype=np.float64) + 1e-9)
        beta    = float(-np.polyfit(log_f, log_p, 1)[0])

        # Periodic peaks in the high-frequency quarter of the spectrum
        hf_profile  = np.array(profile[3 * n // 4:])
        if hf_profile.size > 4:
            hf_mean = hf_profile.mean()
            hf_std  = hf_profile.std() + 1e-9
            periodic_peaks = int(np.sum(hf_profile > hf_mean + 3.0 * hf_std))
        else:
            periodic_peaks = 0

        # Azimuthal coefficient of variation at a mid-frequency ring
        azimuthal_cv = self._azimuthal_cv(psd, cy, cx, ring_r=min(cy, cx) // 4)

        beta_anomaly     = beta < 1.4 or beta > 4.2
        high_periodicity = periodic_peaks > 5
        high_azimuthal   = azimuthal_cv > 0.60
        ai_signal        = (beta_anomaly or high_periodicity) and high_azimuthal

        return {
            'spectral_beta':           float(beta),
            'beta_expected_range':     [1.4, 4.2],
            'beta_anomaly':            bool(beta_anomaly),
            'periodic_hf_peaks':       int(periodic_peaks),
            'azimuthal_cv':            float(azimuthal_cv),
            'high_azimuthal_variance': bool(high_azimuthal),
            'high_freq_periodicity':   bool(high_periodicity),
            'ai_signal_detected':      bool(ai_signal),
        }

    @staticmethod
    def _radial_average(psd, cy, cx):
        h, w   = psd.shape
        max_r  = min(cy, cx, h - cy, w - cx)
        y, x   = np.ogrid[:h, :w]
        r_map  = np.sqrt((y - cy)**2 + (x - cx)**2).astype(int)
        profile, freqs = [], []
        for r in range(1, max_r):
            mask = (r_map == r)
            if mask.sum() > 0:
                profile.append(float(psd[mask].mean()))
                freqs.append(r)
        return profile, freqs

    @staticmethod
    def _azimuthal_cv(psd, cy, cx, ring_r: int) -> float:
        h, w  = psd.shape
        y, x  = np.ogrid[:h, :w]
        r_map = np.sqrt((y - cy)**2 + (x - cx)**2)
        ring  = psd[(r_map >= ring_r) & (r_map < ring_r + 4)]
        if ring.size < 8:
            return 0.0
        mean_ = ring.mean() + 1e-9
        return float(ring.std() / mean_)


class JPEGGhostExtractor(BaseExtractor):
    """
    JPEG Ghost detection (Farid 2009) for spatial manipulation.

    When a region is pasted from a JPEG with a different original quality,
    re-compressing the composite image at the original quality of the
    background yields minimal error everywhere except in the pasted region.
    Scanning multiple quality levels produces a 'ghost quality map'; spatial
    inconsistency in this map is a strong manipulation indicator.
    """
    name           = "jpeg_ghost"
    version        = "9.0"
    dependencies   = ['get_decoded_image']
    QUALITY_LEVELS = (50, 65, 75, 85, 95)
    BLOCK_SIZE     = 32

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and Image is not None and np is not None

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        rgb      = img.convert('RGB')
        gray_arr = np.array(rgb.convert('L'), dtype=np.float64)
        h, w     = gray_arr.shape
        block    = self.BLOCK_SIZE

        if h < block * 4 or w < block * 4:
            return {'error': 'Image too small for JPEG ghost analysis (need ≥ 128×128)'}

        # Build per-quality difference maps
        diff_maps = {}
        for q in self.QUALITY_LEVELS:
            buf = io.BytesIO()
            rgb.save(buf, 'JPEG', quality=q)
            buf.seek(0)
            recomp         = np.array(Image.open(buf).convert('L'), dtype=np.float64)
            diff_maps[q]   = np.abs(gray_arr - recomp)

        # Per-block ghost quality assignment
        block_ghosts = []
        for by in range(0, h - block, block):
            for bx in range(0, w - block, block):
                block_diffs = {
                    q: diff_maps[q][by:by + block, bx:bx + block].mean()
                    for q in self.QUALITY_LEVELS
                }
                block_ghosts.append(min(block_diffs, key=block_diffs.get))

        ghost_counter    = Counter(block_ghosts)
        dominant_q       = ghost_counter.most_common(1)[0][0]
        total_blocks     = len(block_ghosts)
        inconsistent     = sum(1 for g in block_ghosts if g != dominant_q)
        inconsistency_r  = inconsistent / total_blocks
        ghost_std        = float(np.std(block_ghosts))

        manipulation_suspected = inconsistency_r > 0.12 and ghost_std > 8.0

        return {
            'qualities_tested':        list(self.QUALITY_LEVELS),
            'blocks_analyzed':         total_blocks,
            'dominant_ghost_quality':  int(dominant_q),
            'inconsistent_blocks':     inconsistent,
            'inconsistency_ratio':     float(inconsistency_r),
            'ghost_quality_std':       float(ghost_std),
            'ghost_distribution':      {int(k): v for k, v in ghost_counter.items()},
            'manipulation_suspected':  bool(manipulation_suspected),
            'method':                  'Farid (2009) JPEG Ghost — block-level minimum recompression error',
            'thresholds': {
                'inconsistency_ratio': 0.12,
                'ghost_quality_std':   8.0,
            },
        }


class LocalPatchStatisticsExtractor(BaseExtractor):
    """
    4×4 grid local statistical analysis for uniformity anomalies.

    Natural images show high inter-patch variability: bright sky, dark
    shadows, and textured areas differ strongly in brightness AND in
    high-frequency (texture) content. AI generators tend to produce
    images with more uniformly distributed statistics — a telltale sign
    of synthesised content or AI-inpainting over a large region.
    """
    name         = "local_patch_statistics"
    version      = "9.0"
    dependencies = ['get_decoded_image']
    GRID         = 4

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and np is not None and cv2 is not None

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        gray = np.array(img.convert('L'), dtype=np.float64)
        h, w = gray.shape
        g    = self.GRID
        ph   = h // g
        pw   = w // g
        if ph < 16 or pw < 16:
            return {'error': 'Image too small for patch analysis'}

        patches, means, stds, hf_vars = [], [], [], []

        for row in range(g):
            for col in range(g):
                patch = gray[row * ph:(row + 1) * ph, col * pw:(col + 1) * pw]
                m     = float(patch.mean())
                s     = float(patch.std())
                flat  = patch.flatten()
                mu    = flat.mean()
                sig   = flat.std() + 1e-9
                sk    = float(np.mean(((flat - mu) / sig) ** 3))
                ku    = float(np.mean(((flat - mu) / sig) ** 4))
                hfv   = float(cv2.Laplacian(patch, cv2.CV_64F).var())

                patches.append({
                    'row': row, 'col': col,
                    'mean': m, 'std': s,
                    'skewness': sk, 'kurtosis': ku,
                    'hf_variance': hfv,
                })
                means.append(m)
                stds.append(s)
                hf_vars.append(hfv)

        mean_arr       = np.array(means)
        hf_arr         = np.array(hf_vars)
        brightness_cv  = float(mean_arr.std() / (mean_arr.mean() + 1e-9))
        texture_cv     = float(hf_arr.std() / (hf_arr.mean() + 1e-9))
        hf_mu          = hf_arr.mean()
        hf_sig         = hf_arr.std() + 1e-9
        hf_kurtosis    = float(np.mean(((hf_arr - hf_mu) / hf_sig) ** 4))

        low_brightness_cv = brightness_cv < 0.25
        low_texture_cv    = texture_cv    < 0.40
        low_hf_kurtosis   = hf_kurtosis   < 3.0
        ai_signal         = (low_brightness_cv and low_texture_cv) or \
                            (low_hf_kurtosis and low_texture_cv)

        return {
            'grid_size':            f'{g}×{g}',
            'patches_analyzed':     len(patches),
            'patch_stats':          patches,
            'brightness_cv':        float(brightness_cv),
            'texture_cv':           float(texture_cv),
            'hf_variance_kurtosis': float(hf_kurtosis),
            'low_brightness_cv':    bool(low_brightness_cv),
            'low_texture_cv':       bool(low_texture_cv),
            'low_hf_kurtosis':      bool(low_hf_kurtosis),
            'ai_signal_detected':   bool(ai_signal),
            'thresholds': {
                'brightness_cv': 0.25,
                'texture_cv':    0.40,
                'hf_kurtosis':   3.0,
            },
        }


class GradientCoherenceExtractor(BaseExtractor):
    """
    Gradient orientation entropy and anisotropy analysis.

    Real photographs have sparse, structured gradient fields — strong edges
    concentrate at a few dominant orientations (horizontal floors, vertical
    walls, diagonal edges). AI-generated images often exhibit:
      - Higher orientation entropy (more isotropic gradient distribution)
        caused by hallucinated fine textures spread uniformly
      - Lower dominant-orientation concentration
      - Sometimes periodic gradient patterns from convolutional upsampling
    """
    name         = "gradient_coherence"
    version      = "9.0"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and np is not None and cv2 is not None

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        gray = np.array(img.convert('L'), dtype=np.float32)

        gx   = cv2.Sobel(gray, cv2.CV_32F, 1, 0, ksize=3)
        gy   = cv2.Sobel(gray, cv2.CV_32F, 0, 1, ksize=3)
        mag  = np.sqrt(gx**2 + gy**2)

        # Use only the top 20% strongest gradient pixels
        thresh_ = np.percentile(mag, 80)
        strong  = mag > thresh_
        if strong.sum() < 100:
            return {'error': 'Insufficient strong-gradient pixels'}

        ori_dir = np.mod(np.arctan2(gy[strong], gx[strong]), np.pi)
        hist, _ = np.histogram(ori_dir, bins=36, range=(0, np.pi), density=True)
        hist    = hist / (hist.sum() + 1e-9)
        entropy = float(-np.sum(hist * np.log2(hist + 1e-12)))
        max_ent = math.log2(36)
        norm_e  = float(entropy / max_ent)

        # Dominant orientation: power in the top-3 bins
        top3_power = float(np.sort(hist)[::-1][:3].sum())

        # Block-level gradient magnitude CV (high = heterogeneous = more natural)
        block  = 32
        h, w   = gray.shape
        bv     = [
            float(mag[by:by + block, bx:bx + block].mean())
            for by in range(0, h - block, block)
            for bx in range(0, w - block, block)
        ]
        bv_arr   = np.array(bv) if bv else np.array([0.0])
        block_cv = float(bv_arr.std() / (bv_arr.mean() + 1e-9))

        high_ent  = norm_e > 0.82
        low_conc  = top3_power < 0.25
        ai_signal = high_ent and low_conc

        return {
            'orientation_entropy_bits':   float(entropy),
            'orientation_entropy_norm':   float(norm_e),
            'top3_orientation_power':     float(top3_power),
            'gradient_block_cv':          float(block_cv),
            'strong_pixels_used':         int(strong.sum()),
            'high_orientation_entropy':   bool(high_ent),
            'low_dominant_orientation':   bool(low_conc),
            'ai_signal_detected':         bool(ai_signal),
            'thresholds': {
                'norm_entropy': 0.82,
                'top3_power':   0.25,
            },
        }


# ══════════════════════════════════════════════════════════════════════════════
# v9 IMPROVED AI EXTRACTORS (replace v8 versions, same class names)
# ══════════════════════════════════════════════════════════════════════════════

class AIGeneratedImageExtractor(BaseExtractor):
    """
    Improved AI-generation detection with 8 weighted heuristic signals.

    v8 used 4 binary signals equally. v9 uses 8 weighted signals with
    adaptive thresholds and a continuous confidence score (0–1).

    Signal weights (total = 11.0):
      wavelet_kurtosis       2.0   — HH subband kurtosis (heavy tail = camera)
      power_spectrum         2.0   — 1/f^beta slope anomaly
      local_variance_cv      1.5   — block-variance coefficient of variation
      shot_noise_absent      1.5   — noise should scale with brightness (cameras)
      gradient_uniformity    1.0   — orientation entropy too uniform = AI
      hf_autocorrelation     1.5   — spatially correlated HF residual = upsampled
      channel_hf_corr        1.0   — channels too correlated at HF = joint synthesis
      saturation_entropy     0.5   — saturation distribution outside normal range

    ai_generated_suspected when confidence (score / 11.0) ≥ 0.27
    (roughly equivalent to 2–3 medium-weight signals firing together).

    CAVEAT: Modern diffusion models (2025–2026) defeat many of these tests.
    Use a dedicated trained classifier for production-grade detection.
    """
    name         = "ai_generated_heuristics"
    version      = "9.0"
    dependencies = ['get_decoded_image']

    WEIGHTS      = {
        'wavelet_kurtosis':      2.0,
        'power_spectrum':        2.0,
        'local_variance_cv':     1.5,
        'shot_noise_absent':     1.5,
        'gradient_uniformity':   1.0,
        'hf_autocorrelation':    1.5,
        'channel_hf_corr':       1.0,
        'saturation_entropy':    0.5,
    }
    AI_THRESHOLD = 0.27

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and np is not None and cv2 is not None

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}

        gray = np.array(img.convert('L'), dtype=np.float64)
        rgb  = np.array(img.convert('RGB'), dtype=np.float64)

        raw_signals = {
            'wavelet_kurtosis':    self._sig_wavelet_kurtosis(gray),
            'power_spectrum':      self._sig_power_spectrum(gray),
            'local_variance_cv':   self._sig_local_variance_cv(gray),
            'shot_noise_absent':   self._sig_shot_noise(gray),
            'gradient_uniformity': self._sig_gradient_uniformity(gray),
            'hf_autocorrelation':  self._sig_hf_autocorrelation(gray),
            'channel_hf_corr':     self._sig_channel_hf_corr(rgb),
            'saturation_entropy':  self._sig_saturation_entropy(img),
        }

        total_w    = sum(self.WEIGHTS.values())
        score      = 0.0
        triggered  = []
        details    = {}

        for name, sig in raw_signals.items():
            w = self.WEIGHTS[name]
            if sig.get('triggered', False):
                score += w
                triggered.append(f'[{name}] {sig.get("reason", "")}')
            details[name] = {
                'value':     sig.get('value'),
                'threshold': sig.get('threshold'),
                'triggered': sig.get('triggered', False),
                'weight':    w,
                'reason':    sig.get('reason', ''),
            }

        confidence   = score / total_w
        ai_suspected = confidence >= self.AI_THRESHOLD

        return {
            'signal_details':         details,
            'weighted_score':         float(score),
            'max_possible_score':     float(total_w),
            'confidence':             float(confidence),
            'signals_triggered':      len(triggered),
            'signals_total':          len(raw_signals),
            'triggered_descriptions': triggered,
            'ai_generated_suspected': bool(ai_suspected),
            'confidence_threshold':   self.AI_THRESHOLD,
            'confidence_caveat': (
                'Heuristic weighted scoring. Modern diffusion models (2025–2026) can '
                'evade many statistical tests. Use a trained classifier for production-grade detection.'
            ),
        }

    # ── Signal implementations ────────────────────────────────────────────────

    def _sig_wavelet_kurtosis(self, gray: np.ndarray) -> Dict:
        try:
            h, w  = gray.shape
            h2, w2 = h - h % 2, w - w % 2
            g     = gray[:h2, :w2]
            H     = (g[:, 0::2] - g[:, 1::2]) * 0.5
            HH    = (H[0::2, :] - H[1::2, :]) * 0.5
            flat  = HH.flatten()
            mu    = flat.mean(); sigma = flat.std() + 1e-9
            kurt  = float(np.mean(((flat - mu) / sigma) ** 4))
            thresh = 3.5
            t      = kurt < thresh
            return {
                'value': kurt, 'threshold': thresh, 'triggered': t,
                'reason': f'Level-1 HH kurtosis {kurt:.2f} < {thresh} '
                          f'(low heavy-tail — AI textures tend toward Gaussian HH subbands)',
            }
        except Exception as e:
            return {'value': None, 'threshold': 3.5, 'triggered': False, 'reason': f'Error: {e}'}

    def _sig_power_spectrum(self, gray: np.ndarray) -> Dict:
        if not _SCIPY_OK:
            return {'value': None, 'threshold': None, 'triggered': False, 'reason': 'scipy unavailable'}
        try:
            h, w = gray.shape
            if h < 64 or w < 64:
                return {'value': None, 'threshold': None, 'triggered': False, 'reason': 'image too small'}
            win  = np.outer(np.hanning(h), np.hanning(w))
            g    = (gray - gray.mean()) * win
            F    = sp_fft.fftshift(sp_fft.fft2(g))
            psd  = np.abs(F) ** 2
            cy, cx = h // 2, w // 2
            y, x   = np.ogrid[:h, :w]
            r_map  = np.sqrt((y - cy)**2 + (x - cx)**2).astype(int)
            max_r  = min(cy, cx)
            profile = [float(psd[r_map == r].mean())
                       for r in range(1, max_r) if (r_map == r).sum() > 0]
            n        = len(profile)
            lo, hi   = n // 8, 3 * n // 4
            freqs_sl = list(range(1, n + 1))[lo:hi]
            prof_sl  = profile[lo:hi]
            beta     = float(-np.polyfit(np.log(freqs_sl), np.log(np.array(prof_sl) + 1e-9), 1)[0])
            t        = beta < 1.4 or beta > 4.2
            return {
                'value': beta, 'threshold': [1.4, 4.2], 'triggered': t,
                'reason': f'Spectral beta={beta:.2f} outside expected range [1.4, 4.2]',
            }
        except Exception as e:
            return {'value': None, 'threshold': [1.4, 4.2], 'triggered': False, 'reason': f'Error: {e}'}

    def _sig_local_variance_cv(self, gray: np.ndarray) -> Dict:
        try:
            block  = 32
            h, w   = gray.shape
            variances = [
                float(gray[by:by + block, bx:bx + block].var())
                for by in range(0, h - block, block)
                for bx in range(0, w - block, block)
            ]
            if len(variances) < 9:
                return {'value': None, 'threshold': 0.50, 'triggered': False, 'reason': 'too few blocks'}
            arr  = np.array(variances)
            cv_  = float(arr.std() / (arr.mean() + 1e-9))
            t    = cv_ < 0.50
            return {
                'value': cv_, 'threshold': 0.50, 'triggered': t,
                'reason': f'Block-variance CV={cv_:.3f} < 0.50 '
                          f'(suspiciously uniform texture distribution across image)',
            }
        except Exception as e:
            return {'value': None, 'threshold': 0.50, 'triggered': False, 'reason': f'Error: {e}'}

    def _sig_shot_noise(self, gray: np.ndarray) -> Dict:
        """
        Camera images: noise variance ∝ brightness (Poisson/shot noise).
        AI images: noise typically uniform across brightness levels.
        """
        try:
            g_u8     = gray.astype(np.uint8)
            denoised = cv2.fastNlMeansDenoising(g_u8, h=6).astype(np.float64)
            residual = gray - denoised
            flat_g   = gray.flatten()
            flat_r   = residual.flatten()
            q_edges  = np.percentile(flat_g, [0, 20, 40, 60, 80, 100])
            vars_q   = []
            for i in range(5):
                mask = (flat_g >= q_edges[i]) & (flat_g < q_edges[i + 1])
                if mask.sum() > 50:
                    vars_q.append(float(flat_r[mask].var()))
            if len(vars_q) < 3:
                return {'value': None, 'threshold': 0.15, 'triggered': False, 'reason': 'insufficient brightness range'}
            x             = np.arange(len(vars_q), dtype=np.float64)
            y             = np.array(vars_q)
            slope_norm    = float(np.polyfit(x, y, 1)[0] / (np.mean(y) + 1e-9)) if y.std() > 1e-9 else 0.0
            t             = slope_norm < 0.15
            return {
                'value': slope_norm, 'threshold': 0.15, 'triggered': t,
                'reason': f'Brightness-noise slope ratio {slope_norm:.3f} < 0.15 '
                          f'(noise does not scale with brightness — absent shot noise)',
            }
        except Exception as e:
            return {'value': None, 'threshold': 0.15, 'triggered': False, 'reason': f'Error: {e}'}

    def _sig_gradient_uniformity(self, gray: np.ndarray) -> Dict:
        try:
            g32  = gray.astype(np.float32)
            gx   = cv2.Sobel(g32, cv2.CV_32F, 1, 0, ksize=3)
            gy   = cv2.Sobel(g32, cv2.CV_32F, 0, 1, ksize=3)
            mag  = np.sqrt(gx**2 + gy**2)
            thr  = np.percentile(mag, 80)
            strong = mag > thr
            if strong.sum() < 100:
                return {'value': None, 'threshold': 0.82, 'triggered': False, 'reason': 'insufficient gradient pixels'}
            ori_dir = np.mod(np.arctan2(gy[strong], gx[strong]), np.pi)
            hist, _ = np.histogram(ori_dir, bins=36, range=(0, np.pi), density=True)
            hist    = hist / (hist.sum() + 1e-9)
            ent     = float(-np.sum(hist * np.log2(hist + 1e-12)))
            norm_e  = ent / math.log2(36)
            t       = norm_e > 0.82
            return {
                'value': norm_e, 'threshold': 0.82, 'triggered': t,
                'reason': f'Gradient orientation entropy {norm_e:.3f} > 0.82 '
                          f'(isotropic gradient field — AI-hallucinated texture)',
            }
        except Exception as e:
            return {'value': None, 'threshold': 0.82, 'triggered': False, 'reason': f'Error: {e}'}

    def _sig_hf_autocorrelation(self, gray: np.ndarray) -> Dict:
        """
        Camera noise: spatially uncorrelated (white). Upsampled AI: correlated (band-limited).
        """
        try:
            blur  = cv2.GaussianBlur(gray.astype(np.float32), (5, 5), 0).astype(np.float64)
            res   = gray - blur
            r_h   = float(np.corrcoef(res[:-1, :].flatten(), res[1:, :].flatten())[0, 1])
            r_v   = float(np.corrcoef(res[:, :-1].flatten(), res[:, 1:].flatten())[0, 1])
            mean_ac = (abs(r_h) + abs(r_v)) / 2.0
            t       = mean_ac > 0.18
            return {
                'value': mean_ac, 'threshold': 0.18, 'triggered': t,
                'reason': f'HF residual lag-1 autocorrelation {mean_ac:.4f} > 0.18 '
                          f'(spatially correlated noise — consistent with convolutional upsampling)',
            }
        except Exception as e:
            return {'value': None, 'threshold': 0.18, 'triggered': False, 'reason': f'Error: {e}'}

    def _sig_channel_hf_corr(self, rgb: np.ndarray) -> Dict:
        """
        Camera: colour-specific noise → lower cross-channel HF correlation.
        AI: channels synthesised jointly → often higher HF correlation.
        """
        try:
            hf_ch = []
            for c in range(3):
                ch   = rgb[:, :, c].astype(np.float64)
                blur = cv2.GaussianBlur(ch.astype(np.float32), (5, 5), 0).astype(np.float64)
                hf_ch.append((ch - blur).flatten())
            n      = min(20_000, len(hf_ch[0]))
            idx    = np.random.choice(len(hf_ch[0]), size=n, replace=False)
            rg     = float(np.corrcoef(hf_ch[0][idx], hf_ch[1][idx])[0, 1])
            rb     = float(np.corrcoef(hf_ch[0][idx], hf_ch[2][idx])[0, 1])
            mean_c = (abs(rg) + abs(rb)) / 2.0
            t      = mean_c > 0.75
            return {
                'value': mean_c, 'threshold': 0.75, 'triggered': t,
                'reason': f'Cross-channel HF correlation {mean_c:.4f} > 0.75 '
                          f'(channels too correlated at high frequencies — joint AI synthesis signal)',
            }
        except Exception as e:
            return {'value': None, 'threshold': 0.75, 'triggered': False, 'reason': f'Error: {e}'}

    def _sig_saturation_entropy(self, img) -> Dict:
        try:
            # Manual RGB→HSV to avoid Pillow mode issues
            rgb_f = np.array(img.convert('RGB'), dtype=np.float64) / 255.0
            r, g, b   = rgb_f[:,:,0], rgb_f[:,:,1], rgb_f[:,:,2]
            cmax  = np.maximum(np.maximum(r, g), b)
            cmin  = np.minimum(np.minimum(r, g), b)
            delta = cmax - cmin
            sat   = np.where(cmax > 1e-9, delta / cmax, 0.0)
            hist, _ = np.histogram(sat, bins=32, range=(0, 1), density=True)
            hist    = hist / (hist.sum() + 1e-9)
            ent     = float(-np.sum(hist * np.log2(hist + 1e-12)))
            norm_e  = ent / math.log2(32)
            lo, hi  = 0.55, 0.95
            t       = norm_e < lo or norm_e > hi
            return {
                'value': norm_e, 'threshold': [lo, hi], 'triggered': t,
                'reason': f'Saturation entropy {norm_e:.3f} outside normal range [{lo}, {hi}]',
            }
        except Exception as e:
            return {'value': None, 'threshold': [0.55, 0.95], 'triggered': False, 'reason': f'Error: {e}'}


class AIManipulationExtractor(BaseExtractor):
    """
    Improved localised AI manipulation detection using 4-signal co-occurrence.

    Each 32×32 block is assessed against 4 signals:
      1. Laplacian noise variance outlier (MAD-based)
      2. CFA demosaicing correlation outlier (too low = no camera pattern)
      3. Canny edge density outlier (too sharp/smooth for its neighbourhood)
      4. Local luminance entropy outlier

    Blocks where ≥ 2 signals fire simultaneously are flagged as suspect.
    Spatial clustering (scipy ndimage.label) distinguishes coherent
    manipulated regions from isolated false positives — coherent regions
    of ≥ 4 contiguous suspect blocks are much stronger evidence.

    A continuous confidence score (0–1) is reported alongside a binary flag.
    """
    name         = "ai_manipulation_heuristic"
    version      = "9.0"
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

        if h < block * 4 or w < block * 4:
            return {'error': 'Image too small for block analysis (need ≥ 128×128)'}

        noise_vars  = []
        cfa_scores  = []
        edge_dens   = []
        entropies   = []
        rows_g      = list(range(0, h - block, block))
        cols_g      = list(range(0, w - block, block))

        for by in rows_g:
            for bx in cols_g:
                gray_b  = gray[by:by + block, bx:bx + block]
                rgb_b   = rgb[by:by + block, bx:bx + block, :]

                noise_vars.append(float(cv2.Laplacian(gray_b, cv2.CV_32F).var()))
                cfa_scores.append(CFAExtractor._cfa_score(rgb_b))

                edges = cv2.Canny(gray_b.astype(np.uint8), 50, 150)
                edge_dens.append(float(edges.mean()) / 255.0)

                hist_b, _ = np.histogram(gray_b, bins=8, range=(0, 255))
                hist_b    = hist_b / (hist_b.sum() + 1e-9)
                entropies.append(float(-np.sum(hist_b * np.log2(hist_b + 1e-12))))

        if not noise_vars:
            return {'error': 'No blocks extracted'}

        n_arr = np.array(noise_vars)
        c_arr = np.array(cfa_scores)
        e_arr = np.array(edge_dens)
        h_arr = np.array(entropies)

        def mad_bounds(arr, k=4.0):
            med = np.median(arr)
            mad = np.median(np.abs(arr - med)) + 1e-9
            return med - k * mad, med + k * mad

        n_lo, n_hi = mad_bounds(n_arr)
        c_lo, _    = mad_bounds(c_arr, 3.0)
        e_lo, e_hi = mad_bounds(e_arr)
        h_lo, h_hi = mad_bounds(h_arr)

        noise_anom = (n_arr < n_lo) | (n_arr > n_hi)
        cfa_anom   = c_arr < max(float(c_lo), 0.05)
        edge_anom  = (e_arr < e_lo) | (e_arr > e_hi)
        ent_anom   = (h_arr < h_lo) | (h_arr > h_hi)

        anomaly_ct = (noise_anom.astype(int) + cfa_anom.astype(int) +
                      edge_anom.astype(int) + ent_anom.astype(int))
        suspect       = anomaly_ct >= 2
        suspect_ratio = float(suspect.sum() / len(suspect))

        # Spatial clustering
        large_clusters = 0
        n_clusters_total = 0
        nr, nc = len(rows_g), len(cols_g)
        if nr * nc == len(suspect) and _SCIPY_OK:
            suspect_grid = suspect.reshape(nr, nc)
            labeled, n_clusters_total = ndimage.label(suspect_grid)
            cluster_sizes  = [(labeled == i).sum() for i in range(1, n_clusters_total + 1)]
            large_clusters = sum(1 for s in cluster_sizes if s >= 4)

        base_conf    = min(1.0, suspect_ratio / 0.10)
        cluster_bon  = min(0.30, large_clusters * 0.10)
        confidence   = min(1.0, base_conf + cluster_bon)
        ai_suspected = suspect_ratio > 0.05 or large_clusters >= 2

        return {
            'blocks_analyzed':             len(noise_vars),
            'suspect_block_count':         int(suspect.sum()),
            'suspect_block_ratio':         float(suspect_ratio),
            'noise_anomaly_count':         int(noise_anom.sum()),
            'cfa_anomaly_count':           int(cfa_anom.sum()),
            'edge_anomaly_count':          int(edge_anom.sum()),
            'entropy_anomaly_count':       int(ent_anom.sum()),
            'coherent_suspect_clusters':   int(large_clusters),
            'total_suspect_clusters':      int(n_clusters_total),
            'detection_confidence':        float(confidence),
            'localized_ai_edit_suspected': bool(ai_suspected),
            'method': (
                'Multi-signal co-occurrence (noise + CFA + edge-density + entropy) '
                '+ spatial cluster analysis — 4-signal MAD outlier detection'
            ),
            'confidence_caveat': (
                'Heuristic corroborating signal. Combine with wavelet, ELA, and '
                'power-spectrum results for stronger conclusions.'
            ),
        }


# ══════════════════════════════════════════════════════════════════════════════
# DETAILED REPORT BUILDER (v9 — updated with new interpreters + AI fusion)
# ══════════════════════════════════════════════════════════════════════════════

class DetailedReportBuilder:
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
        'ai_detection':         'AI Generation & Manipulation Detection',
        'ai_fusion':            'AI Detection — Cross-Extractor Synthesis',
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

        # Cross-extractor AI fusion (images only)
        if file_type == 'image':
            fusion = self._ai_fusion(evidence)
            if fusion['signals_found'] > 0:
                all_notable.extend(fusion['notable_findings'])
                categories.append({
                    'category':   'ai_fusion',
                    'label':      self.CATEGORY_LABELS['ai_fusion'],
                    'extractors': [{
                        'extractor':        'ai_fusion_synthesis',
                        'version':          '9.0',
                        'status':           'ok',
                        'execution_time_s': 0.0,
                        'findings':         fusion['findings'],
                        'notable_findings': fusion['notable_findings'],
                        'raw_evidence':     fusion,
                    }],
                })

        return {
            'categories':           categories,
            'all_notable_findings': all_notable,
            'total_notable':        len(all_notable),
            'disclaimer': (
                'All findings are the direct output of each extractor — '
                'no aggregate scoring is applied. '
                'Results should be reviewed by a qualified examiner in context.'
            ),
        }

    # ── Cross-extractor AI fusion ─────────────────────────────────────────────

    def _ai_fusion(self, evidence: Dict) -> Dict:
        """Collect AI-related signals across all extractors and synthesise."""
        sigs: Dict[str, Dict] = {}

        for cat_key, results in evidence.items():
            for res in results:
                name = res.get('extractor', '')
                ev   = res.get('evidence', {})
                if res.get('confidence', 0.0) == 0.0 or 'error' in ev:
                    continue

                if name == 'ai_generated_heuristics':
                    sigs['main'] = {
                        'confidence': ev.get('confidence', 0.0),
                        'triggered':  ev.get('signals_triggered', 0),
                        'total':      ev.get('signals_total', 0),
                        'suspected':  ev.get('ai_generated_suspected', False),
                    }
                elif name == 'ai_manipulation_heuristic':
                    sigs['manipulation'] = {
                        'suspect_ratio':   ev.get('suspect_block_ratio', 0.0),
                        'clusters':        ev.get('coherent_suspect_clusters', 0),
                        'confidence':      ev.get('detection_confidence', 0.0),
                        'suspected':       ev.get('localized_ai_edit_suspected', False),
                    }
                elif name == 'wavelet_consistency':
                    sigs['wavelet'] = {
                        'kurtosis': ev.get('l1_hh_kurtosis', 99.0),
                        'signal':   ev.get('ai_signal_detected', False),
                    }
                elif name == 'power_spectrum':
                    sigs['spectrum'] = {
                        'beta':   ev.get('spectral_beta', 2.5),
                        'signal': ev.get('ai_signal_detected', False),
                    }
                elif name == 'jpeg_ghost':
                    sigs['ghost'] = {
                        'inconsistency': ev.get('inconsistency_ratio', 0.0),
                        'suspected':     ev.get('manipulation_suspected', False),
                    }
                elif name == 'local_patch_statistics':
                    sigs['patch'] = {
                        'brightness_cv': ev.get('brightness_cv', 1.0),
                        'texture_cv':    ev.get('texture_cv', 1.0),
                        'signal':        ev.get('ai_signal_detected', False),
                    }
                elif name == 'gradient_coherence':
                    sigs['gradient'] = {
                        'entropy': ev.get('orientation_entropy_norm', 0.0),
                        'signal':  ev.get('ai_signal_detected', False),
                    }
                elif name == 'cfa_consistency':
                    sigs['cfa'] = {
                        'absent':     ev.get('cfa_absent_or_inconsistent', False),
                        'mean_score': ev.get('mean_cfa_score', 1.0),
                    }
                elif name == 'ela_v2':
                    sigs['ela'] = {
                        'local_edit': ev.get('localized_editing_suspected', False),
                    }
                elif name == 'resampling':
                    sigs['resampling'] = {
                        'suspected': ev.get('resampling_suspected', False),
                    }
                elif name == 'noise_inconsistency':
                    sigs['noise_inc'] = {
                        'suspected': ev.get('inconsistent_noise_suspected', False),
                    }

        # Count positive signals
        positive = []
        if sigs.get('main', {}).get('suspected'):       positive.append('main_heuristics')
        if sigs.get('manipulation', {}).get('suspected'): positive.append('manipulation_heuristic')
        if sigs.get('wavelet', {}).get('signal'):        positive.append('wavelet_consistency')
        if sigs.get('spectrum', {}).get('signal'):       positive.append('power_spectrum')
        if sigs.get('ghost', {}).get('suspected'):       positive.append('jpeg_ghost')
        if sigs.get('patch', {}).get('signal'):          positive.append('local_patch_statistics')
        if sigs.get('gradient', {}).get('signal'):       positive.append('gradient_coherence')
        if sigs.get('cfa', {}).get('absent'):            positive.append('cfa_absent')
        if sigs.get('ela', {}).get('local_edit'):        positive.append('ela_v2')
        if sigs.get('resampling', {}).get('suspected'):  positive.append('resampling')
        if sigs.get('noise_inc', {}).get('suspected'):   positive.append('noise_inconsistency')

        findings: List[str] = []
        notable:  List[str] = []

        findings.append(f'Extractors with positive AI/manipulation signal: {len(positive)} / {len(sigs)}')
        for p in positive:
            findings.append(f'  ▶ {p}')

        main_conf = sigs.get('main', {}).get('confidence', 0.0)
        manip_conf = sigs.get('manipulation', {}).get('confidence', 0.0)

        if len(positive) == 0:
            findings.append('No AI-related extractors reported a positive signal. '
                            'Image characteristics are consistent with authentic camera capture.')
        elif len(positive) == 1:
            findings.append('Single extractor positive — weak signal; may be a false positive '
                            'for this image type. Consider image content before drawing conclusions.')
        elif len(positive) >= 2:
            findings.append(
                f'Multiple extractors ({len(positive)}) independently report anomalies. '
                f'Cross-extractor agreement strengthens the overall signal.'
            )
            if main_conf > 0:
                findings.append(f'Main heuristic confidence score  : {main_conf:.2%}')
            if manip_conf > 0:
                findings.append(f'Manipulation heuristic confidence: {manip_conf:.2%}')

        # Build notable summary
        if len(positive) >= 3:
            notable.append(
                f'⚠ AI FUSION: {len(positive)} independent extractors report positive signals '
                f'({", ".join(positive[:5])}{"..." if len(positive) > 5 else ""}). '
                f'Convergent evidence across wavelet, spectral, spatial, and visual channels '
                f'significantly increases confidence in AI generation or manipulation. '
                f'A trained classifier is recommended for a definitive verdict.'
            )
        elif len(positive) == 2:
            notable.append(
                f'↑ AI FUSION: 2 extractors agree ({", ".join(positive)}). '
                f'Moderate evidence — examine individual extractor outputs for context.'
            )

        return {
            'signals_found':    len(sigs),
            'positive_signals': len(positive),
            'positive_list':    positive,
            'per_extractor':    sigs,
            'findings':         findings,
            'notable_findings': notable,
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

    # ── Original per-extractor interpreters (unchanged) ───────────────────────

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
                     f'compressed, or contain densely packed binary data.')
        elif entropy > 7.5:
            n.append(f'↑ Elevated byte entropy ({entropy:.4f}/8.0) — notable but not conclusive.')
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
            n.append(f'Camera/Device     : {ev.get("Image Make","").strip()} {ev.get("Image Model","").strip()}'.strip())
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
                     'or creator/rights information absent in core EXIF.')
        else:
            f.append('XMP metadata block  : not found')
        return f, n

    def _interp_iptc(self, ev: Dict) -> Tuple[List[str], List[str]]:
        note = ev.get('note', '')
        return ([note] if note else ['IPTC: no data or parser not available']), []

    def _interp_pdf_metadata(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        if not ev:
            n.append('⚠ PDF contains no standard metadata fields — may have been deliberately stripped.')
            return ['No PDF metadata found.'], n
        field_map = {
            'Title': 'Title', 'Author': 'Author', 'Subject': 'Subject',
            'Keywords': 'Keywords', 'Creator': 'Creating application',
            'Producer': 'PDF producer library', 'CreationDate': 'Creation date',
            'ModDate': 'Last-modified date', 'Trapped': 'Trapped flag',
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
        if cd: n.append(f'PDF creation date : {cd}')
        if md: n.append(f'PDF modified date : {md}')
        if cd and md and str(cd) != str(md):
            n.append('↑ CreationDate and ModDate differ — the PDF was modified after initial creation.')
        if ev.get('Author'):   n.append(f'Author field      : {ev["Author"]}')
        if ev.get('Creator'):  n.append(f'Created with      : {ev["Creator"]}')
        if ev.get('Producer'): n.append(f'PDF producer      : {ev["Producer"]}')
        return f, n

    def _interp_structure(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        markers = ev.get('jpeg_markers')
        if markers is not None:
            f.append(f'JPEG markers (first 20): {", ".join(markers)}')
            marker_desc = {
                '0xe0': 'APP0 (JFIF header)', '0xe1': 'APP1 (EXIF / XMP)',
                '0xe2': 'APP2 (ICC profile)', '0xed': 'APP13 (IPTC / Photoshop)',
                '0xdb': 'DQT (quantization table)', '0xc0': 'SOF0 (baseline JPEG)',
                '0xc2': 'SOF2 (progressive JPEG)', '0xda': 'SOS (start of scan)',
                '0xfe': 'COM (comment segment)',
            }
            for m in markers:
                desc = marker_desc.get(m)
                if desc: f.append(f'  {m} → {desc}')
        pdf = ev.get('pdf', {})
        if pdf:
            f.append(f'PDF pages         : {pdf.get("num_pages", "unknown")}')
            f.append(f'Cross-ref table   : {pdf.get("xref_table", "unknown")}')
            if pdf.get('xref_table') == 'missing':
                n.append('⚠ PDF cross-reference table is missing or unreadable.')
        return f, n

    def _interp_statistics(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        entropy = ev.get('entropy', 0.0)
        f.append(f'File entropy      : {entropy:.5f} / 8.0')
        dist = ev.get('byte_distribution', [])
        if dist:
            zero_f = dist[0]
            f.append(f'Null-byte freq    : {zero_f:.4f}  ({zero_f * 100:.1f}%)')
            f.append(f'Byte freq[0–19]   : {[round(x, 4) for x in dist]}')
            if zero_f > 0.30:
                n.append(f'⚠ Null bytes account for {zero_f * 100:.1f}% — possible sparse data or padding.')
        return f, n

    def _interp_noise(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        var = ev.get('noise_variance')
        if var is not None:
            f.append(f'Laplacian noise variance: {var:.4f}')
            f.append(f'Method                 : {ev.get("method", "")}')
            if var < 10:
                n.append(f'↓ Very low noise variance ({var:.2f}) — unusually smooth; '
                         f'consistent with AI-generated or heavily post-processed content.')
            elif var > 2000:
                n.append(f'↑ Very high noise variance ({var:.2f}) — strong texture or motion blur.')
            else:
                f.append('Noise variance is within a typical photographic range.')
        return f, n

    def _interp_ela(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        score = ev.get('ela_score')
        max_d = ev.get('max_diff')
        if score is not None:
            f.append(f'ELA mean error (q=90)  : {score:.4f}')
            f.append(f'Method                 : {ev.get("method", "")}')
            if max_d is not None: f.append(f'Maximum pixel diff     : {max_d}')
            if score > 15:
                n.append(f'⚠ Elevated ELA score ({score:.2f}) — possible localised recompression or editing.')
            elif score > 8:
                n.append(f'↑ Moderate ELA score ({score:.2f}) — worth closer inspection.')
            else:
                f.append('ELA score is within the typical range.')
        return f, n

    def _interp_clone_detection(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        detected    = ev.get('detected', False)
        match_count = ev.get('match_count', 0)
        f.append(f'Method             : ORB feature matching (displaced >10 px)')
        f.append(f'Positive detection : {"YES" if detected else "no"}')
        f.append(f'Displaced matches  : {match_count}')
        if detected:
            n.append(f'⚠ ORB clone detection triggered ({match_count} displaced matches) — '
                     f'possible copy-move region. Confirm with copy_move_v2 (SIFT+RANSAC).')
        else:
            f.append('No significant copy-move pattern found.')
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
            n.append(f'⚠ LSB uniformity suspicious (chi²={chi2:.4f}) — possible steganographic payload. '
                     f'See advanced_steganalysis (RS method) for a more sensitive test.')
        else:
            f.append('LSB uniformity within normal bounds.')
        if zip_sig:
            n.append('⚠ ZIP file signature detected in raw bytes — possible polyglot or hidden archive.')
        return f, n

    def _interp_perceptual_hash(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        if ev.get('phash'):
            f.append(f'pHash (perceptual) : {ev["phash"]}')
            f.append(f'dHash (difference) : {ev.get("dhash", "n/a")}')
            f.append(f'aHash (average)    : {ev.get("ahash", "n/a")}')
            n.append('Perceptual hashes computed — use for near-duplicate or modified-copy detection.')
        else:
            f.append('Perceptual hashing: not available.')
        return f, n

    def _interp_ocr(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        text = ev.get('text', '')
        f.append(f'OCR language   : {ev.get("language", "eng")}')
        f.append(f'Characters extracted: {len(text)}')
        if text.strip():
            f.append(f'--- Extracted text (first 500 chars) ---\n{text[:500]}')
            if len(text) > 500:
                f.append(f'... [{len(text) - 500} more chars]')
            n.append(f'OCR succeeded — {len(text)} characters extracted.')
        else:
            f.append('OCR produced no text.')
        return f, n

    def _interp_pdf_embedded(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        images = ev.get('images', [])
        f.append(f'Embedded images      : {len(images)}')
        for img in images[:15]:
            f.append(f'  Page {img.get("page","?"):<4} | format: {img.get("format","?"):<5} | size: {img.get("size",0):,} bytes')
        if len(images) > 15: f.append(f'  ... and {len(images) - 15} more image(s)')
        if images: n.append(f'{len(images)} image(s) embedded in PDF.')
        attachments = ev.get('attachments', [])
        f.append(f'File attachments     : {"FOUND" if attachments else "none"}')
        if attachments: n.append('⚠ Embedded file attachments detected — examine separately.')
        js = ev.get('javascript', [])
        f.append(f'JavaScript actions   : {"FOUND" if js else "none"}')
        if js: n.append('⚠ JavaScript actions detected — potential security risk.')
        forms = ev.get('forms', [])
        f.append(f'AcroForm / forms     : {"FOUND" if forms else "none"}')
        if forms: n.append('Interactive AcroForm fields present — may submit data to a remote server.')
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
            n.append(f'⚠ {len(missing)} font(s) not embedded: {", ".join(missing[:5])}. '
                     f'Can indicate text replaced without proper font re-embedding.')
        return f, n

    def _interp_security(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        enc  = ev.get('encrypted', False)
        sigs = ev.get('signatures', [])
        perm = ev.get('permissions')
        f.append(f'Encrypted          : {"YES" if enc else "no"}')
        if enc: n.append('⚠ PDF is encrypted — full content analysis is limited.')
        if perm is not None: f.append(f'Permission flags   : {perm}')
        f.append(f'Digital signatures : {len(sigs)} found')
        if sigs: n.append(f'{len(sigs)} digital signature(s) present — verify validity independently.')
        return f, n

    def _interp_pdf_hidden(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        wt = ev.get('white_text', [])
        an = ev.get('annotations', [])
        f.append(f'Near-white text blocks    : {len(wt)}')
        if wt:
            for item in wt[:10]:
                f.append(f'  Page {item.get("page","?")}: "{item.get("text","")[:80]}"')
            if len(wt) > 10: f.append(f'  ... and {len(wt)-10} more block(s)')
            n.append(f'⚠ {len(wt)} block(s) of near-white text — commonly used to hide content.')
        else:
            f.append('No near-white hidden text detected.')
        f.append(f'Invisible annotations     : {len(an)}')
        if an:
            for a in an[:5]:
                f.append(f'  Page {a.get("page","?")}: subtype {a.get("subtype","?")}')
            n.append(f'⚠ {len(an)} annotation(s) with no visible appearance stream.')
        else:
            f.append('No invisible-appearance annotations detected.')
        return f, n

    def _interp_pdf_revision(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        inc = ev.get('incremental_saves', 0)
        f.append(f'Incremental saves : {inc}')
        if inc > 0:
            n.append(f'⚠ PDF has {inc} incremental-save link(s) — content from earlier versions '
                     f'may be recoverable from the file body.')
        else:
            f.append('No incremental-save chain detected.')
        return f, n

    def _interp_pdf_layout(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        pages = ev.get('pages', [])
        f.append(f'Pages analysed      : {len(pages)}')
        for p in pages[:10]:
            nwc = p.get('near_white_text_count', 0)
            f.append(f'  Page {p.get("page","?"):<3} | text lines: {p.get("text_count",0):<5} | '
                     f'rectangles: {p.get("rect_count",0):<5} | near-white items: {nwc}')
            if nwc > 0:
                n.append(f'⚠ Page {p.get("page","?")}: {nwc} near-white text item(s) in layout.')
        margins = ev.get('margins', {})
        if margins:
            f.append(f'First-page margins — left: {margins.get("left",0):.1f} | '
                     f'right: {margins.get("right",0):.1f} | top: {margins.get("top",0):.1f} | '
                     f'bottom: {margins.get("bottom",0):.1f}')
        return f, n

    def _interp_jpeg_quantization(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        f.append(f'DQT tables found : {ev.get("tables_found", 0)}')
        for t in ev.get('tables', []):
            f.append(f'  Table {t.get("table_id","?")} | precision: {t.get("precision","?")} | '
                     f'est. quality: ~{t.get("estimated_quality","?")} | '
                     f'mean coeff: {t.get("mean_value",0):.2f}')
        spread = ev.get('quality_spread')
        if spread is not None: f.append(f'Quality spread across tables: {spread:.1f} pts')
        if ev.get('inconsistent_tables'):
            n.append(f'⚠ JPEG quantization tables inconsistent (spread {spread:.0f} pts) — '
                     f'image was re-saved with a different encoder or quality setting.')
        if ev.get('note'): f.append(f'Note: {ev["note"]}')
        return f, n

    def _interp_compression_history(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        f.append(f'DCT blocks analysed          : {ev.get("blocks_analyzed", 0):,}')
        f.append(f'Histogram bins (unique AC11) : {ev.get("histogram_bins", 0)}')
        ps = ev.get('periodicity_score', 0.0)
        f.append(f'Histogram periodicity score  : {ps:.5f}  (threshold > 0.35)')
        f.append(f'Method                       : {ev.get("method", "")}')
        if ev.get('double_compression_suspected'):
            n.append(f'⚠ Double-JPEG compression detected (periodicity {ps:.4f}) — '
                     f'strong signal that the image was re-saved at a different quality.')
        else:
            f.append('No double-compression periodicity pattern detected.')
        return f, n

    def _interp_resampling(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        peaks = ev.get('periodic_peak_count', 0)
        ratio = ev.get('peak_ratio', 0.0)
        f.append(f'Periodic FFT peaks above threshold : {peaks:,}')
        f.append(f'Peak ratio                         : {ratio:.7f}  (threshold > 0.0008000)')
        f.append(f'Method                             : {ev.get("method", "")}')
        if ev.get('resampling_suspected'):
            n.append(f'⚠ Resampling artefact detected (peak ratio {ratio:.6f}) — '
                     f'image was likely scaled, rotated, or warped before saving.')
        else:
            f.append('No periodic FFT peaks consistent with resampling detected.')
        return f, n

    def _interp_cfa_consistency(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        f.append(f'Analysis grid               : {ev.get("grid_shape", [])}')
        f.append(f'Mean CFA correlation score  : {ev.get("mean_cfa_score", 0):.5f}  (>0.15 = consistent)')
        f.append(f'Std dev across blocks       : {ev.get("std_cfa_score", 0):.5f}')
        f.append(f'Block inconsistency ratio   : {ev.get("inconsistency_ratio", 0):.4f}')
        f.append(f'Method                      : {ev.get("method", "")}')
        if ev.get('cfa_absent_or_inconsistent'):
            n.append(f'⚠ CFA demosaicing pattern weak or absent (mean score {ev.get("mean_cfa_score",0):.4f}) — '
                     f'consistent with AI-generated images, screenshots, or composited regions.')
        else:
            f.append('CFA demosaicing pattern present — consistent with camera capture.')
        return f, n

    def _interp_prnu_residual(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        f.append(f'Blocks analysed             : {ev.get("blocks_analyzed", 0)}')
        f.append(f'Mean residual energy        : {ev.get("mean_residual_energy", 0):.5f}')
        cv_ = ev.get('residual_energy_cv', 0.0)
        f.append(f'Residual energy CV          : {cv_:.5f}  (threshold > 0.8 = inconsistent)')
        f.append(f'Note                        : {ev.get("note", "")}')
        if ev.get('spatial_inconsistency_suspected'):
            n.append(f'⚠ PRNU residual energy spatially inconsistent (CV={cv_:.3f}) — '
                     f'content from different capture pipelines may have been composited.')
        else:
            f.append('PRNU residual energy spatially consistent.')
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
            n.append(f'⚠ Block noise inconsistency: {out_c} blocks ({out_r:.1%}) deviate strongly — '
                     f'classic indicator of splicing, inpainting, or compositing.')
        else:
            f.append('Block noise variance consistent — no outlier regions.')
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
            n.append(f'⚠ RS steganalysis: asymmetry {asym:.4f} exceeds threshold — '
                     f'statistical signal consistent with steganographic embedding.')
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
            n.append(f'⚠ Copy-move detected by SIFT + RANSAC ({inliers} geometrically-verified inliers) — '
                     f'high-confidence manipulation signal.')
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
                         f'max block: {reg.get("max_block_mean",0):>8.2f} | '
                         f'hot-block ratio: {reg.get("hot_block_ratio",0):.3%}')
        if ev.get('localized_editing_suspected'):
            max_hr = max((regions.get(q) or regions.get(str(q), {})).get('hot_block_ratio', 0)
                         for q in (60, 75, 90))
            n.append(f'⚠ Multi-quality ELA: localised hot-spot regions detected '
                     f'(max hot-block ratio {max_hr:.2%}) — strong indicator of composited region.')
        else:
            f.append('No localised ELA hot-spots detected.')
        return f, n

    def _interp_font_consistency(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        f.append(f'Distinct fonts             : {ev.get("distinct_fonts", 0)}')
        f.append('Font usage (top 10):')
        for font, count in list(ev.get('font_usage', {}).items())[:10]:
            f.append(f'  {font:<40}: {count} use(s)')
        f.append(f'Font-size outlier count    : {ev.get("size_outlier_count", 0)}')
        anomalies = ev.get('font_anomalies', [])
        if anomalies:
            f.append(f'Font anomalies: {len(anomalies)}')
            for a in anomalies[:10]:
                f.append(f'  Page {a.get("page","?")}: minority "{a.get("minority_font","?")}" '
                         f'({a.get("minority_count",0)}×) vs dominant "{a.get("dominant_font","?")}"')
        if ev.get('inconsistent_fonts_suspected'):
            n.append(f'⚠ Font consistency: {len(anomalies)} page(s) with minority fonts — '
                     f'consistent with localised text replacement.')
        else:
            f.append('Font distribution appears consistent.')
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
        f.append(f'Glyph-height outliers        : {ho}  ({hr:.3%})')
        f.append(f'Mean OCR confidence          : {mc:.1f}%')
        f.append(f'Low-confidence words (<50%)  : {lc:.3%}')
        if ev.get('rendering_inconsistency_suspected'):
            n.append(f'⚠ OCR consistency: outlier ratio {hr:.2%}, low-confidence ratio {lc:.2%} — '
                     f'possible localised text insertion from a different rendering source.')
        else:
            f.append('OCR consistency: glyph sizes and confidence uniform.')
        return f, n

    # ── v9 new interpreter methods ────────────────────────────────────────────

    def _interp_wavelet_consistency(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        f.append(f'Wavelet levels computed   : {ev.get("levels_computed", 0)}')
        f.append(f'Level-1 HH kurtosis       : {ev.get("l1_hh_kurtosis", 0):.4f}  '
                 f'(threshold < {ev.get("thresholds", {}).get("kurtosis", 3.5)}: suspicious)')
        ratios = ev.get('energy_ratios', [])
        if ratios:
            f.append(f'Inter-level energy ratios : {[f"{r:.2f}" for r in ratios]}')
            f.append(f'Ratio mean                : {ev.get("energy_ratio_mean", 0):.3f}  '
                     f'(threshold < {ev.get("thresholds", {}).get("energy_ratio", 2.5)}: suspicious)')
        f.append(f'LH/HL anisotropy          : {ev.get("lh_hl_anisotropy", 0):.4f}  '
                 f'(threshold > {ev.get("thresholds", {}).get("anisotropy", 0.4)}: suspicious)')

        triggered = []
        if ev.get('low_kurtosis'):     triggered.append('Low HH kurtosis (more Gaussian subbands than expected for a camera image)')
        if ev.get('low_energy_ratio'): triggered.append('Low inter-level energy ratio (hallucinated texture at multiple scales)')
        if ev.get('high_anisotropy'):  triggered.append('High LH/HL anisotropy (directional bias from convolutional upsampling)')

        if triggered:
            n.append(f'⚠ Wavelet consistency: {len(triggered)} anomalous signal(s):')
            for t in triggered: n.append(f'   • {t}')
        else:
            f.append('Wavelet statistics are consistent with camera-captured content.')
        return f, n

    def _interp_power_spectrum(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        beta = ev.get('spectral_beta')
        if beta is not None:
            f.append(f'Spectral beta (1/f^beta) : {beta:.4f}  (expected: 1.4 – 4.2)')
        f.append(f'Beta anomaly             : {"YES" if ev.get("beta_anomaly") else "no"}')
        f.append(f'Periodic HF peaks        : {ev.get("periodic_hf_peaks", 0)}  (threshold > 5)')
        f.append(f'Azimuthal CV             : {ev.get("azimuthal_cv", 0):.4f}  (threshold > 0.60)')

        if ev.get('ai_signal_detected'):
            parts = []
            if ev.get('beta_anomaly'):          parts.append(f'spectral slope beta={beta:.2f} outside [1.4, 4.2]')
            if ev.get('high_freq_periodicity'): parts.append(f'{ev.get("periodic_hf_peaks",0)} periodic HF peaks detected')
            if ev.get('high_azimuthal_variance'): parts.append(f'azimuthal CV={ev.get("azimuthal_cv",0):.3f} > 0.60')
            n.append(f'⚠ Power spectrum anomaly detected: {"; ".join(parts)}. '
                     f'Deviation from the natural 1/f² PSD law, periodic peaks, or angular '
                     f'non-uniformity are consistent with AI generation or heavy processing.')
        else:
            f.append('Power spectrum is consistent with the natural 1/f power law.')
        return f, n

    def _interp_jpeg_ghost(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        f.append(f'Method                  : {ev.get("method", "")}')
        f.append(f'Qualities tested        : {ev.get("qualities_tested", [])}')
        f.append(f'Blocks analyzed         : {ev.get("blocks_analyzed", 0)}')
        f.append(f'Dominant ghost quality  : Q{ev.get("dominant_ghost_quality", "?")}')
        inc_r  = ev.get('inconsistency_ratio', 0.0)
        g_std  = ev.get('ghost_quality_std', 0.0)
        f.append(f'Inconsistent blocks     : {ev.get("inconsistent_blocks", 0)}  ({inc_r:.2%})')
        f.append(f'Ghost quality std dev   : {g_std:.2f}')
        dist   = ev.get('ghost_distribution', {})
        if dist:
            f.append('Ghost quality distribution:')
            for q, cnt in sorted(dist.items()):
                f.append(f'  Q{q:<3}: {cnt} block(s)')
        thr = ev.get('thresholds', {})
        if ev.get('manipulation_suspected'):
            n.append(f'⚠ JPEG Ghost: {inc_r:.1%} of blocks have a different ghost quality from '
                     f'the dominant Q{ev.get("dominant_ghost_quality","?")} (std={g_std:.1f}). '
                     f'Spatial inconsistency in the ghost quality map indicates that regions of the '
                     f'image originated from a different JPEG compression history — '
                     f'a strong indicator of copy-paste manipulation or compositing.')
        else:
            f.append('JPEG ghost quality map is spatially consistent — no manipulation signal.')
        return f, n

    def _interp_local_patch_statistics(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        f.append(f'Grid                    : {ev.get("grid_size", "4×4")}  ({ev.get("patches_analyzed", 0)} patches)')
        bcv = ev.get('brightness_cv', 0.0)
        tcv = ev.get('texture_cv', 0.0)
        hfk = ev.get('hf_variance_kurtosis', 0.0)
        f.append(f'Brightness CV           : {bcv:.4f}  (threshold < 0.25: suspicious uniformity)')
        f.append(f'Texture (HF) CV         : {tcv:.4f}  (threshold < 0.40: suspicious uniformity)')
        f.append(f'HF variance kurtosis    : {hfk:.4f}  (threshold < 3.0: suspicious uniformity)')
        thr = ev.get('thresholds', {})

        triggered = []
        if ev.get('low_brightness_cv'): triggered.append(f'Brightness CV={bcv:.3f} < {thr.get("brightness_cv", 0.25)} (unusually uniform brightness across all patches)')
        if ev.get('low_texture_cv'):    triggered.append(f'Texture CV={tcv:.3f} < {thr.get("texture_cv", 0.40)} (AI generators often fill all regions with similar texture)')
        if ev.get('low_hf_kurtosis'):   triggered.append(f'HF kurtosis={hfk:.3f} < {thr.get("hf_kurtosis", 3.0)} (texture content too evenly distributed)')

        if triggered:
            n.append(f'⚠ Local patch statistics: {len(triggered)} uniformity signal(s):')
            for t in triggered: n.append(f'   • {t}')
        else:
            f.append('Local patch statistics show natural brightness and texture variation.')
        return f, n

    def _interp_gradient_coherence(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        ne  = ev.get('orientation_entropy_norm', 0.0)
        t3  = ev.get('top3_orientation_power', 0.0)
        gcv = ev.get('gradient_block_cv', 0.0)
        f.append(f'Orientation entropy (norm) : {ne:.4f}  (threshold > 0.82 = too isotropic)')
        f.append(f'Top-3 orientation power    : {t3:.4f}  (threshold < 0.25 = weak dominant directions)')
        f.append(f'Gradient block CV          : {gcv:.4f}')
        f.append(f'Strong pixels used         : {ev.get("strong_pixels_used", 0):,}')
        thr = ev.get('thresholds', {})

        if ev.get('ai_signal_detected'):
            n.append(f'⚠ Gradient coherence: normalised orientation entropy {ne:.3f} > '
                     f'{thr.get("norm_entropy", 0.82)}, top-3 power {t3:.3f} < '
                     f'{thr.get("top3_power", 0.25)}. '
                     f'An isotropic gradient field with no dominant orientations is '
                     f'consistent with AI-hallucinated texture that fills the image uniformly, '
                     f'unlike real scenes where edges concentrate along specific directions.')
        else:
            f.append('Gradient orientation shows natural directional concentration — '
                     'consistent with a real scene.')
        return f, n

    def _interp_ai_generated_heuristics(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        conf  = ev.get('confidence', 0.0)
        score = ev.get('weighted_score', 0.0)
        max_s = ev.get('max_possible_score', 11.0)
        cnt   = ev.get('signals_triggered', 0)
        total = ev.get('signals_total', 0)
        thresh= ev.get('confidence_threshold', 0.27)

        f.append(f'Weighted score    : {score:.2f} / {max_s:.1f}')
        f.append(f'Confidence        : {conf:.2%}  (threshold ≥ {thresh:.0%} = suspected)')
        f.append(f'Signals triggered : {cnt} / {total}')
        f.append('')
        f.append('Per-signal breakdown:')

        for sig_name, detail in ev.get('signal_details', {}).items():
            flag  = '▶ TRIGGERED' if detail.get('triggered') else '  ok'
            val   = detail.get('value')
            val_s = f'{val:.4f}' if isinstance(val, float) else str(val)
            f.append(f'  {flag}  [{sig_name}]  value={val_s}  weight={detail.get("weight",0):.1f}')
            if detail.get('triggered') and detail.get('reason'):
                f.append(f'            → {detail["reason"]}')

        f.append(f'')
        f.append(f'Caveat: {ev.get("confidence_caveat", "")}')

        if ev.get('ai_generated_suspected'):
            n.append(f'⚠ AI generation heuristics: confidence {conf:.1%} ≥ {thresh:.0%} threshold. '
                     f'{cnt}/{total} weighted signals triggered (score {score:.2f}/{max_s:.1f}):')
            for desc in ev.get('triggered_descriptions', []):
                n.append(f'   • {desc}')
            n.append('   A dedicated trained classifier is required for a reliable verdict.')
        else:
            f.append(f'AI generation heuristics: confidence {conf:.1%} below threshold {thresh:.0%} — '
                     f'image characteristics are not inconsistent with camera capture.')
        return f, n

    def _interp_ai_manipulation_heuristic(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        sc  = ev.get('suspect_block_count', 0)
        sr  = ev.get('suspect_block_ratio', 0.0)
        lc  = ev.get('coherent_suspect_clusters', 0)
        tc  = ev.get('total_suspect_clusters', 0)
        conf= ev.get('detection_confidence', 0.0)
        f.append(f'Blocks analyzed               : {ev.get("blocks_analyzed", 0)}')
        f.append(f'Suspect blocks (≥2 signals)   : {sc}  ({sr:.3%})')
        f.append(f'Noise anomalies               : {ev.get("noise_anomaly_count", 0)}')
        f.append(f'CFA anomalies                 : {ev.get("cfa_anomaly_count", 0)}')
        f.append(f'Edge-density anomalies        : {ev.get("edge_anomaly_count", 0)}')
        f.append(f'Entropy anomalies             : {ev.get("entropy_anomaly_count", 0)}')
        f.append(f'Coherent suspect clusters ≥4  : {lc}  (out of {tc} total clusters)')
        f.append(f'Detection confidence          : {conf:.2%}')
        f.append(f'Method                        : {ev.get("method", "")}')
        f.append(f'Caveat                        : {ev.get("confidence_caveat", "")}')
        if ev.get('localized_ai_edit_suspected'):
            n.append(
                f'⚠ AI manipulation heuristic (confidence {conf:.1%}): {sr:.2%} of blocks show '
                f'multi-signal co-occurrence (noise + CFA + edge + entropy anomalies). '
                + (f'{lc} spatially coherent cluster(s) of ≥4 adjacent suspect blocks detected — '
                   f'coherent spatial regions are a much stronger signal than isolated outliers. '
                   if lc > 0 else '')
                + 'Consistent with AI inpainting or compositing at localised regions.'
            )
        else:
            f.append('No localised AI-manipulation signature detected.')
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
        lines.append(f'  Engine: Forensic Engine v9 (AI-Detection Enhanced Edition)')
        lines.append(SEP)
        lines.append(f'  File      : {file_path}')
        lines.append(f'  Type      : {file_type}  ({mime_type})')
        lines.append(f'  Timestamp : {timestamp}')
        if report_id:
            lines.append(f'  Report ID : {report_id}')
        lines.append(SEP)
        lines.append('')

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
            'sensor':     EvidencePipeline('sensor',     [CFAExtractor(), PRNUExtractor()]),
            'visual2':    EvidencePipeline('visual2',    [
                NoiseInconsistencyExtractor(),
                AdvancedSteganalysisExtractor(),
                CopyMoveExtractorV2(),
                ELAExtractorV2(),
                AIGeneratedImageExtractor(),    # v9 improved
                AIManipulationExtractor(),      # v9 improved
            ]),
            'document_consistency': EvidencePipeline('document_consistency', [
                FontConsistencyExtractor(),
                OCRImageConsistencyExtractor(),
            ]),
            # ── v9 NEW AI-detection pipeline ──────────────────────────────────
            'ai_detection': EvidencePipeline('ai_detection', [
                WaveletConsistencyExtractor(),
                PowerSpectrumExtractor(),
                JPEGGhostExtractor(),
                LocalPatchStatisticsExtractor(),
                GradientCoherenceExtractor(),
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
        'User-Agent':        'forensic-engine/9.0 (+github-actions)',
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
            'Forensic Engine v9 — AI-Detection Enhanced Edition. '
            '32 extractors across 17 pipelines. '
            '5 new AI-detection extractors, improved weighted heuristics, '
            'spatial cluster analysis, and cross-extractor AI fusion synthesis.'
        )
    )
    parser.add_argument('file',              help='Path to file to analyse')
    parser.add_argument('-o', '--output',    help='Output JSON file (default: stdout)')
    parser.add_argument('--pretty',          action='store_true', help='Pretty-print JSON')
    parser.add_argument('--text-report',     action='store_true',
                        help='Write a human-readable text report')
    parser.add_argument('--mode',            choices=['light', 'full'], default='full',
                        help='light = skip OCR + clone-detection; full = everything')
    parser.add_argument('--include-images',  action='store_true',
                        help='Embed extracted PDF images as base64 in output')
    parser.add_argument('--pdf-dpi',         type=int, default=PDF_IMAGE_RESOLUTION,
                        help=f'DPI for PDF→image rasterisation (default {PDF_IMAGE_RESOLUTION})')
    parser.add_argument('--known-hashes',    help='JSON file of known sha256 hashes')
    parser.add_argument('--report-id',       help='Report ID to embed in output')
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

    indent      = 2 if args.pretty else None
    json_output = json.dumps(package, indent=indent, default=str)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(json_output)
        log(f'Wrote JSON report to {args.output}', args.verbose)
    else:
        if not args.text_report:
            print(json_output)

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

    if args.callback_url and args.report_id:
        send_callback(args.callback_url, args.callback_secret, {
            'report_id': args.report_id,
            'report':    package,
        })


if __name__ == '__main__':
    main()
