

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
    extract_text  = None
    extract_pages = None
    LAParams      = None

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
        self.file_path = file_path
        self.raw_data  = raw_data
        self.options   = options or RunOptions()
        self._mime_type     = None
        self._file_type     = None
        self._decoded_image = None
        self._pdf_reader    = None
        self._ocr_text      = None
        self._pdf_images: List = []
        self._pdf_layout    = None
        self._warning       = None

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
                    resources    = self._safe_resources(page)
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
# CORE EXTRACTORS (unchanged from v8)
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

            chi2       = chi_square_bit_test(lsb_bits)
            ones_ratio = sum(lsb_bits) / len(lsb_bits) if lsb_bits else 0.5
            suspicious = len(lsb_bits) > 5_000 and chi2 < 0.5
            hidden_zip = 'found' if detect_zip_header(context.raw_data) else None
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
        coeffs  = np.round(np.array(coeffs)).astype(int)
        hist_c  = Counter(coeffs.tolist())
        values  = [hist_c[k] for k in sorted(hist_c.keys())]
        ps      = self._periodicity_score(values)
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
        rgb  = np.array(img.convert('RGB'), dtype=np.float64)
        h, w = rgb.shape[:2]
        block = 32
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
                'Single-image PRNU detects spatial noise-texture inconsistency. '
                'Camera attribution requires a reference fingerprint.'
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

        total     = max(len(groups), 1)
        rs_ratio  = (r - s) / total
        rs_neg    = (r_neg - s_neg) / total
        asymmetry = abs(rs_ratio - rs_neg)
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


# ══════════════════════════════════════════════════════════════════════════════
# v8.1 REPLACEMENT: AIGeneratedImageExtractor  (10 weighted signals)
# ══════════════════════════════════════════════════════════════════════════════

class AIGeneratedImageExtractor(BaseExtractor):
    """
    10-signal weighted AI-generation detector (v8.1).

    Signal                        Weight  Threshold
    ─────────────────────────────────────────────────────────────────────────
    S1  Local variance CV              3    < 0.75  (too uniform)
    S2  Multi-scale noise floor        3    all scales < 2.5 std
    S3  Gradient magnitude kurtosis    2    < 4.5
    S4  Local channel-corr CV          2    < 0.12  (too uniform)
    S5  Edge density CV                2    < 0.50  (too uniform)
    S6  Block DCT coefficient kurtosis 2    < 4.0
    S7  Noise autocorrelation peak     3    > 0.12
    S8  Spectral band anomaly          1    periodic_peak_ratio > 0.002
    S9  Saturation uniformity          1    > 0.85
    S10 Patch texture entropy CV       2    < 0.20  (too uniform)

    Total weight = 21.  ai_generated_suspected when weighted_score >= 0.30.
    """
    name    = "ai_generated_heuristics"
    version = "8.1"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and np is not None

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}

        rgb  = np.array(img.convert('RGB'), dtype=np.float64)
        gray = np.array(img.convert('L'),   dtype=np.float64)
        h, w = gray.shape

        if min(h, w) < 64:
            return {
                'note': 'Image too small for full AI heuristic analysis (min 64×64)',
                'ai_generated_suspected': False,
                'indicator_count': 0,
                'indicators_triggered': [],
                'weighted_score': 0.0,
            }

        raw_signals: Dict[str, Any]          = {}
        reasons:     List[str]               = []
        # (signal_flag_key, weight)
        weighted_flags: List[Tuple[str, int]] = []

        # ── S1: Local variance CV (w=3) ──────────────────────────────────────
        lv_cv, s1 = self._local_variance_cv(gray)
        raw_signals['local_variance_cv']       = round(float(lv_cv), 4)
        raw_signals['s1_local_var_uniform']    = s1
        weighted_flags.append(('s1_local_var_uniform', 3))
        if s1:
            reasons.append(
                f'S1 Local variance too uniform (CV={lv_cv:.3f}; threshold<0.75) '
                '— real scenes contain spatially diverse regions.')

        # ── S2: Multi-scale noise floor (w=3) ────────────────────────────────
        ns_scales, s2 = self._multiscale_noise_floor(gray)
        raw_signals['noise_floor_by_scale']  = ns_scales
        raw_signals['s2_noise_floor_low']    = s2
        weighted_flags.append(('s2_noise_floor_low', 3))
        if s2:
            reasons.append(
                f'S2 Noise floor anomalously low across {len(ns_scales)} scales '
                f'{ns_scales} — sensor noise absent.')

        # ── S3: Gradient magnitude kurtosis (w=2) ────────────────────────────
        gk, s3 = self._gradient_kurtosis(gray)
        raw_signals['gradient_kurtosis']      = round(float(gk), 3)
        raw_signals['s3_grad_kurtosis_low']   = s3
        weighted_flags.append(('s3_grad_kurtosis_low', 2))
        if s3:
            reasons.append(
                f'S3 Gradient kurtosis low ({gk:.2f}; threshold<4.5) '
                '— edges are unnaturally uniform in strength.')

        # ── S4: Local channel-correlation CV (w=2) ────────────────────────────
        cc_cv, s4 = self._local_channel_corr_cv(rgb, h, w)
        raw_signals['channel_corr_cv']         = round(float(cc_cv), 4)
        raw_signals['s4_channel_corr_uniform'] = s4
        weighted_flags.append(('s4_channel_corr_uniform', 2))
        if s4:
            reasons.append(
                f'S4 Inter-channel correlation spatially uniform (CV={cc_cv:.3f}; threshold<0.12) '
                '— atypical of camera sensor Bayer noise.')

        # ── S5: Edge density CV (w=2) ─────────────────────────────────────────
        ed_cv, s5 = self._edge_density_cv(gray)
        raw_signals['edge_density_cv']          = round(float(ed_cv), 4)
        raw_signals['s5_edge_density_uniform']  = s5
        weighted_flags.append(('s5_edge_density_uniform', 2))
        if s5:
            reasons.append(
                f'S5 Edge density spatially uniform (CV={ed_cv:.3f}; threshold<0.50) '
                '— natural scenes have highly varied edge density per region.')

        # ── S6: Block DCT kurtosis (w=2) ─────────────────────────────────────
        dk, s6 = self._block_dct_kurtosis(gray)
        raw_signals['block_dct_kurtosis']      = round(float(dk), 3)
        raw_signals['s6_dct_kurtosis_low']     = s6
        weighted_flags.append(('s6_dct_kurtosis_low', 2))
        if s6:
            reasons.append(
                f'S6 DCT coefficient kurtosis low ({dk:.2f}; threshold<4.0) '
                '— lacks the sparse, heavy-tailed coding of natural camera images.')

        # ── S7: Noise autocorrelation peak (w=3) ─────────────────────────────
        ac_pk, s7 = self._noise_autocorr_peak(gray)
        raw_signals['noise_autocorr_peak']     = round(float(ac_pk), 5)
        raw_signals['s7_noise_structured']     = s7
        weighted_flags.append(('s7_noise_structured', 3))
        if s7:
            reasons.append(
                f'S7 Noise autocorrelation shows structure (peak={ac_pk:.4f}; threshold>0.12) '
                '— periodic pattern consistent with AI upsampling / grid artifact.')

        # ── S8: Spectral band anomaly (w=1) ──────────────────────────────────
        sp_info, s8 = self._spectral_band_anomaly(gray)
        raw_signals['spectral_info']           = sp_info
        raw_signals['s8_spectral_anomaly']     = s8
        weighted_flags.append(('s8_spectral_anomaly', 1))
        if s8:
            reasons.append(
                'S8 Spectral band anomaly — unusual periodic energy in mid/high frequency region.')

        # ── S9: Saturation uniformity (w=1) ──────────────────────────────────
        sat_u, s9 = self._saturation_uniformity(img)
        raw_signals['saturation_uniformity']   = round(float(sat_u), 4)
        raw_signals['s9_saturation_uniform']   = s9
        weighted_flags.append(('s9_saturation_uniform', 1))
        if s9:
            reasons.append(
                f'S9 Saturation distribution unusually uniform ({sat_u:.4f}; threshold>0.85) '
                '— real images exhibit greater saturation diversity.')

        # ── S10: Patch texture entropy CV (w=2) ──────────────────────────────
        pe_cv, s10 = self._patch_texture_diversity(gray)
        raw_signals['patch_entropy_cv']         = round(float(pe_cv), 4)
        raw_signals['s10_texture_uniform']      = s10
        weighted_flags.append(('s10_texture_uniform', 2))
        if s10:
            reasons.append(
                f'S10 Patch texture diversity low (entropy CV={pe_cv:.3f}; threshold<0.20) '
                '— image patches have suspiciously similar texture complexity.')

        # ── Weighted score ────────────────────────────────────────────────────
        total_w, triggered_w = 0, 0
        for flag_key, wt in weighted_flags:
            total_w += wt
            if raw_signals.get(flag_key, False):
                triggered_w += wt

        weighted_score = triggered_w / total_w if total_w > 0 else 0.0

        return {
            'signals':               raw_signals,
            'indicator_count':       len(reasons),
            'indicators_triggered':  reasons,
            'triggered_weight':      triggered_w,
            'total_weight':          total_w,
            'weighted_score':        round(weighted_score, 4),
            'ai_generated_suspected': weighted_score >= 0.30,
            'confidence_caveat': (
                'Multi-signal heuristic v8.1 (10 signals, weighted total=21). '
                'Weighted score ≥ 0.30 triggers suspicion. '
                'Modern AI generators (2025+) are increasingly difficult to detect '
                'with signal-based methods — a trained classifier is required for '
                'production-grade detection. False positives are possible on images '
                'with uniform or repetitive content.'
            ),
        }

    # ── Signal implementations ─────────────────────────────────────────────────

    @staticmethod
    def _local_variance_cv(gray: np.ndarray) -> Tuple[float, bool]:
        """CV of 64×64 block variances. Low CV = too uniform = AI signal."""
        block = 64
        h, w  = gray.shape
        variances = [
            float(np.var(gray[by:by + block, bx:bx + block]))
            for by in range(0, h - block, block)
            for bx in range(0, w - block, block)
        ]
        if len(variances) < 4:
            return 0.0, False
        arr = np.array(variances)
        cv  = float(arr.std() / (arr.mean() + 1e-9))
        return cv, cv < 0.75

    @staticmethod
    def _multiscale_noise_floor(gray: np.ndarray) -> Tuple[List[float], bool]:
        """Gaussian residual std at 3 scales. All < 2.5 = no sensor noise = AI signal."""
        if cv2 is None:
            return [], False
        scores, current = [], gray.astype(np.float32)
        for _ in range(3):
            blurred = cv2.GaussianBlur(current, (5, 5), 0)
            scores.append(round(float(np.std(current - blurred)), 4))
            ch, cw = current.shape
            if ch < 32 or cw < 32:
                break
            current = cv2.resize(current, (max(1, cw // 2), max(1, ch // 2)))
        anomaly = bool(scores) and all(s < 2.5 for s in scores)
        return scores, anomaly

    @staticmethod
    def _gradient_kurtosis(gray: np.ndarray) -> Tuple[float, bool]:
        """Kurtosis of Sobel gradient magnitudes. < 4.5 = too uniform = AI signal."""
        if cv2 is None:
            return 3.0, False
        g8  = np.clip(gray, 0, 255).astype(np.uint8)
        sx  = cv2.Sobel(g8, cv2.CV_64F, 1, 0, ksize=3)
        sy  = cv2.Sobel(g8, cv2.CV_64F, 0, 1, ksize=3)
        mag = np.sqrt(sx ** 2 + sy ** 2).flatten()
        std = mag.std() + 1e-9
        kurt = float(np.mean(((mag - mag.mean()) / std) ** 4))
        return kurt, kurt < 4.5

    @staticmethod
    def _local_channel_corr_cv(rgb: np.ndarray, h: int, w: int) -> Tuple[float, bool]:
        """CV of per-64×64-block RG correlations. Low CV = too consistent = AI signal."""
        block = 64
        corrs = []
        for by in range(0, h - block, block):
            for bx in range(0, w - block, block):
                p  = rgb[by:by + block, bx:bx + block, :]
                r_ = p[:, :, 0].flatten()
                g_ = p[:, :, 1].flatten()
                if np.std(r_) > 1e-6 and np.std(g_) > 1e-6:
                    c = float(np.corrcoef(r_, g_)[0, 1])
                    if not math.isnan(c):
                        corrs.append(abs(c))
        if len(corrs) < 4:
            return 0.0, False
        arr = np.array(corrs)
        cv  = float(arr.std() / (arr.mean() + 1e-9))
        return cv, cv < 0.12

    @staticmethod
    def _edge_density_cv(gray: np.ndarray) -> Tuple[float, bool]:
        """CV of Canny edge density per 32×32 block. Low CV = edges too uniform = AI signal."""
        if cv2 is None:
            return 0.0, False
        block = 32
        h, w  = gray.shape
        densities = []
        for by in range(0, h - block, block):
            for bx in range(0, w - block, block):
                patch   = np.clip(gray[by:by + block, bx:bx + block], 0, 255).astype(np.uint8)
                edges   = cv2.Canny(patch, 50, 150)
                densities.append(float(np.mean(edges > 0)))
        if len(densities) < 4:
            return 0.0, False
        arr = np.array(densities)
        cv  = float(arr.std() / (arr.mean() + 1e-9))
        return cv, cv < 0.50

    @staticmethod
    def _block_dct_kurtosis(gray: np.ndarray) -> Tuple[float, bool]:
        """Kurtosis of AC DCT coefficients across sampled 8×8 blocks. < 4.0 = AI signal."""
        if cv2 is None:
            return 3.0, False
        g32  = gray.astype(np.float32)
        h, w = g32.shape
        h8, w8 = h - h % 8, w - w % 8
        g32  = g32[:h8, :w8]
        # Sample at most ~400 blocks
        step_h = max(1, h8 // (8 * 20))
        step_w = max(1, w8 // (8 * 20))
        ac_coeffs = []
        for by in range(0, h8, 8 * step_h):
            for bx in range(0, w8, 8 * step_w):
                blk = g32[by:by + 8, bx:bx + 8] - 128.0
                d   = cv2.dct(blk)
                ac_coeffs.extend(d.flatten()[1:].tolist())
        if len(ac_coeffs) < 64:
            return 3.0, False
        arr  = np.array(ac_coeffs, dtype=np.float64)
        std  = arr.std() + 1e-9
        kurt = float(np.mean(((arr - arr.mean()) / std) ** 4))
        return kurt, kurt < 4.0

    @staticmethod
    def _noise_autocorr_peak(gray: np.ndarray) -> Tuple[float, bool]:
        """Max off-center 2D autocorrelation peak of noise residual. >0.12 = AI signal."""
        if cv2 is None:
            return 0.0, False
        max_dim = 256
        h, w    = gray.shape
        if min(h, w) > max_dim:
            sc     = max_dim / min(h, w)
            gray_s = cv2.resize(gray.astype(np.float32),
                                (max(1, int(w * sc)), max(1, int(h * sc)))).astype(np.float64)
        else:
            gray_s = gray.copy()
        blurred  = cv2.GaussianBlur(gray_s.astype(np.float32), (5, 5), 0).astype(np.float64)
        residual = gray_s - blurred
        F        = np.fft.fft2(residual)
        ac       = np.abs(np.fft.ifft2(F * np.conj(F)))
        ac       = np.fft.fftshift(ac)
        cy, cx   = ac.shape[0] // 2, ac.shape[1] // 2
        origin   = ac[cy, cx]
        if origin < 1e-9:
            return 0.0, False
        ac_norm  = ac / origin
        ac_norm[max(0, cy - 2):cy + 3, max(0, cx - 2):cx + 3] = 0
        peak = float(ac_norm.max())
        return peak, peak > 0.12

    @staticmethod
    def _spectral_band_anomaly(gray: np.ndarray) -> Tuple[Dict, bool]:
        """Periodic peak ratio in mid/high frequency bands. >0.002 = AI signal."""
        if not _SCIPY_OK:
            return {}, False
        max_dim = 512
        h, w    = gray.shape
        if max(h, w) > max_dim:
            sc = max_dim / max(h, w)
            gray_s = (cv2.resize(gray.astype(np.float32),
                                 (max(1, int(w * sc)), max(1, int(h * sc)))).astype(np.float64)
                      if cv2 is not None else gray[:int(h * sc), :int(w * sc)])
        else:
            gray_s = gray
        f        = sp_fft.fft2(gray_s)
        mag      = np.abs(sp_fft.fftshift(f))
        h2, w2   = mag.shape
        cy, cx   = h2 // 2, w2 // 2
        Y, X     = np.ogrid[:h2, :w2]
        dist     = np.sqrt((Y - cy) ** 2 + (X - cx) ** 2)
        max_d    = float(min(cy, cx))
        mid_mask  = (dist > max_d * 0.10) & (dist <= max_d * 0.40)
        high_mask = (dist > max_d * 0.40) & (dist <= max_d)
        combined  = mag[mid_mask | high_mask].flatten()
        mean_f    = float(np.mean(combined))
        std_f     = float(np.std(combined)) + 1e-9
        peak_ratio = float(np.sum(combined > mean_f + 5 * std_f)) / (len(combined) + 1)
        mid_e  = float(np.mean(mag[mid_mask] ** 2)) + 1e-9
        high_e = float(np.mean(mag[high_mask] ** 2)) + 1e-9
        info = {
            'high_mid_energy_ratio':   round(high_e / mid_e, 5),
            'periodic_peak_ratio':     round(peak_ratio, 6),
        }
        return info, peak_ratio > 0.002

    @staticmethod
    def _saturation_uniformity(img) -> Tuple[float, bool]:
        """Normalized saturation entropy (1−entropy/max). >0.85 = too uniform = AI signal."""
        if Image is None or np is None:
            return 0.0, False
        try:
            hsv = np.array(img.convert('HSV'))
        except Exception:
            return 0.0, False
        sat  = hsv[:, :, 1].astype(np.float64)
        hist, _ = np.histogram(sat, bins=32, range=(0, 255), density=True)
        hist = hist / (hist.sum() + 1e-9)
        ent  = -np.sum(hist * np.log2(hist + 1e-12))
        max_e = math.log2(len(hist))
        uniformity = float(1.0 - (ent / max_e if max_e > 0 else 0))
        return uniformity, uniformity > 0.85

    @staticmethod
    def _patch_texture_diversity(gray: np.ndarray) -> Tuple[float, bool]:
        """CV of 32×32 block entropy. Low CV = all patches equally textured = AI signal."""
        block = 32
        h, w  = gray.shape
        entropies = []
        for by in range(0, h - block, block):
            for bx in range(0, w - block, block):
                patch = gray[by:by + block, bx:bx + block]
                hist, _ = np.histogram(patch, bins=16, range=(0, 255))
                hist_n  = hist / (hist.sum() + 1e-9)
                ent     = -np.sum(hist_n * np.log2(hist_n + 1e-12))
                entropies.append(float(ent))
        if len(entropies) < 4:
            return 0.0, False
        arr = np.array(entropies)
        cv  = float(arr.std() / (arr.mean() + 1e-9))
        return cv, cv < 0.20


# ══════════════════════════════════════════════════════════════════════════════
# v8.1 ENHANCEMENT: AIManipulationExtractor (4-metric block analysis)
# ══════════════════════════════════════════════════════════════════════════════

class AIManipulationExtractor(BaseExtractor):
    """
    Enhanced localized AI-manipulation detector (v8.1).
    Four per-block metrics: Laplacian noise variance, CFA green-channel
    correlation, local entropy, gradient mean.
    Blocks that are outliers in ≥2 metrics simultaneously are flagged.
    """
    name    = "ai_manipulation_heuristic"
    version = "8.1"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and np is not None and cv2 is not None

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        gray = np.array(img.convert('L'), dtype=np.float32)
        rgb  = np.array(img.convert('RGB'), dtype=np.float64)
        h, w = gray.shape
        block = 32

        noise_grid, cfa_grid, entropy_grid, grad_grid = [], [], [], []

        for by in range(0, h - block, block):
            for bx in range(0, w - block, block):
                pg = gray[by:by + block, bx:bx + block]
                pc = rgb[by:by + block, bx:bx + block, :]

                # Metric 1: Laplacian variance (noise proxy)
                noise_grid.append(float(cv2.Laplacian(pg, cv2.CV_32F).var()))

                # Metric 2: CFA green-channel correlation
                cfa_grid.append(CFAExtractor._cfa_score(pc))

                # Metric 3: Local entropy
                hist, _ = np.histogram(pg, bins=16, range=(0, 255))
                hn      = hist / (hist.sum() + 1e-9)
                entropy_grid.append(float(-np.sum(hn * np.log2(hn + 1e-12))))

                # Metric 4: Mean gradient magnitude
                sx = cv2.Sobel(pg, cv2.CV_32F, 1, 0, ksize=3)
                sy = cv2.Sobel(pg, cv2.CV_32F, 0, 1, ksize=3)
                grad_grid.append(float(np.sqrt(sx ** 2 + sy ** 2).mean()))

        if not noise_grid:
            return {'error': 'Image too small for block analysis'}

        n_arr = np.array(noise_grid)
        c_arr = np.array(cfa_grid)
        e_arr = np.array(entropy_grid)
        g_arr = np.array(grad_grid)

        n_med = np.median(n_arr)
        c_med = np.median(c_arr)
        e_med = np.median(e_arr)
        g_med = np.median(g_arr)

        # Original 2-metric criterion (kept for backward comparison)
        suspect_orig = int(np.sum(
            (c_arr < c_med * 0.5) & (np.abs(n_arr - n_med) > n_med * 0.75)
        ))

        # Enhanced: blocks outlying in ≥2 of 4 metrics
        n_out = np.abs(n_arr - n_med) > 3.0 * (np.median(np.abs(n_arr - n_med)) + 1e-6)
        c_out = c_arr < c_med * 0.40
        e_out = np.abs(e_arr - e_med) > 2.0 * (e_arr.std() + 1e-6)
        g_out = np.abs(g_arr - g_med) > 2.0 * (g_arr.std() + 1e-6)

        multi_out      = (n_out.astype(int) + c_out.astype(int) +
                          e_out.astype(int) + g_out.astype(int)) >= 2
        suspect_enh    = int(np.sum(multi_out))
        total_blocks   = len(noise_grid)
        ratio_orig     = suspect_orig / total_blocks
        ratio_enh      = suspect_enh / total_blocks

        suspected = ratio_enh > 0.04 or ratio_orig > 0.05

        return {
            'blocks_analyzed':              total_blocks,
            'suspect_block_count_original': suspect_orig,
            'suspect_block_count_enhanced': suspect_enh,
            'suspect_ratio_original':       round(float(ratio_orig), 4),
            'suspect_ratio_enhanced':       round(float(ratio_enh), 4),
            'metric_medians': {
                'noise_variance': round(float(n_med), 3),
                'cfa_score':      round(float(c_med), 4),
                'entropy':        round(float(e_med), 4),
                'gradient_mean':  round(float(g_med), 3),
            },
            'localized_ai_edit_suspected':  suspected,
            'method': (
                'Enhanced 4-metric block analysis v8.1: Laplacian noise variance, '
                'CFA green-channel correlation, local entropy, gradient mean. '
                'Blocks outlying in ≥2 metrics are flagged as spatially suspect.'
            ),
            'confidence_caveat': 'Heuristic corroborating signal, not a standalone verdict.',
        }


# ══════════════════════════════════════════════════════════════════════════════
# NEW v8.1: WaveletAnalysisExtractor
# ══════════════════════════════════════════════════════════════════════════════

class WaveletAnalysisExtractor(BaseExtractor):
    """
    Haar 3-level 2D wavelet decomposition (pure numpy — no pywavelets).
    Checks:
      (a) Inter-level energy decay — natural images follow ~1/f² law (decay ~2–8).
      (b) HH subband kurtosis at level 1 — natural images are sparse (kurtosis > 5).
      (c) Fine-to-coarse energy ratio (level-1 total / level-3 total).
    """
    name    = "wavelet_analysis"
    version = "8.1"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and np is not None

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        gray = np.array(img.convert('L'), dtype=np.float64)
        if min(gray.shape) < 64:
            return {'error': 'Image too small (min 64×64 for 3-level wavelet)'}

        subbands, LL = self._haar_2d(gray, levels=3)

        # Per-level total detail energy
        level_energies: Dict[int, float] = {}
        level_stats: List[Dict]          = []
        for i, sb in enumerate(subbands):
            lv_e = 0.0
            for sn, coeff in sb.items():
                e    = float(np.mean(coeff ** 2))
                flat = coeff.flatten()
                std  = float(np.std(flat)) + 1e-9
                kurt = float(np.mean(((flat - float(np.mean(flat))) / std) ** 4)) \
                       if len(flat) > 4 else 3.0
                level_stats.append({
                    'level': i + 1, 'subband': sn,
                    'energy': round(e, 6), 'kurtosis': round(kurt, 3),
                })
                lv_e += e
            level_energies[i + 1] = lv_e

        # Energy decay ratios between consecutive levels
        decay_ratios = []
        for i in range(1, len(level_energies)):
            prev_e = level_energies[i]
            curr_e = level_energies[i + 1]
            if curr_e > 0:
                decay_ratios.append(round(float(prev_e / curr_e), 3))

        mean_decay = float(np.mean(decay_ratios)) if decay_ratios else 0.0

        # HH kurtosis at level 1 (finest diagonal detail)
        hh1 = next((s['kurtosis'] for s in level_stats
                     if s['level'] == 1 and s['subband'] == 'HH'), 3.0)

        # Fine-to-coarse energy ratio
        e1 = level_energies.get(1, 0.0)
        e3 = level_energies.get(3, 0.0)
        fc_ratio = float(e1 / (e3 + 1e-9))

        # Anomaly flags
        decay_anomaly    = mean_decay < 1.3 or mean_decay > 15.0
        kurtosis_anomaly = hh1 < 3.5
        ratio_anomaly    = fc_ratio < 2.0 or fc_ratio > 60.0

        ai_signals = int(decay_anomaly) + int(kurtosis_anomaly) + int(ratio_anomaly)

        return {
            'level_energies':              level_energies,
            'energy_decay_ratios':         decay_ratios,
            'mean_energy_decay_ratio':     round(mean_decay, 4),
            'hh1_subband_kurtosis':        round(hh1, 3),
            'fine_to_coarse_energy_ratio': round(fc_ratio, 4),
            'anomalous_energy_decay':      decay_anomaly,
            'anomalous_hh_kurtosis':       kurtosis_anomaly,
            'anomalous_energy_ratio':      ratio_anomaly,
            'ai_wavelet_signals':          ai_signals,
            'ai_signal_suspected':         ai_signals >= 2,
            'method': (
                'Haar 3-level 2D wavelet (pure numpy). '
                'Checks energy decay ratio (natural ~2–8), '
                'HH-1 kurtosis (natural >5), '
                'fine/coarse energy ratio.'
            ),
        }

    @staticmethod
    def _haar_2d(img: np.ndarray, levels: int = 3):
        """Pure-numpy Haar 2D wavelet decomposition."""
        subbands = []
        current  = img.astype(np.float64)
        for _ in range(levels):
            h, w   = current.shape
            h2, w2 = h - h % 2, w - w % 2
            c      = current[:h2, :w2]
            # Row-wise low/high pass
            L  = (c[:, 0::2] + c[:, 1::2]) / 2.0
            H  = (c[:, 0::2] - c[:, 1::2]) / 2.0
            # Column-wise
            LL = (L[0::2, :] + L[1::2, :]) / 2.0
            HL = (L[0::2, :] - L[1::2, :]) / 2.0
            LH = (H[0::2, :] + H[1::2, :]) / 2.0
            HH = (H[0::2, :] - H[1::2, :]) / 2.0
            subbands.append({'HL': HL, 'LH': LH, 'HH': HH})
            current = LL
        return subbands, current


# ══════════════════════════════════════════════════════════════════════════════
# NEW v8.1: LocalTextureConsistencyExtractor
# ══════════════════════════════════════════════════════════════════════════════

class LocalTextureConsistencyExtractor(BaseExtractor):
    """
    Block-level texture diversity analysis.
    For each 32×32 block computes: std deviation, histogram entropy,
    and (if cv2 available) Canny edge density.
    Reports CV for each metric. Low CV across the image = suspiciously
    uniform texture = AI-generation signal.
    """
    name    = "local_texture_consistency"
    version = "8.1"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and np is not None

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}
        gray = np.array(img.convert('L'), dtype=np.float64)
        h, w = gray.shape
        if min(h, w) < 64:
            return {'error': 'Image too small (min 64×64)'}

        block = 32
        stds, entropies, edge_densities = [], [], []

        for by in range(0, h - block, block):
            for bx in range(0, w - block, block):
                patch = gray[by:by + block, bx:bx + block]
                stds.append(float(np.std(patch)))

                hist, _ = np.histogram(patch, bins=16, range=(0, 255))
                hist_n  = hist / (hist.sum() + 1e-9)
                entropies.append(float(-np.sum(hist_n * np.log2(hist_n + 1e-12))))

                if cv2 is not None:
                    edges = cv2.Canny(np.clip(patch, 0, 255).astype(np.uint8), 30, 100)
                    edge_densities.append(float(np.mean(edges > 0)))

        def _cv(arr_list: List[float]) -> Tuple[float, float]:
            if len(arr_list) < 2:
                return 0.0, 0.0
            a = np.array(arr_list)
            return float(a.std() / (a.mean() + 1e-9)), float(a.mean())

        std_cv,  std_mean  = _cv(stds)
        ent_cv,  ent_mean  = _cv(entropies)
        edge_cv, edge_mean = _cv(edge_densities) if edge_densities else (0.0, 0.0)

        std_flag  = std_cv  < 0.60
        ent_flag  = ent_cv  < 0.20
        edge_flag = bool(edge_densities) and edge_cv < 0.50

        ai_signals = int(std_flag) + int(ent_flag) + int(edge_flag)

        return {
            'blocks_analyzed':          len(stds),
            'block_std_cv':             round(std_cv,  4),
            'block_std_mean':           round(std_mean, 3),
            'block_entropy_cv':         round(ent_cv,  4),
            'block_entropy_mean':       round(ent_mean, 4),
            'block_edge_density_cv':    round(edge_cv,  4),
            'block_edge_density_mean':  round(edge_mean, 4),
            'std_too_uniform':          std_flag,
            'entropy_too_uniform':      ent_flag,
            'edge_density_too_uniform': edge_flag,
            'ai_texture_signals':       ai_signals,
            'ai_texture_suspected':     ai_signals >= 2,
            'method': (
                '32×32 block texture CV analysis: '
                'pixel std (CV<0.60), entropy (CV<0.20), '
                'Canny edge density (CV<0.50). '
                '≥2 flags → suspected AI uniform texture.'
            ),
        }


# ══════════════════════════════════════════════════════════════════════════════
# NEW v8.1: AdvancedJPEGGhostExtractor
# ══════════════════════════════════════════════════════════════════════════════

class AdvancedJPEGGhostExtractor(BaseExtractor):
    """
    Multi-quality JPEG ghost analysis.
    Re-saves the image at qualities [50, 65, 80, 95] and computes per-block
    residuals (16×16 blocks). For each block the "optimal quality" (= the
    re-save that produces the lowest residual, meaning it is closest to that
    block's original encoding quality) is recorded.

    If all blocks share the same optimal quality the image has a consistent
    JPEG history. High std of optimal-quality indices indicates blocks with
    different encoding histories → a splice or manipulation signal.
    """
    name    = "jpeg_ghost"
    version = "8.1"
    dependencies = ['get_decoded_image']

    QUALITIES = [50, 65, 80, 95]
    BLOCK     = 16
    MAX_DIM   = 1024   # resize for efficiency

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and Image is not None and np is not None

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}

        rgb = img.convert('RGB')

        # Resize large images for efficiency
        w_orig, h_orig = rgb.size
        if max(h_orig, w_orig) > self.MAX_DIM:
            scale = self.MAX_DIM / max(h_orig, w_orig)
            rgb   = rgb.resize((max(1, int(w_orig * scale)),
                                max(1, int(h_orig * scale))), Image.LANCZOS)

        rgb_arr = np.array(rgb, dtype=np.int32)
        h, w    = rgb_arr.shape[:2]
        block   = self.BLOCK
        n_by    = (h - block) // block
        n_bx    = (w - block) // block

        if n_by < 2 or n_bx < 2:
            return {'error': 'Image too small for block ghost analysis (min ~64×64)'}

        quality_residuals: Dict[int, np.ndarray] = {}

        for q in self.QUALITIES:
            buf = io.BytesIO()
            rgb.save(buf, 'JPEG', quality=q)
            buf.seek(0)
            try:
                recomp = np.array(Image.open(buf).convert('RGB'), dtype=np.int32)
            except Exception:
                continue
            if recomp.shape != rgb_arr.shape:
                continue
            diff         = np.abs(rgb_arr - recomp).sum(axis=2)
            block_errors = np.zeros((n_by, n_bx), dtype=np.float32)
            for by in range(n_by):
                for bx in range(n_bx):
                    block_errors[by, bx] = diff[
                        by * block:(by + 1) * block,
                        bx * block:(bx + 1) * block
                    ].mean()
            quality_residuals[q] = block_errors

        if len(quality_residuals) < 2:
            return {'error': 'Could not compute ghost residuals', 'qualities_tested': 0}

        qualities_used = list(quality_residuals.keys())
        stack          = np.stack(list(quality_residuals.values()), axis=2)
        best_q_idx     = np.argmin(stack, axis=2)   # index into qualities_used

        idx_std    = float(best_q_idx.std())
        idx_unique = int(len(np.unique(best_q_idx)))

        mean_errors = {q: round(float(quality_residuals[q].mean()), 3)
                       for q in quality_residuals}

        # Inconsistency: multiple different "optimal qualities" across blocks
        ghost_inconsistency = idx_std > 0.8 and idx_unique >= 2

        # Distribution of optimal quality indices
        total_blocks = n_by * n_bx
        idx_counts   = {qualities_used[i]: int(np.sum(best_q_idx == i))
                        for i in range(len(qualities_used))}

        return {
            'blocks_analyzed':               total_blocks,
            'qualities_tested':              qualities_used,
            'mean_error_by_quality':         mean_errors,
            'optimal_quality_distribution':  idx_counts,
            'best_quality_index_std':        round(idx_std, 4),
            'best_quality_index_unique_count': idx_unique,
            'ghost_inconsistency_suspected': ghost_inconsistency,
            'method': (
                f'JPEG ghost analysis at qualities {qualities_used}. '
                '16×16 per-block minimum-residual quality mapping. '
                'Inconsistent optimal-quality distribution → mixed JPEG history → '
                'possible composite / spliced region.'
            ),
        }


# ══════════════════════════════════════════════════════════════════════════════
# NEW v8.1: AIDetectionFusionExtractor
# ══════════════════════════════════════════════════════════════════════════════

class AIDetectionFusionExtractor(BaseExtractor):
    """
    Independent weighted consensus of 6 AI-generation signals.
    Computes its own lightweight measurements so it does not depend on
    results from other extractors.  Acts as a second-opinion extractor
    that can confirm or challenge the individual extractor outputs.

    Signal                        Weight  Threshold
    ─────────────────────────────────────────────────────────────────────────
    A  Noise floor std                 3    < 1.8
    B  Local variance CV               3    < 0.70
    C  DCT AC coefficient kurtosis     2    < 4.0
    D  Wavelet energy decay l1→l2      2    < 1.3 or > 12.0
    E  Noise autocorrelation peak      3    > 0.12
    F  Mean CFA correlation score      2    < 0.12

    Total weight = 15.  ai_generated_suspected when weighted_score >= 0.40.
    """
    name    = "ai_detection_fusion"
    version = "8.1"
    dependencies = ['get_decoded_image']

    @staticmethod
    def applicable(context) -> bool:
        return context.file_type == 'image' and np is not None

    def _extract(self, context) -> Dict[str, Any]:
        img = context.get_decoded_image()
        if img is None:
            return {'error': 'Could not decode image'}

        gray = np.array(img.convert('L'), dtype=np.float64)
        rgb  = np.array(img.convert('RGB'), dtype=np.float64)
        h, w = gray.shape

        if min(h, w) < 64:
            return {'error': 'Image too small (min 64×64)'}

        signals_found:   List[str]       = []
        signal_details:  Dict[str, Any]  = {}
        total_weight     = 0
        triggered_weight = 0

        # ── A: Noise floor std (w=3) ──────────────────────────────────────────
        w_a = 3
        total_weight += w_a
        if cv2 is not None:
            blurred  = cv2.GaussianBlur(gray.astype(np.float32), (5, 5), 0).astype(np.float64)
            noise_std = float(np.std(gray - blurred))
            flag_a    = noise_std < 1.8
            signal_details['A_noise_floor_std'] = round(noise_std, 4)
            if flag_a:
                triggered_weight += w_a
                signals_found.append(
                    f'A) Low noise floor std ({noise_std:.3f}; thr<1.8) — '
                    f'sensor noise absent (weight {w_a}).')

        # ── B: Local variance CV (w=3) ────────────────────────────────────────
        w_b = 3
        total_weight += w_b
        block = 64
        variances = [
            float(np.var(gray[by:by + block, bx:bx + block]))
            for by in range(0, h - block, block)
            for bx in range(0, w - block, block)
        ]
        if len(variances) >= 4:
            var_arr = np.array(variances)
            var_cv  = float(var_arr.std() / (var_arr.mean() + 1e-9))
            flag_b  = var_cv < 0.70
            signal_details['B_local_variance_cv'] = round(var_cv, 4)
            if flag_b:
                triggered_weight += w_b
                signals_found.append(
                    f'B) Local variance too uniform (CV={var_cv:.3f}; thr<0.70) — '
                    f'lacks natural scene diversity (weight {w_b}).')

        # ── C: DCT AC kurtosis (w=2) ──────────────────────────────────────────
        w_c = 2
        total_weight += w_c
        if cv2 is not None:
            g32  = gray.astype(np.float32)
            h8, w8 = h - h % 8, w - w % 8
            g32  = g32[:h8, :w8]
            step_h = max(1, h8 // (8 * 20))
            step_w = max(1, w8 // (8 * 20))
            ac_c = []
            for by in range(0, h8, 8 * step_h):
                for bx in range(0, w8, 8 * step_w):
                    blk = g32[by:by + 8, bx:bx + 8] - 128.0
                    d   = cv2.dct(blk)
                    ac_c.extend(d.flatten()[1:].tolist())
            if len(ac_c) >= 64:
                arr_c    = np.array(ac_c, dtype=np.float64)
                std_c    = arr_c.std() + 1e-9
                dct_kurt = float(np.mean(((arr_c - arr_c.mean()) / std_c) ** 4))
                flag_c   = dct_kurt < 4.0
                signal_details['C_dct_kurtosis'] = round(dct_kurt, 3)
                if flag_c:
                    triggered_weight += w_c
                    signals_found.append(
                        f'C) Low DCT kurtosis ({dct_kurt:.2f}; thr<4.0) — '
                        f'lacks sparse natural image coding (weight {w_c}).')

        # ── D: Wavelet energy decay L1→L2 (w=2) ──────────────────────────────
        w_d = 2
        total_weight += w_d
        try:
            subbands, _ = WaveletAnalysisExtractor._haar_2d(gray, levels=3)
            level_e = [sum(float(np.mean(sb[k] ** 2)) for k in sb) for sb in subbands]
            if len(level_e) >= 2 and level_e[1] > 0:
                decay_l1_l2 = float(level_e[0] / level_e[1])
                flag_d      = decay_l1_l2 < 1.3 or decay_l1_l2 > 12.0
                signal_details['D_wavelet_decay_l1_l2'] = round(decay_l1_l2, 3)
                if flag_d:
                    triggered_weight += w_d
                    signals_found.append(
                        f'D) Anomalous wavelet energy decay L1→L2 ({decay_l1_l2:.2f}; '
                        f'normal 1.3–12.0) — deviates from 1/f² scaling (weight {w_d}).')
        except Exception:
            pass

        # ── E: Noise autocorrelation peak (w=3) ──────────────────────────────
        w_e = 3
        total_weight += w_e
        if cv2 is not None:
            max_dim = 256
            gray_s  = gray
            if min(h, w) > max_dim:
                sc     = max_dim / min(h, w)
                gray_s = cv2.resize(gray.astype(np.float32),
                                    (max(1, int(w * sc)), max(1, int(h * sc)))
                                    ).astype(np.float64)
            bl2  = cv2.GaussianBlur(gray_s.astype(np.float32), (5, 5), 0).astype(np.float64)
            res2 = gray_s - bl2
            F2   = np.fft.fft2(res2)
            ac2  = np.abs(np.fft.ifft2(F2 * np.conj(F2)))
            ac2  = np.fft.fftshift(ac2)
            cy2, cx2 = ac2.shape[0] // 2, ac2.shape[1] // 2
            origin2  = ac2[cy2, cx2]
            if origin2 > 1e-9:
                ac2_n = ac2 / origin2
                ac2_n[max(0, cy2 - 2):cy2 + 3, max(0, cx2 - 2):cx2 + 3] = 0
                ac_pk = float(ac2_n.max())
                flag_e = ac_pk > 0.12
                signal_details['E_noise_autocorr_peak'] = round(ac_pk, 5)
                if flag_e:
                    triggered_weight += w_e
                    signals_found.append(
                        f'E) Structured noise autocorrelation (peak={ac_pk:.4f}; thr>0.12) — '
                        f'AI upsampling / grid artifact (weight {w_e}).')

        # ── F: Mean CFA correlation (w=2) ─────────────────────────────────────
        w_f = 2
        total_weight += w_f
        if cv2 is not None:
            block_f = 32
            cfa_s   = []
            for by in range(0, h - block_f, block_f):
                for bx in range(0, w - block_f, block_f):
                    cfa_s.append(
                        CFAExtractor._cfa_score(rgb[by:by + block_f, bx:bx + block_f, :])
                    )
            if cfa_s:
                mean_cfa = float(np.mean(cfa_s))
                flag_f   = mean_cfa < 0.12
                signal_details['F_mean_cfa_score'] = round(mean_cfa, 4)
                if flag_f:
                    triggered_weight += w_f
                    signals_found.append(
                        f'F) Weak CFA demosaicing pattern (mean={mean_cfa:.4f}; thr<0.12) — '
                        f'Bayer interpolation absent (weight {w_f}).')

        # ── Weighted consensus ─────────────────────────────────────────────────
        weighted_score = triggered_weight / total_weight if total_weight > 0 else 0.0

        if weighted_score < 0.25:
            confidence = 'low'
            verdict    = 'No significant AI-generation signals — consistent with camera capture.'
        elif weighted_score < 0.50:
            confidence = 'medium'
            verdict    = 'Some AI-generation signals present — warrants closer examination.'
        else:
            confidence = 'high'
            verdict    = 'Strong AI-generation signals — high suspicion of synthetic origin.'

        return {
            'signal_details':     signal_details,
            'signals_triggered':  signals_found,
            'triggered_weight':   triggered_weight,
            'total_weight':       total_weight,
            'weighted_score':     round(weighted_score, 4),
            'confidence_tier':    confidence,
            'verdict':            verdict,
            'ai_generated_suspected': weighted_score >= 0.40,
            'method': (
                'Weighted fusion of 6 independent signals: '
                'noise floor (×3), local variance CV (×3), DCT kurtosis (×2), '
                'wavelet decay (×2), noise autocorrelation (×3), CFA score (×2). '
                'Total weight=15; weighted_score ≥ 0.40 → suspected AI generation.'
            ),
            'caveat': (
                'Independent second-opinion extractor. '
                'Modern AI generators (2025+) may not trigger all signals. '
                'False positive rate varies by scene content. '
                'A trained classifier is required for production-grade detection.'
            ),
        }


# ══════════════════════════════════════════════════════════════════════════════
# DETAILED REPORT BUILDER
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
    }

    def build(self, evidence: Dict[str, List[Dict[str, Any]]], file_type: str) -> Dict[str, Any]:
        all_notable: List[str] = []
        categories:  List[Dict] = []
        for cat_key, results in evidence.items():
            label   = self.CATEGORY_LABELS.get(cat_key, cat_key.replace('_', ' ').title())
            entries = []
            for res in results:
                entry = self._process(res)
                entries.append(entry)
                all_notable.extend(entry.get('notable_findings', []))
            categories.append({'category': cat_key, 'label': label, 'extractors': entries})
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
            findings.append(f'{label}: {v:.6f}' if isinstance(v, float) else f'{label}: {v}')
        return findings, []

    # ── Original interpreters (unchanged) ─────────────────────────────────────

    def _interp_file_evidence(self, ev):
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
        f.append(f'Structure valid   : {"YES" if struct_ok else "NO"}')
        f.append(f'Known-hash match  : {"YES" if ev.get("duplicate") else "no"}')
        if entropy > 7.9:
            n.append(f'⚠ Extremely high byte entropy ({entropy:.4f}/8.0) — may be encrypted or compressed.')
        elif entropy > 7.5:
            n.append(f'↑ Elevated byte entropy ({entropy:.4f}/8.0).')
        if ev.get('corrupted'):
            n.append('⚠ File failed structural validation — appears corrupted or malformed.')
        if ev.get('duplicate'):
            n.append('⚠ SHA-256 matches a hash in the known-files list — possible duplicate.')
        return f, n

    def _interp_exif(self, ev):
        f, n = [], []
        if not ev:
            f.append('No EXIF data found.')
            return f, n
        priority = [
            'Image Make', 'Image Model', 'EXIF DateTimeOriginal', 'Image DateTime',
            'EXIF DateTimeDigitized', 'EXIF Software', 'EXIF ExifImageWidth',
            'EXIF ExifImageLength', 'GPS GPSLatitude', 'GPS GPSLongitude',
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
        if ev.get('Image Make') or ev.get('Image Model'):
            n.append(f'Camera/Device: {ev.get("Image Make","").strip()} {ev.get("Image Model","").strip()}'.strip())
        if ev.get('EXIF DateTimeOriginal'):
            n.append(f'Capture timestamp: {ev["EXIF DateTimeOriginal"]}')
        if ev.get('EXIF Software'):
            n.append(f'Processing software present in EXIF: {ev["EXIF Software"]}')
        if ev.get('GPS GPSLatitude') and ev.get('GPS GPSLongitude'):
            n.append(f'GPS coordinates embedded — lat: {ev["GPS GPSLatitude"]}, lon: {ev["GPS GPSLongitude"]}')
        return f, n

    def _interp_xmp(self, ev):
        f, n = [], []
        if ev.get('raw_xmp_present'):
            f.append('XMP metadata block: PRESENT')
            snippet = ev.get('xmp_snippet', '')
            if snippet:
                f.append(f'XMP snippet (≤500 ch):\n{snippet}')
            n.append('XMP metadata present — may contain editing history, software chain, or rights information.')
        else:
            f.append('XMP metadata block: not found')
        return f, n

    def _interp_iptc(self, ev):
        note = ev.get('note', '')
        return ([note] if note else ['IPTC: no data']), []

    def _interp_pdf_metadata(self, ev):
        f, n = [], []
        if not ev:
            n.append('⚠ PDF contains no standard metadata — may have been stripped to obscure origin.')
            return ['No PDF metadata found.'], n
        field_map = {
            'Title': 'Title', 'Author': 'Author', 'Subject': 'Subject',
            'Keywords': 'Keywords', 'Creator': 'Creating application',
            'Producer': 'PDF producer library', 'CreationDate': 'Creation date',
            'ModDate': 'Last-modified date',
        }
        for raw_key, label in field_map.items():
            val = ev.get(raw_key) or ev.get(raw_key.lower())
            if val:
                f.append(f'{label:<25}: {val}')
        for k, v in ev.items():
            if k not in field_map and k.lower() not in [x.lower() for x in field_map]:
                f.append(f'{k:<25}: {v}')
        cd = ev.get('CreationDate') or ev.get('creationdate')
        md = ev.get('ModDate') or ev.get('moddate')
        if cd: n.append(f'PDF creation date: {cd}')
        if md: n.append(f'PDF modified date: {md}')
        if cd and md and str(cd) != str(md):
            n.append('↑ CreationDate and ModDate differ — document was modified after initial creation.')
        if ev.get('Author'):   n.append(f'Author field: {ev["Author"]}')
        if ev.get('Creator'):  n.append(f'Created with: {ev["Creator"]}')
        if ev.get('Producer'): n.append(f'PDF producer: {ev["Producer"]}')
        return f, n

    def _interp_structure(self, ev):
        f, n = [], []
        markers = ev.get('jpeg_markers')
        if markers is not None:
            f.append(f'JPEG markers (first 20): {", ".join(markers)}')
        pdf = ev.get('pdf', {})
        if pdf:
            f.append(f'PDF pages       : {pdf.get("num_pages", "unknown")}')
            f.append(f'Cross-ref table : {pdf.get("xref_table", "unknown")}')
            if pdf.get('xref_table') == 'missing':
                n.append('⚠ PDF cross-reference table missing — file may be malformed or rebuilt.')
        return f, n

    def _interp_statistics(self, ev):
        f, n = [], []
        entropy = ev.get('entropy', 0.0)
        f.append(f'File entropy  : {entropy:.5f} / 8.0')
        dist = ev.get('byte_distribution', [])
        if dist:
            zero_f = dist[0]
            f.append(f'Null-byte freq: {zero_f:.4f}  ({zero_f * 100:.1f}%)')
            if zero_f > 0.30:
                n.append(f'⚠ Null bytes: {zero_f * 100:.1f}% — may indicate sparse data or structured binary.')
        return f, n

    def _interp_noise(self, ev):
        f, n = [], []
        var = ev.get('noise_variance')
        if var is not None:
            f.append(f'Laplacian noise variance: {var:.4f}')
            if var < 10:
                n.append(f'↓ Very low noise variance ({var:.2f}) — unusually smooth.')
            elif var > 2000:
                n.append(f'↑ Very high noise variance ({var:.2f}) — strong texture or noise.')
        return f, n

    def _interp_ela(self, ev):
        f, n = [], []
        score = ev.get('ela_score')
        if score is not None:
            f.append(f'ELA mean error (q=90): {score:.4f}')
            if score > 15:
                n.append(f'⚠ Elevated ELA score ({score:.2f}) — possible recompression / editing artefact.')
            elif score > 8:
                n.append(f'↑ Moderate ELA score ({score:.2f}) — worth closer inspection.')
        return f, n

    def _interp_clone_detection(self, ev):
        f, n = [], []
        detected    = ev.get('detected', False)
        match_count = ev.get('match_count', 0)
        f.append(f'Positive detection : {"YES" if detected else "no"}')
        f.append(f'Displaced matches  : {match_count}')
        if detected:
            n.append(f'⚠ ORB clone detection: {match_count} displaced feature matches — possible copy-move.')
        return f, n

    def _interp_steganography(self, ev):
        f, n = [], []
        sampled = ev.get('lsb_bits_sampled', 0)
        ratio   = ev.get('lsb_ones_ratio', 0.5)
        chi2    = ev.get('lsb_chi_square')
        susp    = ev.get('suspicious_lsb_uniformity', False)
        f.append(f'LSB bits sampled : {sampled:,}')
        f.append(f'LSB ones ratio   : {ratio:.5f}')
        if chi2 is not None:
            f.append(f'Chi-square       : {chi2:.5f}')
        if susp:
            n.append(f'⚠ LSB distribution unusually uniform (chi²={chi2:.4f}) — possible steganographic payload.')
        if ev.get('hidden_zip_signature'):
            n.append('⚠ ZIP file signature (PK\\x03\\x04) found — possible polyglot or hidden archive.')
        return f, n

    def _interp_perceptual_hash(self, ev):
        f, n = [], []
        if ev.get('phash'):
            f.append(f'pHash: {ev["phash"]}')
            f.append(f'dHash: {ev.get("dhash", "n/a")}')
            f.append(f'aHash: {ev.get("ahash", "n/a")}')
            n.append('Perceptual hashes computed — usable for near-duplicate detection.')
        else:
            f.append('Perceptual hashing: not available.')
        return f, n

    def _interp_ocr(self, ev):
        f, n = [], []
        text = ev.get('text', '')
        f.append(f'Characters extracted: {len(text)}')
        if text.strip():
            f.append(f'--- Extracted text (first 500 chars) ---\n{text[:500]}')
            n.append(f'OCR succeeded — {len(text)} characters extracted.')
        else:
            f.append('OCR produced no text.')
        return f, n

    def _interp_pdf_embedded(self, ev):
        f, n = [], []
        images = ev.get('images', [])
        f.append(f'Embedded images  : {len(images)}')
        if images:
            n.append(f'{len(images)} image(s) embedded in PDF.')
        attachments = ev.get('attachments', [])
        f.append(f'File attachments : {"FOUND" if attachments else "none"}')
        if attachments:
            n.append('⚠ Embedded file attachments detected — examine separately.')
        js = ev.get('javascript', [])
        f.append(f'JavaScript       : {"FOUND" if js else "none"}')
        if js:
            n.append('⚠ JavaScript actions in PDF — potential security risk.')
        forms = ev.get('forms', [])
        f.append(f'AcroForm         : {"FOUND" if forms else "none"}')
        if forms:
            n.append('Interactive form fields present — data may be submitted remotely.')
        return f, n

    def _interp_pdf_fonts(self, ev):
        f, n = [], []
        embedded = ev.get('embedded', [])
        missing  = ev.get('missing', [])
        f.append(f'Embedded fonts ({len(embedded)}): {", ".join(embedded[:10]) or "none"}')
        f.append(f'Non-embedded  ({len(missing)}): {", ".join(missing[:10]) or "none"}')
        if missing:
            n.append(f'⚠ {len(missing)} font(s) not embedded — rendering may differ; possible text replacement.')
        return f, n

    def _interp_security(self, ev):
        f, n = [], []
        enc = ev.get('encrypted', False)
        f.append(f'Encrypted         : {"YES" if enc else "no"}')
        if enc:
            n.append('⚠ PDF is encrypted — full content analysis is limited.')
        sigs = ev.get('signatures', [])
        f.append(f'Digital signatures: {len(sigs)}')
        if sigs:
            n.append(f'{len(sigs)} digital signature(s) present — verify validity independently.')
        return f, n

    def _interp_pdf_hidden(self, ev):
        f, n = [], []
        wt = ev.get('white_text', [])
        an = ev.get('annotations', [])
        f.append(f'Near-white text blocks   : {len(wt)}')
        if wt:
            for item in wt[:10]:
                f.append(f'  Page {item.get("page","?")}: "{item.get("text","")[:80]}"')
            n.append(f'⚠ {len(wt)} near-white text block(s) — commonly used to hide content.')
        f.append(f'Invisible annotations    : {len(an)}')
        if an:
            n.append(f'⚠ {len(an)} annotation(s) with no visible appearance stream.')
        return f, n

    def _interp_pdf_revision(self, ev):
        f, n = [], []
        inc = ev.get('incremental_saves', 0)
        f.append(f'Incremental saves: {inc}')
        if inc > 0:
            n.append(f'⚠ PDF has {inc} incremental-save link(s) — earlier versions may be recoverable.')
        return f, n

    def _interp_pdf_layout(self, ev):
        f, n = [], []
        pages = ev.get('pages', [])
        f.append(f'Pages analysed: {len(pages)}')
        for p in pages[:10]:
            nwc = p.get('near_white_text_count', 0)
            f.append(f'  Page {p.get("page","?")}: text lines {p.get("text_count",0)}, '
                     f'rects {p.get("rect_count",0)}, near-white {nwc}')
            if nwc > 0:
                n.append(f'⚠ Page {p.get("page","?")}: {nwc} near-white text item(s).')
        return f, n

    def _interp_jpeg_quantization(self, ev):
        f, n = [], []
        count = ev.get('tables_found', 0)
        f.append(f'DQT tables found: {count}')
        for t in ev.get('tables', []):
            f.append(f'  Table {t.get("table_id","?")} | quality ~{t.get("estimated_quality","?")} | '
                     f'mean coeff {t.get("mean_value",0):.2f}')
        spread = ev.get('quality_spread')
        if spread is not None:
            f.append(f'Quality spread: {spread:.1f} pts')
        if ev.get('inconsistent_tables'):
            n.append(f'⚠ Inconsistent JPEG quantization tables (spread {spread:.0f} pts) — '
                     'image re-saved with a different encoder/quality.')
        return f, n

    def _interp_compression_history(self, ev):
        f, n = [], []
        ps = ev.get('periodicity_score', 0.0)
        f.append(f'DCT blocks analysed         : {ev.get("blocks_analyzed", 0):,}')
        f.append(f'Histogram periodicity score : {ps:.5f}  (threshold > 0.35)')
        f.append(f'Method                      : {ev.get("method", "")}')
        if ev.get('double_compression_suspected'):
            n.append(f'⚠ Double-JPEG compression artefact (periodicity {ps:.4f}) — '
                     'image was re-saved at a different quality after initial JPEG compression.')
        return f, n

    def _interp_resampling(self, ev):
        f, n = [], []
        ratio = ev.get('peak_ratio', 0.0)
        f.append(f'Periodic FFT peaks : {ev.get("periodic_peak_count", 0):,}')
        f.append(f'Peak ratio         : {ratio:.7f}  (threshold > 0.0008000)')
        if ev.get('resampling_suspected'):
            n.append(f'⚠ Resampling artefact (peak ratio {ratio:.6f}) — image may have been '
                     'geometrically transformed (scaled, rotated, warped).')
        return f, n

    def _interp_cfa_consistency(self, ev):
        f, n = [], []
        mean_s = ev.get('mean_cfa_score', 0)
        f.append(f'Mean CFA score        : {mean_s:.5f}  (>0.15 = consistent demosaicing)')
        f.append(f'Std dev               : {ev.get("std_cfa_score", 0):.5f}')
        f.append(f'Inconsistency ratio   : {ev.get("inconsistency_ratio", 0):.4f}')
        if ev.get('cfa_absent_or_inconsistent'):
            n.append(f'⚠ CFA demosaicing correlation weak/absent (mean {mean_s:.4f}) — '
                     'consistent with AI-generated images, screenshots, or composited regions.')
        return f, n

    def _interp_prnu_residual(self, ev):
        f, n = [], []
        cv_ = ev.get('residual_energy_cv', 0.0)
        f.append(f'Blocks analysed        : {ev.get("blocks_analyzed", 0)}')
        f.append(f'Mean residual energy   : {ev.get("mean_residual_energy", 0):.5f}')
        f.append(f'Residual energy CV     : {cv_:.5f}  (threshold > 0.8)')
        if ev.get('spatial_inconsistency_suspected'):
            n.append(f'⚠ PRNU residual energy spatially inconsistent (CV={cv_:.3f}) — '
                     'possible composite from different capture pipelines.')
        return f, n

    def _interp_noise_inconsistency(self, ev):
        f, n = [], []
        out_c = ev.get('outlier_block_count', 0)
        out_r = ev.get('outlier_ratio', 0.0)
        f.append(f'Blocks analysed    : {ev.get("blocks_analyzed", 0)}')
        f.append(f'Outlier blocks     : {out_c}  ({out_r:.2%})')
        if ev.get('inconsistent_noise_suspected'):
            n.append(f'⚠ Noise inconsistency: {out_c} blocks ({out_r:.1%}) deviate strongly — '
                     'classic signal of image splicing, inpainting, or compositing.')
        return f, n

    def _interp_advanced_steganalysis(self, ev):
        f, n = [], []
        asym = ev.get('rs_asymmetry', 0.0)
        f.append(f'Groups analysed  : {ev.get("groups_analyzed", 0):,}')
        f.append(f'RS asymmetry     : {asym:.5f}  (threshold > 0.03)')
        if ev.get('embedding_suspected'):
            n.append(f'⚠ RS steganalysis: asymmetry {asym:.4f} — statistical signal of hidden payload.')
        return f, n

    def _interp_copy_move_v2(self, ev):
        f, n = [], []
        note = ev.get('note')
        if note:
            f.append(f'Note: {note}')
            return f, n
        inliers = ev.get('ransac_inliers', 0)
        f.append(f'RANSAC geometric inliers: {inliers}  (threshold ≥ 8)')
        if ev.get('detected'):
            n.append(f'⚠ Copy-move detected (SIFT+RANSAC): {inliers} inliers — high-confidence manipulation signal.')
        return f, n

    def _interp_ela_v2(self, ev):
        f, n = [], []
        f.append(f'Method: {ev.get("method", "")}')
        scores  = ev.get('scores_by_quality', {})
        regions = ev.get('region_analysis', {})
        for q in (60, 75, 90):
            sc  = scores.get(q) or scores.get(str(q))
            reg = regions.get(q) or regions.get(str(q), {})
            if sc is not None:
                f.append(f'  Q{q:>3} | mean: {sc:>8.3f} | hot-block ratio: {reg.get("hot_block_ratio",0):.3%}')
        if ev.get('localized_editing_suspected'):
            n.append('⚠ Multi-quality ELA: localised hot-spot regions detected — '
                     'inconsistently compressed areas indicate compositing or selective re-save.')
        return f, n

    def _interp_font_consistency(self, ev):
        f, n = [], []
        f.append(f'Distinct fonts: {ev.get("distinct_fonts", 0)}')
        anomalies = ev.get('font_anomalies', [])
        if anomalies:
            for a in anomalies[:5]:
                f.append(f'  Page {a.get("page","?")}: minority "{a.get("minority_font","?")}" '
                         f'({a.get("minority_count",0)}×) vs dominant "{a.get("dominant_font","?")}"')
        if ev.get('inconsistent_fonts_suspected'):
            n.append(f'⚠ Font inconsistency: {len(anomalies)} page(s) with minority fonts — '
                     'possible localised text replacement.')
        return f, n

    def _interp_ocr_image_consistency(self, ev):
        f, n = [], []
        wc = ev.get('word_count', 0)
        f.append(f'Words detected: {wc}')
        if wc == 0:
            return f, n
        hr = ev.get('height_outlier_ratio', 0.0)
        lc = ev.get('low_confidence_ratio', 0.0)
        f.append(f'Glyph-height outlier ratio : {hr:.3%}')
        f.append(f'Low-confidence word ratio  : {lc:.3%}')
        if ev.get('rendering_inconsistency_suspected'):
            n.append(f'⚠ OCR inconsistency: height outlier {hr:.2%}, low-confidence {lc:.2%} — '
                     'possible localised text insertion from a different source.')
        return f, n

    # ── v8.1 UPDATED interpreter: ai_generated_heuristics ─────────────────────

    def _interp_ai_generated_heuristics(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        sigs   = ev.get('signals', {})
        cnt    = ev.get('indicator_count', 0)
        reasons = ev.get('indicators_triggered', [])
        tw     = ev.get('triggered_weight', 0)
        total  = ev.get('total_weight', 21)
        ws     = ev.get('weighted_score', 0.0)

        f.append(f'Signals evaluated         : 10 (weighted total = {total})')
        f.append(f'Indicators triggered      : {cnt} / 10')
        f.append(f'Triggered weight          : {tw} / {total}')
        f.append(f'Weighted score            : {ws:.4f}  (threshold ≥ 0.30)')
        f.append('')
        f.append('Per-signal measurements:')

        sig_display = [
            ('local_variance_cv',    'S1  Local variance CV',           'threshold < 0.75'),
            ('noise_floor_by_scale', 'S2  Multi-scale noise floor',     'threshold all < 2.5'),
            ('gradient_kurtosis',    'S3  Gradient kurtosis',           'threshold < 4.5'),
            ('channel_corr_cv',      'S4  Channel correlation CV',      'threshold < 0.12'),
            ('edge_density_cv',      'S5  Edge density CV',             'threshold < 0.50'),
            ('block_dct_kurtosis',   'S6  Block DCT kurtosis',          'threshold < 4.0'),
            ('noise_autocorr_peak',  'S7  Noise autocorr peak',         'threshold > 0.12'),
            ('spectral_info',        'S8  Spectral band anomaly',       'periodic_peak_ratio > 0.002'),
            ('saturation_uniformity','S9  Saturation uniformity',       'threshold > 0.85'),
            ('patch_entropy_cv',     'S10 Patch entropy CV',            'threshold < 0.20'),
        ]
        for key, label, thr in sig_display:
            val = sigs.get(key, 'n/a')
            if isinstance(val, float):
                val_str = f'{val:.4f}'
            elif isinstance(val, list):
                val_str = str([round(x, 3) for x in val])
            elif isinstance(val, dict):
                val_str = ', '.join(f'{k}={v}' for k, v in list(val.items())[:3])
            else:
                val_str = str(val)
            f.append(f'  {label:<35} = {val_str:<15}  ({thr})')

        f.append('')
        f.append(f'Caveat: {ev.get("confidence_caveat", "")}')

        if ev.get('ai_generated_suspected'):
            n.append(f'⚠ AI-generation heuristics v8.1: weighted score {ws:.4f} ≥ 0.30 threshold.')
            n.append(f'  {cnt}/10 signals triggered ({tw}/{total} weighted):')
            for r in reasons:
                n.append(f'   • {r}')
            n.append('  A trained classifier is required for production-grade detection.')
        else:
            f.append(f'Weighted score {ws:.4f} is below the 0.30 threshold — '
                     'image characteristics are not inconsistent with camera capture.')
        return f, n

    # ── v8.1 UPDATED interpreter: ai_manipulation_heuristic ───────────────────

    def _interp_ai_manipulation_heuristic(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        f.append(f'Blocks analysed            : {ev.get("blocks_analyzed", 0)}')
        sc_o = ev.get('suspect_block_count_original', 0)
        sr_o = ev.get('suspect_ratio_original', 0.0)
        sc_e = ev.get('suspect_block_count_enhanced', 0)
        sr_e = ev.get('suspect_ratio_enhanced', 0.0)
        f.append(f'Suspect blocks (original)  : {sc_o}  ({sr_o:.3%})')
        f.append(f'Suspect blocks (enhanced)  : {sc_e}  ({sr_e:.3%})')
        meds = ev.get('metric_medians', {})
        if meds:
            f.append('Block metric medians:')
            for k, v in meds.items():
                f.append(f'  {k:<20}: {v}')
        f.append(f'Method: {ev.get("method", "")}')
        f.append(f'Caveat: {ev.get("confidence_caveat", "")}')
        if ev.get('localized_ai_edit_suspected'):
            n.append(
                f'⚠ AI manipulation heuristic v8.1: enhanced ratio {sr_e:.2%} of blocks '
                f'show co-occurring anomalies in ≥2 of 4 metrics '
                f'(noise variance, CFA, entropy, gradient). '
                'Spatially localised co-occurring anomalies are consistent with '
                'AI inpainting or compositing. Treat as a corroborating signal.')
        else:
            f.append('No localised AI-manipulation signature detected.')
        return f, n

    # ── NEW v8.1 interpreters ──────────────────────────────────────────────────

    def _interp_wavelet_analysis(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        le   = ev.get('level_energies', {})
        dr   = ev.get('energy_decay_ratios', [])
        md   = ev.get('mean_energy_decay_ratio', 0.0)
        hh1k = ev.get('hh1_subband_kurtosis', 3.0)
        fc   = ev.get('fine_to_coarse_energy_ratio', 0.0)

        f.append('Haar wavelet 3-level decomposition (pure numpy):')
        for lvl, e in sorted(le.items()):
            f.append(f'  Level {lvl} total detail energy : {e:.6f}')
        f.append(f'Energy decay ratios L1→L2, L2→L3 : {dr}  (natural: ~2–8)')
        f.append(f'Mean energy decay ratio            : {md:.4f}')
        f.append(f'HH-1 subband kurtosis              : {hh1k:.3f}  (natural: >5.0)')
        f.append(f'Fine/coarse energy ratio (L1/L3)   : {fc:.4f}  (anomaly if <2 or >60)')
        f.append(f'AI wavelet signals triggered        : {ev.get("ai_wavelet_signals", 0)} / 3')
        f.append(f'Method: {ev.get("method", "")}')

        signals = []
        if ev.get('anomalous_energy_decay'):
            signals.append(f'anomalous energy decay ratio {md:.2f}')
        if ev.get('anomalous_hh_kurtosis'):
            signals.append(f'low HH-1 kurtosis {hh1k:.2f} (natural >5.0)')
        if ev.get('anomalous_energy_ratio'):
            signals.append(f'anomalous fine/coarse ratio {fc:.2f}')

        if ev.get('ai_signal_suspected'):
            n.append(
                f'⚠ Wavelet analysis: {len(signals)} signal(s) triggered — '
                + '; '.join(signals) + '. '
                'Deviations from natural 1/f² scaling are consistent with AI synthesis '
                'or heavy processing.')
        else:
            f.append('Wavelet energy distribution is within natural bounds.')
        return f, n

    def _interp_local_texture_consistency(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        f.append(f'Blocks analysed         : {ev.get("blocks_analyzed", 0)}')
        std_cv  = ev.get('block_std_cv', 0.0)
        ent_cv  = ev.get('block_entropy_cv', 0.0)
        edge_cv = ev.get('block_edge_density_cv', 0.0)
        f.append(f'Block std CV            : {std_cv:.4f}   (threshold < 0.60  → too uniform)')
        f.append(f'Block entropy CV        : {ent_cv:.4f}   (threshold < 0.20  → too uniform)')
        f.append(f'Block edge density CV   : {edge_cv:.4f}  (threshold < 0.50  → too uniform)')
        f.append(f'Block std mean          : {ev.get("block_std_mean", 0):.3f}')
        f.append(f'Block entropy mean      : {ev.get("block_entropy_mean", 0):.4f}')
        f.append(f'Block edge density mean : {ev.get("block_edge_density_mean", 0):.4f}')
        ai_sigs = ev.get('ai_texture_signals', 0)
        f.append(f'AI texture signals      : {ai_sigs} / 3')
        f.append(f'Method: {ev.get("method", "")}')

        triggered = []
        if ev.get('std_too_uniform'):        triggered.append(f'std CV={std_cv:.3f}')
        if ev.get('entropy_too_uniform'):    triggered.append(f'entropy CV={ent_cv:.3f}')
        if ev.get('edge_density_too_uniform'): triggered.append(f'edge density CV={edge_cv:.3f}')

        if ev.get('ai_texture_suspected'):
            n.append(
                f'⚠ Local texture consistency: {len(triggered)} metric(s) show abnormally uniform '
                'block-level texture — ' + ', '.join(triggered) + '. '
                'Natural scenes exhibit high regional diversity in std, entropy, and edge density. '
                'This uniformity is consistent with AI-generated content.')
        else:
            f.append('Block-level texture diversity is within natural bounds.')
        return f, n

    def _interp_jpeg_ghost(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        f.append(f'Blocks analysed            : {ev.get("blocks_analyzed", 0)}')
        f.append(f'Qualities tested           : {ev.get("qualities_tested", [])}')
        mean_err = ev.get('mean_error_by_quality', {})
        if mean_err:
            f.append('Mean residual per quality:')
            for q, e in sorted(mean_err.items()):
                f.append(f'  Q{q:<3} → mean error {e:.3f}')
        opt_dist = ev.get('optimal_quality_distribution', {})
        if opt_dist:
            f.append('Block optimal-quality distribution:')
            for q, cnt in sorted(opt_dist.items()):
                f.append(f'  Q{q:<3} → {cnt} block(s)')
        idx_std    = ev.get('best_quality_index_std', 0.0)
        idx_unique = ev.get('best_quality_index_unique_count', 1)
        f.append(f'Optimal quality index std  : {idx_std:.4f}  (threshold > 0.8)')
        f.append(f'Unique optimal qualities   : {idx_unique}')
        f.append(f'Method: {ev.get("method", "")}')

        if ev.get('ghost_inconsistency_suspected'):
            n.append(
                f'⚠ JPEG ghost inconsistency: {idx_unique} distinct optimal quality levels '
                f'detected across blocks (index std={idx_std:.3f}). '
                'Different image regions have different JPEG compression histories — '
                'a strong indicator that content from multiple sources was composited. '
                'The quality distribution map shows which blocks originate from different sources.')
        else:
            f.append('JPEG ghost analysis: optimal quality is consistent across all blocks — '
                     'no mixed compression history detected.')
        return f, n

    def _interp_ai_detection_fusion(self, ev: Dict) -> Tuple[List[str], List[str]]:
        f, n = [], []
        ws      = ev.get('weighted_score', 0.0)
        tw      = ev.get('triggered_weight', 0)
        total   = ev.get('total_weight', 15)
        tier    = ev.get('confidence_tier', 'low')
        verdict = ev.get('verdict', '')
        details = ev.get('signal_details', {})
        signals = ev.get('signals_triggered', [])

        f.append('AI Detection Fusion — 6-signal independent consensus (v8.1):')
        f.append(f'  Weighted score  : {ws:.4f}  (threshold ≥ 0.40 = suspected)')
        f.append(f'  Triggered weight: {tw} / {total}')
        f.append(f'  Confidence tier : {tier.upper()}')
        f.append(f'  Verdict         : {verdict}')
        f.append('')
        f.append('Signal measurements:')
        label_map = {
            'A_noise_floor_std':    ('A  Noise floor std',        'thr < 1.8', 3),
            'B_local_variance_cv':  ('B  Local variance CV',      'thr < 0.70', 3),
            'C_dct_kurtosis':       ('C  DCT AC kurtosis',        'thr < 4.0', 2),
            'D_wavelet_decay_l1_l2':('D  Wavelet decay L1→L2',   'thr <1.3 or >12', 2),
            'E_noise_autocorr_peak':('E  Noise autocorr peak',    'thr > 0.12', 3),
            'F_mean_cfa_score':     ('F  Mean CFA score',         'thr < 0.12', 2),
        }
        for key, (label, thr, wt) in label_map.items():
            val = details.get(key, 'n/a')
            val_str = f'{val:.4f}' if isinstance(val, float) else str(val)
            f.append(f'  {label:<30} = {val_str:<10}  ({thr})  [weight {wt}]')

        f.append('')
        f.append(f'Caveat: {ev.get("caveat", "")}')

        if ev.get('ai_generated_suspected'):
            n.append(f'⚠ AI Detection Fusion: weighted score {ws:.4f} ≥ 0.40 — '
                     f'{tier.upper()} confidence of AI generation.')
            for sig in signals:
                n.append(f'   • {sig}')
            n.append('  Fusion result is independent of other individual extractors.')
        elif tier == 'medium':
            n.append(f'↑ AI Detection Fusion (medium): score {ws:.4f} — some signals present, '
                     'below the 0.40 threshold but warrants attention alongside other findings.')
        else:
            f.append(f'Fusion score {ws:.4f} below threshold — no dominant AI-generation pattern.')
        return f, n

    # ── Text report formatter ──────────────────────────────────────────────────

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
        lines.append('  Engine: Forensic Engine v8.1 (AI Detection Enhanced Edition)')
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
            lines.append('  No notable findings.')
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
                    lines.append(f'  │  STATUS: UNAVAILABLE — {ext_entry.get("reason", "")}')
                else:
                    lines.append('  │  STATUS: OK')
                    for finding in ext_entry.get('findings', []):
                        for sub in finding.split('\n'):
                            lines.append(f'  │  {sub}')
                    nf = ext_entry.get('notable_findings', [])
                    if nf:
                        lines.append('  │  ── Notable ──')
                        for item in nf:
                            for sub in item.split('\n'):
                                lines.append(f'  │  {sub}')
                lines.append('  └' + '─' * 70)
            lines.append('')
        lines.append(SEP)
        lines.append('  DISCLAIMER')
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
        package['detailed_assessment'] = builder.build(package['evidence'], context.file_type)
        return package


class ForensicEngine:
    def __init__(self):
        self.pipelines = {
            'file':      EvidencePipeline('file',      [FileEvidenceExtractor()]),
            'metadata':  EvidencePipeline('metadata',  [
                EXIFExtractor(), XMPExtractor(), IPTCExtractor(), PDFMetadataExtractor()
            ]),
            'structure': EvidencePipeline('structure', [StructureExtractor()]),
            'statistics': EvidencePipeline('statistics', [StatisticsExtractor()]),
            # visual: added WaveletAnalysisExtractor (v8.1)
            'visual':    EvidencePipeline('visual',    [
                WaveletAnalysisExtractor(),       # NEW v8.1
                NoiseExtractor(),
                ELAExtractor(),
                CloneExtractor(),
                SteganographyExtractor(),
                PerceptualHashExtractor(),
            ]),
            'text':      EvidencePipeline('text',      [OCRExtractor()]),
            'embedded':  EvidencePipeline('embedded',  [PDFEmbeddedExtractor(), PDFFontExtractor()]),
            'security':  EvidencePipeline('security',  [SecurityExtractor()]),
            'hidden':    EvidencePipeline('hidden',    [PDFHiddenExtractor()]),
            'revision':  EvidencePipeline('revision',  [PDFRevisionExtractor()]),
            'layout':    EvidencePipeline('layout',    [PDFLayoutExtractor()]),
            'quantization': EvidencePipeline('quantization', [
                JPEGQuantizationExtractor(),
                CompressionHistoryExtractor(),
            ]),
            'resampling': EvidencePipeline('resampling', [ResamplingExtractor()]),
            'sensor':    EvidencePipeline('sensor',    [CFAExtractor(), PRNUExtractor()]),
            # visual2: added 3 new v8.1 extractors; AIDetectionFusionExtractor runs last
            'visual2':   EvidencePipeline('visual2',   [
                NoiseInconsistencyExtractor(),
                AdvancedSteganalysisExtractor(),
                CopyMoveExtractorV2(),
                ELAExtractorV2(),
                AIGeneratedImageExtractor(),        # REPLACED v8.1 (10 signals)
                AIManipulationExtractor(),          # ENHANCED v8.1 (4-metric)
                LocalTextureConsistencyExtractor(), # NEW v8.1
                AdvancedJPEGGhostExtractor(),       # NEW v8.1
                AIDetectionFusionExtractor(),       # NEW v8.1 (runs last, second opinion)
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
    data    = json.dumps(payload, default=str).encode('utf-8')
    headers = {
        'Content-Type':      'application/json',
        'x-callback-secret': secret,
        'User-Agent':        'forensic-engine/8.1 (+github-actions)',
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
            'Forensic Engine v8.1 — AI Detection Enhanced Edition. '
            '31 extractors across 16 pipelines (4 new / 2 enhanced in v8.1). '
            'All evidence is shown directly; no aggregate risk score is computed.'
        )
    )
    parser.add_argument('file',              help='Path to file to analyse')
    parser.add_argument('-o', '--output',    help='Output JSON file (default: stdout)')
    parser.add_argument('--pretty',          action='store_true', help='Pretty-print JSON')
    parser.add_argument('--text-report',     action='store_true',
                        help='Also write a human-readable text report.')
    parser.add_argument('--mode',            choices=['light', 'full'], default='full')
    parser.add_argument('--include-images',  action='store_true')
    parser.add_argument('--pdf-dpi',         type=int, default=PDF_IMAGE_RESOLUTION)
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
                'report_id': args.report_id, 'error': str(e), 'report': None,
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
        builder     = DetailedReportBuilder()
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
            'report_id': args.report_id, 'report': package,
        })


if __name__ == '__main__':
    main()




Claude is AI and can make mistakes. Please double-check responses.
