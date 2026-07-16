import os
import io
from typing import Optional, List, Dict, Any, Tuple

from forensic_engine.dependencies import (
    magic, pypdf, Image, pytesseract, convert_from_bytes, PDFMINER_OK,
    PDFResourceManager, LAParams, PDFPageAggregator, PDFPageInterpreter,
    PDFParser, PDFDocument, PDFPage, LTTextBox, LTTextLine, LTChar, LTRect
)
from forensic_engine.constants import MAX_MEMORY_FILE_SIZE
from forensic_engine.options import RunOptions

class ExtractionContext:
    """
    Shared mutable state passed to every extractor. Caches decoded images,
    PDF readers, OCR text, and layout data to avoid redundant computation
    across a pipeline run.
    """

    def __init__(self, file_path: str, raw_data: bytes, options: "RunOptions" = None) -> None:
        self.file_path            = file_path
        self.raw_data             = raw_data
        self.options              = options or RunOptions()
        self._mime_type: Optional[str] = None
        self._file_type: Optional[str] = None
        self._decoded_image            = None
        self._pdf_reader               = None
        self._ocr_text: Optional[str]  = None
        self._pdf_images: List         = []
        self._pdf_layout               = None
        self._warning: Optional[str]   = None

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

    def _detect_type(self) -> None:
        ext  = os.path.splitext(self.file_path)[1].lower()
        mime = "application/octet-stream"
        if magic:
            try:
                mime = magic.from_buffer(self.raw_data, mime=True)
            except Exception:
                pass
        else:
            if ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"):
                mime = f"image/{ext[1:]}"
            elif ext == ".pdf":
                mime = "application/pdf"
        self._mime_type = mime
        self._file_type = (
            "image" if mime.startswith("image") else
            "pdf"   if mime == "application/pdf"  else
            "unknown"
        )
        if len(self.raw_data) > MAX_MEMORY_FILE_SIZE:
            self._warning = f"File size exceeds {MAX_MEMORY_FILE_SIZE // 1024 // 1024} MB."

    def get_decoded_image(self):
        if self._decoded_image is None and Image is not None and self.file_type == "image":
            try:
                img = Image.open(io.BytesIO(self.raw_data))
                img.load()
                self._decoded_image = img
            except Exception:
                self._decoded_image = False
        return self._decoded_image if self._decoded_image is not False else None

    def get_pdf_reader(self):
        if self._pdf_reader is None and pypdf is not None and self.file_type == "pdf":
            try:
                self._pdf_reader = pypdf.PdfReader(io.BytesIO(self.raw_data))
            except Exception:
                self._pdf_reader = False
        return self._pdf_reader if self._pdf_reader is not False else None

    @staticmethod
    def _safe_resources(page) -> dict:
        try:
            res = page.get("/Resources")
            if res is None:
                return {}
            return res.get_object() if hasattr(res, "get_object") else res
        except Exception:
            return {}

    def get_pdf_images(self) -> List:
        if not self._pdf_images and self.file_type == "pdf":
            reader = self.get_pdf_reader()
            if reader:
                for page_num, page in enumerate(reader.pages):
                    resources    = self._safe_resources(page)
                    xobjects_ref = resources.get("/XObject") if resources else None
                    if not xobjects_ref:
                        continue
                    try:
                        xobjects = xobjects_ref.get_object()
                    except Exception:
                        continue
                    for obj_name in xobjects:
                        try:
                            obj = xobjects[obj_name]
                            if obj.get("/Subtype") == "/Image":
                                img_data = obj.get_data()
                                if img_data:
                                    fmt  = "jpeg"
                                    filt = obj.get("/Filter")
                                    if filt == "/FlateDecode":
                                        fmt = "png"
                                    self._pdf_images.append((page_num, img_data, fmt))
                        except Exception:
                            continue
        return self._pdf_images

    def get_pdf_text_with_positions(self):
        if self._pdf_layout is None and self.file_type == "pdf" and PDFMINER_OK:
            try:
                self._pdf_layout = self._extract_layout()
            except Exception:
                self._pdf_layout = False
        return self._pdf_layout if self._pdf_layout is not False else None

    def _extract_layout(self) -> Dict[str, Any]:
        if not PDFMINER_OK:
            return {}
        layout_data: Dict[str, Any] = {"pages": [], "margins": {}}
        try:
            rsrcmgr     = PDFResourceManager()
            laparams    = LAParams()
            device      = PDFPageAggregator(rsrcmgr, laparams=laparams)
            interpreter = PDFPageInterpreter(rsrcmgr, device)
            parser      = PDFParser(io.BytesIO(self.raw_data))
            doc         = PDFDocument(parser)
            for page_num, page in enumerate(PDFPage.create_pages(doc)):
                interpreter.process_page(page)
                layout    = device.get_result()
                page_data = {"page": page_num, "texts": [], "rects": []}
                for element in layout:
                    if isinstance(element, LTTextBox):
                        for textline in element:
                            if isinstance(textline, LTTextLine):
                                entry = {
                                    "text": textline.get_text().strip(),
                                    "x0": textline.x0, "y0": textline.y0,
                                    "x1": textline.x1, "y1": textline.y1,
                                    "fontname": None, "size": None,
                                    "near_white": False,
                                }
                                for ch in textline:
                                    if isinstance(ch, LTChar):
                                        entry["fontname"] = getattr(ch, "fontname", None)
                                        entry["size"]     = getattr(ch, "size", None)
                                        color = self._char_color(ch)
                                        if color is not None and all(c > 0.92 for c in color):
                                            entry["near_white"] = True
                                        break
                                page_data["texts"].append(entry)
                    elif isinstance(element, LTRect):
                        page_data["rects"].append({
                            "x0": element.x0, "y0": element.y0,
                            "x1": element.x1, "y1": element.y1,
                        })
                layout_data["pages"].append(page_data)
            if layout_data["pages"]:
                first = layout_data["pages"][0]
                if first["texts"]:
                    xs = [t["x0"] for t in first["texts"]]
                    layout_data["margins"] = {
                        "left":   min(xs),
                        "right":  max(t["x1"] for t in first["texts"]),
                        "top":    max(t["y0"] for t in first["texts"]),
                        "bottom": min(t["y0"] for t in first["texts"]),
                    }
        except Exception:
            pass
        return layout_data

    @staticmethod
    def _char_color(ch) -> Optional[Tuple[float, ...]]:
        try:
            gs     = getattr(ch, "graphicstate", None)
            if gs is None:
                return None
            ncolor = getattr(gs, "ncolor", None)
            if ncolor is None:
                return None
            if isinstance(ncolor, (int, float)):
                return (float(ncolor),) * 3
            if isinstance(ncolor, (list, tuple)):
                return tuple(float(c) for c in ncolor)
        except Exception:
            return None

    def get_ocr_text(self) -> str:
        if self._ocr_text is None:
            if self.options.mode == "light":
                self._ocr_text = ""
                return self._ocr_text
            if self.file_type == "image" and pytesseract is not None:
                img = self.get_decoded_image()
                if img:
                    try:
                        self._ocr_text = pytesseract.image_to_string(img)
                    except Exception:
                        self._ocr_text = ""
            elif (self.file_type == "pdf"
                  and pytesseract is not None
                  and convert_from_bytes is not None):
                try:
                    images         = convert_from_bytes(self.raw_data, dpi=self.options.pdf_dpi)
                    self._ocr_text = "\n".join(pytesseract.image_to_string(i) for i in images)
                except Exception:
                    self._ocr_text = ""
            else:
                self._ocr_text = ""
        return self._ocr_text
