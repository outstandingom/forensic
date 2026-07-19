from typing import Dict

MAX_MEMORY_FILE_SIZE: int = 1024 * 1024 * 1024  # 1 GB
PDF_IMAGE_RESOLUTION: int = 150
STEGO_SAMPLE_PIXELS: int  = 20_000

CATEGORY_CAMERA_ORIGIN  = "camera_origin"
CATEGORY_EDITING        = "editing_detection"
CATEGORY_AI_STATISTICAL = "ai_statistical_indicators"
CATEGORY_DOCUMENT       = "document_forensics"
CATEGORY_STEGANOGRAPHY  = "steganography"
CATEGORY_FILE_INTEGRITY = "file_integrity"
CATEGORY_CONTENT        = "content_extraction"

RELIABILITY_HIGH   = "High"
RELIABILITY_MEDIUM = "Medium"
RELIABILITY_LOW    = "Low"

CATEGORY_LABELS: Dict[str, str] = {
    CATEGORY_CAMERA_ORIGIN:  "Camera Origin",
    CATEGORY_EDITING:        "Editing Detection",
    CATEGORY_AI_STATISTICAL: "AI Statistical Indicators",
    CATEGORY_DOCUMENT:       "Document Forensics",
    CATEGORY_STEGANOGRAPHY:  "Steganography",
    CATEGORY_FILE_INTEGRITY: "File Integrity",
    CATEGORY_CONTENT:        "Content Extraction",
}
