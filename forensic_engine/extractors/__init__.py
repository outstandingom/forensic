from typing import Type, List, Dict
from forensic_engine.base import BaseExtractor

from forensic_engine.extractors.file_integrity import (
    FileEvidenceExtractor, StatisticsExtractor, StructureExtractor,
    SecurityExtractor, PerceptualHashExtractor
)
from forensic_engine.extractors.document_forensics import (
    PDFMetadataExtractor, PDFEmbeddedExtractor, PDFFontExtractor,
    PDFHiddenExtractor, PDFLayoutExtractor, PDFRevisionExtractor,
    OCRExtractor, FontConsistencyExtractor, OCRImageConsistencyExtractor
)
from forensic_engine.extractors.camera_origin import (
    EXIFExtractor, XMPExtractor, IPTCExtractor,
    JPEGQuantizationExtractor, CFAExtractor, PRNUExtractor
)
from forensic_engine.extractors.editing_detection import (
    ELAExtractor, ELAExtractorV2, CloneExtractor, CopyMoveExtractorV2,
    ResamplingExtractor, CompressionHistoryExtractor, JPEGGhostExtractor,
    NoiseInconsistencyExtractor
)
from forensic_engine.extractors.ai_indicators import (
    NoiseExtractor, WaveletConsistencyExtractor, PowerSpectrumExtractor,
    LocalPatchStatisticsExtractor, GradientCoherenceExtractor,
    AIGeneratedImageExtractor, AIManipulationExtractor
)
from forensic_engine.extractors.steganography import (
    SteganographyExtractor, AdvancedSteganalysisExtractor
)

EXTRACTOR_REGISTRY: List[Type[BaseExtractor]] = [
    # File Integrity
    FileEvidenceExtractor, StatisticsExtractor, StructureExtractor,
    SecurityExtractor, PerceptualHashExtractor,
    # Document Forensics
    PDFMetadataExtractor, PDFEmbeddedExtractor, PDFFontExtractor,
    PDFHiddenExtractor, PDFLayoutExtractor, PDFRevisionExtractor,
    OCRExtractor, FontConsistencyExtractor, OCRImageConsistencyExtractor,
    # Camera Origin
    EXIFExtractor, XMPExtractor, IPTCExtractor,
    JPEGQuantizationExtractor, CFAExtractor, PRNUExtractor,
    # Editing Detection
    ELAExtractor, ELAExtractorV2, CloneExtractor, CopyMoveExtractorV2,
    ResamplingExtractor, CompressionHistoryExtractor, JPEGGhostExtractor,
    NoiseInconsistencyExtractor,
    # AI Indicators
    NoiseExtractor, WaveletConsistencyExtractor, PowerSpectrumExtractor,
    LocalPatchStatisticsExtractor, GradientCoherenceExtractor,
    AIGeneratedImageExtractor, AIManipulationExtractor,
    # Steganography
    SteganographyExtractor, AdvancedSteganalysisExtractor
]

def get_extractors_by_category() -> Dict[str, List[Type[BaseExtractor]]]:
    grouped = {}
    for ext in EXTRACTOR_REGISTRY:
        grouped.setdefault(ext.category, []).append(ext)
    return grouped
