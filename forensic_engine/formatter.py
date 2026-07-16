import json
from typing import Dict, Any, List
from forensic_engine.constants import CATEGORY_LABELS

class ForensicReportFormatter:
    """
    Formats structured extractor evidence into a human-readable text report.
    Presents pure factual observations without aggregate confidence scores
    or conclusive verdicts.
    """

    def __init__(self, data: Dict[str, Any]) -> None:
        self.data = data
        self.meta = data.get("metadata", {})
        self.cats = data.get("categories", {})

    def format_text(self) -> str:
        lines = []
        lines.append("=" * 80)
        lines.append("          AUTOMATED FORENSIC EVIDENCE REPORT (v10.0)          ")
        lines.append("=" * 80)
        lines.append("")
        lines.append("DISCLAIMER: This system extracts low-level statistical, structural, and")
        lines.append("metadata artifacts. It does not produce verdicts, AI decisions, or confidence")
        lines.append("scores. The presence of artifacts must be interpreted by a human analyst.")
        lines.append("")
        
        lines.append("-" * 80)
        lines.append("1. FILE IDENTIFICATION")
        lines.append("-" * 80)
        lines.append(f"  Target File: {self.meta.get('file_path', 'Unknown')}")
        lines.append(f"  MIME Type:   {self.meta.get('mime_type', 'Unknown')}")
        lines.append(f"  Scan Time:   {self.meta.get('scan_timestamp', 'Unknown')} UTC")
        hashes = self.meta.get("hashes", {})
        if hashes:
            lines.append("  Hashes:")
            for k, v in hashes.items():
                lines.append(f"    {k.upper():<6}: {v}")
        if self.meta.get("warnings"):
            lines.append("")
            lines.append("  WARNINGS:")
            for w in self.meta.get("warnings", []):
                lines.append(f"    ! {w}")
        lines.append("")

        cat_order = [
            "file_integrity", "document_forensics", "camera_origin",
            "editing_detection", "ai_statistical_indicators", "steganography"
        ]

        section_idx = 2
        for cat_id in cat_order:
            cat_data = self.cats.get(cat_id)
            if not cat_data:
                continue

            results = cat_data.get("results", [])
            if not results:
                continue

            lines.append("-" * 80)
            lines.append(f"{section_idx}. {CATEGORY_LABELS.get(cat_id, cat_id.upper())}")
            lines.append("-" * 80)
            section_idx += 1

            for res in results:
                ext_name = res.get("extractor", "Unknown")
                lines.append(f"\n  [ {ext_name} ]")
                lines.append(f"  Status: {res.get('status', 'unknown')}")
                
                if res.get("summary"):
                    lines.append(f"  Summary: {res.get('summary')}")
                
                supports = res.get("supports", [])
                if supports:
                    lines.append("  Evidence Observations:")
                    for obs in supports:
                        lines.append(f"    - {obs}")

                lims = res.get("limitations", [])
                if lims:
                    lines.append("  Methodological Limitations:")
                    for lim in lims:
                        lines.append(f"    * {lim}")

            lines.append("")

        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)

        return "\n".join(lines)
