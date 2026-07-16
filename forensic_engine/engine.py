import os
import sys
import time
from datetime import datetime, timezone
from typing import Dict, Any

from forensic_engine.options import RunOptions
from forensic_engine.context import ExtractionContext
from forensic_engine.base import compute_hashes
from forensic_engine.extractors import get_extractors_by_category

class ForensicEngine:
    """
    Orchestrates the execution of forensic extractors on a target file.
    Does NOT produce verdicts; only aggregates factual evidence.
    """

    def __init__(self, options: RunOptions = None) -> None:
        self.options = options or RunOptions()
        self.registry = get_extractors_by_category()

    def process_file(self, file_path: str) -> Dict[str, Any]:
        """
        Main entry point. Reads the file, runs all applicable extractors,
        and builds the final JSON schema.
        """
        start_t = time.perf_counter()

        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Target file not found: {file_path}")

        with open(file_path, "rb") as f:
            raw_data = f.read()

        context = ExtractionContext(file_path, raw_data, self.options)
        hashes = compute_hashes(raw_data)

        report: Dict[str, Any] = {
            "metadata": {
                "file_path":      os.path.basename(file_path),
                "file_size":      len(raw_data),
                "mime_type":      context.mime_type,
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                "hashes":         hashes,
                "warnings":       []
            },
            "categories": {},
            "execution": {}
        }

        if context._warning:
            report["metadata"]["warnings"].append(context._warning)

        total_ext = 0
        total_err = 0

        for cat_id, extractor_classes in self.registry.items():
            cat_results = []
            for ext_cls in extractor_classes:
                if ext_cls.applicable(context):
                    total_ext += 1
                    ext_instance = ext_cls()
                    try:
                        res = ext_instance.extract(context)
                        if res.get("status") == "error":
                            total_err += 1
                        cat_results.append(res)
                    except Exception as e:
                        total_err += 1
                        cat_results.append({
                            "extractor": ext_cls.name,
                            "status": "error",
                            "summary": f"Unhandled exception: {e}"
                        })
            if cat_results:
                report["categories"][cat_id] = {
                    "results": cat_results,
                    "extractor_count": len(cat_results)
                }

        end_t = time.perf_counter()
        report["execution"] = {
            "total_time_s": round(end_t - start_t, 4),
            "extractors_run": total_ext,
            "errors": total_err,
        }

        return report
