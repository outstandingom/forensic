import sys
import json
import argparse
from typing import NoReturn

from forensic_engine.engine import ForensicEngine
from forensic_engine.options import RunOptions
from forensic_engine.formatter import ForensicReportFormatter
from forensic_engine.callback import dispatch_webhook
from forensic_engine import __version__

def main() -> NoReturn:
    parser = argparse.ArgumentParser(
        description="Forensic Evidence Engine (v10.0) — High-accuracy artifact extraction."
    )
    parser.add_argument("file", help="Path to the file to analyze")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of text report")
    parser.add_argument("--output", type=str, help="Save JSON output to this file")
    parser.add_argument("--report-id", type=str, help="Report ID for Supabase")
    parser.add_argument("--user-id", type=str, help="User ID for Supabase")
    parser.add_argument("--callback-url", type=str, help="Supabase Edge Function URL")
    parser.add_argument("--callback-secret", type=str, help="Supabase Edge Function Secret")
    parser.add_argument("--pretty", action="store_true", help="Pretty print JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable stderr debug logging")
    parser.add_argument("--mode", choices=["full", "light"], default="full", help="Analysis depth (default: full)")
    parser.add_argument("--no-images", action="store_true", help="Skip intensive image analysis")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    options = RunOptions(
        mode="light" if args.mode == "light" else "full",
        include_images=not args.no_images,
        verbose=args.verbose,
    )

    if args.callback_url:
        import os
        os.environ["SUPABASE_CALLBACK_URL"] = args.callback_url
    if args.callback_secret:
        import os
        os.environ["SUPABASE_CALLBACK_SECRET"] = args.callback_secret

    try:
        engine = ForensicEngine(options)
        report = engine.process_file(args.file)
        # Add report info
        if args.report_id:
            report["metadata"]["report_id"] = args.report_id
        if args.user_id:
            report["metadata"]["user_id"] = args.user_id
            
    except Exception as e:
        print(f"FATAL ERROR: {e}", file=sys.stderr)
        report = {
            "metadata": {
                "file_path": args.file,
                "warnings": [f"Fatal engine error: {e}"]
            },
            "status": "failed",
            "error_message": str(e)
        }
        if args.report_id: report["metadata"]["report_id"] = args.report_id
        if args.user_id: report["metadata"]["user_id"] = args.user_id
        
        webhook_payload = {
            "report_id": args.report_id or "unknown",
            "report": report
        }
        dispatch_webhook(webhook_payload)
        
        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2 if args.pretty else None)
            except:
                pass
                
        if args.json:
            print(json.dumps(report, indent=2 if args.pretty else None))
        else:
            print(f"FATAL ERROR: {e}")
            
        sys.exit(0)

    webhook_payload = {
        "report_id": args.report_id or report["metadata"].get("report_id", "unknown"),
        "report": report
    }
    dispatch_webhook(webhook_payload)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2 if args.pretty else None)
            if args.verbose:
                print(f"[CLI] JSON saved to {args.output}", file=sys.stderr)
        except Exception as e:
            print(f"[CLI] Failed to write JSON output: {e}", file=sys.stderr)

    if args.json:
        print(json.dumps(report, indent=2 if args.pretty else None))
    else:
        formatter = ForensicReportFormatter(report)
        print(formatter.format_text())

    sys.exit(0)

if __name__ == "__main__":
    main()
