import os
import sys
import json
import urllib.request
from typing import Dict, Any

def dispatch_webhook(payload: Dict[str, Any]) -> None:
    """
    If running in CI, dispatch the results back to the Supabase Edge Function
    via HTTP POST using the x-callback-secret.
    """
    callback_url = os.environ.get("SUPABASE_CALLBACK_URL")
    secret       = os.environ.get("SUPABASE_CALLBACK_SECRET")

    if not callback_url:
        print("[Webhook] No SUPABASE_CALLBACK_URL provided, skipping HTTP post.", file=sys.stderr)
        return

    print(f"[Webhook] Dispatching results to: {callback_url}", file=sys.stderr)

    headers = {
        "Content-Type": "application/json",
        "x-callback-secret": secret or "",
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(callback_url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as response:
            status = response.status
            body   = response.read().decode("utf-8")
            print(f"[Webhook] Response {status}: {body}", file=sys.stderr)
    except Exception as exc:
        print(f"[Webhook] Failed to dispatch: {exc}", file=sys.stderr)
