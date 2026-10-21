"""Out-of-band alerting: ledger entry + desktop notification + optional webhook.

The whole point: the alert path must NOT depend on the agent being watched.
The ledger entry is the durable record; the desktop notification reaches the
human; the webhook reaches a second system (PagerDuty/Slack/email gateway).
All three are best-effort EXCEPT the ledger write, which is mandatory --
if the ledger cannot be written, the failure is raised loudly, never swallowed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import urllib.request
from typing import Callable

from .baseline import BaselineStore
from .watcher import WatchResult

# Injectable in tests so no network is needed. Signature: sink(url, payload_dict).
_webhook_sink: Callable[[str, dict], None] | None = None


def set_webhook_sink(sink) -> None:
    global _webhook_sink
    _webhook_sink = sink


def _default_webhook_post(url: str, payload: dict) -> None:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def notify_desktop(title: str, body: str) -> bool:
    """Best-effort desktop notification. Returns False when unavailable."""
    if shutil.which("notify-send") is None:
        return False
    try:
        subprocess.run(
            ["notify-send", "--urgency=critical", title, body],
            check=False,
            timeout=5,
            capture_output=True,
        )
        return True
    except Exception:
        return False


def render_alert(result: WatchResult, hostname: str = "") -> tuple[str, str]:
    """Returns (title, body) for a check result."""
    if result.fatal:
        title = "WATCHTOWER-GUARD: watcher failure (fail-open)"
        body = f"{result.fatal}"
        return title, body
    kinds = {}
    for f in result.findings:
        kinds.setdefault(f.kind, []).append(f)
    lines = []
    for kind, fs in kinds.items():
        lines.append(f"{kind} x{len(fs)}")
        for f in fs[:5]:
            lines.append(f"  - {f.path}: {f.detail}")
        if len(fs) > 5:
            lines.append(f"  ... and {len(fs) - 5} more")
    title = f"WATCHTOWER-GUARD: guardrail tampering detected ({len(result.findings)} findings)"
    body = "\n".join(lines)
    return title, body


def fire_alerts(
    store: BaselineStore,
    result: WatchResult,
    webhook_url: str | None = None,
) -> dict:
    """Write the ledger entry (mandatory), then notify (best-effort).

    Returns a dict describing what was delivered. Ledger failure raises.
    """
    if result.fatal:
        event = "WATCHER_ERROR"
        details = {"fatal": result.fatal}
    elif result.tampered:
        event = "TAMPER_DETECTED"
        details = {
            "findings": [
                {"kind": f.kind, "path": f.path, "detail": f.detail,
                 "old": f.old, "new": f.new}
                for f in result.findings
            ]
        }
    else:
        event = "CHECK_OK"
        details = {}

    entry = store.append(event, details)  # mandatory; raises on failure

    title, body = render_alert(result)
    delivered = {
        "ledger_seq": entry["seq"],
        "desktop": notify_desktop(title, body),
        "webhook": False,
        "webhook_error": None,
    }
    if webhook_url:
        try:
            payload = {"title": title, "body": body, "event": event,
                       "details": details, "ledger_seq": entry["seq"]}
            if _webhook_sink is not None:
                _webhook_sink(webhook_url, payload)
            else:
                _default_webhook_post(webhook_url, payload)
            delivered["webhook"] = True
        except Exception as e:  # webhook must never break the ledger record
            delivered["webhook_error"] = str(e)
    return delivered
