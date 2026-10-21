"""Audit: read the ledger, verify the chain, render a human timeline."""

from __future__ import annotations

from .baseline import BaselineStore


def read_ledger(store: BaselineStore) -> list[dict]:
    return list(store.iter_ledger())


def verify_chain(store: BaselineStore) -> tuple[bool, str]:
    return store.verify_chain()


def render_timeline(store: BaselineStore) -> str:
    ok, msg = store.verify_chain()
    lines = [f"# watchtower-guard audit timeline", f"# chain: {msg}", ""]
    for e in store.iter_ledger():
        lines.append(f"[{e['ts']}] seq={e['seq']} {e['event']}")
        details = e.get("details", {})
        if e["event"] == "TAMPER_DETECTED":
            for f in details.get("findings", []):
                lines.append(f"    {f['kind']}: {f['path']}")
                lines.append(f"      {f['detail']}")
                if f.get("old") or f.get("new"):
                    lines.append(f"      old={f.get('old')} new={f.get('new')}")
        elif e["event"] in ("WATCHER_ERROR", "LEDGER_TAMPER"):
            lines.append(f"    {details}")
        lines.append("")
    if not ok:
        lines.append("!! CHAIN BROKEN: history was edited or deleted. "
                     "Treat every earlier entry as untrusted.")
    return "\n".join(lines)
