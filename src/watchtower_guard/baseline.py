"""Signed baselines and a hash-chained, append-only audit ledger.

Security model:
- The baseline manifest is HMAC-signed with a key that MUST live outside the
  watched agent's reach (different UID, or at least a path the agent cannot
  write). Without the key, the agent cannot forge a "clean" baseline after
  tampering.
- The ledger is append-only and hash-chained: each entry commits to the hash of
  the previous one, so deleting or editing history breaks the chain and is
  detectable by `verify_chain`.
- This does NOT stop a root-level attacker. It makes tampering evident.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path

from .fingerprint import load_json

BASELINE_NAME = "baseline.json"
LEDGER_NAME = "ledger.jsonl"


def _utcnow() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
    )


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


class BaselineError(Exception):
    """Raised when the baseline is missing, corrupt, or fails signature."""


class BaselineStore:
    def __init__(self, store_dir: str | Path, key: bytes):
        self.store_dir = Path(store_dir)
        self.key = key
        self.baseline_path = self.store_dir / BASELINE_NAME
        self.ledger_path = self.store_dir / LEDGER_NAME

    # -- key management ------------------------------------------------------
    @staticmethod
    def generate_key() -> bytes:
        return secrets.token_bytes(32)

    # -- baseline ------------------------------------------------------------
    def _sign(self, payload: dict) -> str:
        return hmac.new(self.key, _canonical(payload), hashlib.sha256).hexdigest()

    def write_baseline(self, manifest: dict, watchlist: dict) -> dict:
        self.store_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "created": _utcnow(),
            "watchlist": watchlist,
            "manifest": manifest,
        }
        payload["signature"] = self._sign(payload)
        tmp = self.baseline_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.baseline_path)  # atomic, no torn writes
        return payload

    def read_baseline(self) -> dict:
        try:
            payload = load_json(self.baseline_path)
        except (OSError, json.JSONDecodeError, ValueError) as e:
            raise BaselineError(f"baseline unreadable or corrupt: {e}") from e
        sig = payload.get("signature")
        if not isinstance(sig, str):
            raise BaselineError("baseline has no signature")
        body = {k: v for k, v in payload.items() if k != "signature"}
        expected = self._sign(body)
        if not hmac.compare_digest(sig, expected):
            raise BaselineError("baseline signature mismatch (forged or edited)")
        return body

    # -- ledger (append-only, hash-chained) ----------------------------------
    @staticmethod
    def _entry_hash(prev: str, entry: dict) -> str:
        return hashlib.sha256((prev + _canonical(entry).decode("utf-8")).encode()).hexdigest()

    def _last_hash(self) -> str:
        entries = list(self.iter_ledger())
        return entries[-1]["hash"] if entries else "GENESIS"

    def append(self, event: str, details: dict) -> dict:
        """Append one ledger entry. Returns the entry. Never overwrites history."""
        self.store_dir.mkdir(parents=True, exist_ok=True)
        prev = self._last_hash()
        entries = list(self.iter_ledger())
        seq = entries[-1]["seq"] + 1 if entries else 1
        entry = {"seq": seq, "ts": _utcnow(), "event": event, "details": details}
        entry["prev"] = prev
        entry["hash"] = self._entry_hash(prev, entry)
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def iter_ledger(self):
        if not self.ledger_path.exists():
            return
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def verify_chain(self) -> tuple[bool, str]:
        """Returns (ok, message). ok=False means history was edited or deleted."""
        prev = "GENESIS"
        expected_seq = 1
        for entry in self.iter_ledger():
            if entry.get("seq") != expected_seq:
                return False, f"sequence break at entry {entry.get('seq')}"
            if entry.get("prev") != prev:
                return False, f"chain break at seq {expected_seq}"
            body = {k: v for k, v in entry.items() if k not in ("hash",)}
            if entry.get("hash") != self._entry_hash(entry["prev"], body):
                return False, f"hash mismatch at seq {expected_seq} (entry edited)"
            prev = entry["hash"]
            expected_seq += 1
        return True, f"chain ok ({expected_seq - 1} entries)"
