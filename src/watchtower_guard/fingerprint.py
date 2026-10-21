"""File fingerprinting: sha256 manifests and config-key extraction."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

CHUNK = 1024 * 1024


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _iter_target_files(targets: list[str]) -> list[Path]:
    """Expand target paths (files, dirs, globs) into a sorted list of files.

    Symlinks are NOT followed: a symlink swapped to point elsewhere is itself a
    change worth flagging, and following it could pull in attacker content.
    """
    files: set[Path] = set()
    for t in targets:
        # glob expansion
        expanded = sorted(Path(p) for p in _glob(t)) if _has_glob(t) else [Path(t)]
        for p in expanded:
            if p.is_symlink():
                files.add(p)  # record the link itself, not its target
            elif p.is_dir():
                for root, _dirs, names in os.walk(p, followlinks=False):
                    for name in sorted(names):
                        fp = Path(root) / name
                        files.add(fp)
            elif p.is_file():
                files.add(p)
    return sorted(files)


def _has_glob(pattern: str) -> bool:
    return any(c in pattern for c in "*?[")


def _glob(pattern: str):
    import glob

    return glob.glob(pattern, recursive=True)


def fingerprint_files(targets: list[str]) -> dict[str, dict]:
    """Return {relative_or_abs_path: {sha256, size, is_symlink, link_target?}}."""
    manifest: dict[str, dict] = {}
    for p in _iter_target_files(targets):
        key = str(p)
        try:
            if p.is_symlink():
                manifest[key] = {
                    "sha256": hashlib.sha256(
                        os.readlink(p).encode("utf-8")
                    ).hexdigest(),
                    "size": 0,
                    "is_symlink": True,
                    "link_target": os.readlink(p),
                }
            else:
                manifest[key] = {
                    "sha256": sha256_file(p),
                    "size": p.stat().st_size,
                    "is_symlink": False,
                }
        except OSError as e:
            manifest[key] = {"error": f"unreadable: {e}"}
    return manifest


def get_config_value(path: str | Path, dotted_key: str):
    """Extract a dotted key (e.g. 'notifications.no_notify') from a JSON config."""
    data = load_json(path)
    cur = data
    for part in dotted_key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None, False
        cur = cur[part]
    return cur, True


def check_config_policy(path: str | Path, key: str, must_equal):
    """Return (ok, actual, present). ok=False means the guardrail was weakened."""
    try:
        actual, present = get_config_value(path, key)
    except (OSError, json.JSONDecodeError, ValueError):
        return False, "<unreadable-or-invalid>", False
    if not present:
        return False, "<missing>", False
    return (actual == must_equal), actual, True
