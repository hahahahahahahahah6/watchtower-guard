"""The watcher: re-fingerprint, compare against the signed baseline, classify.

Event taxonomy:
- MODIFIED        file content changed (old/new sha256 recorded)
- REMOVED         watched file is gone
- ADDED           new file appeared under a watched dir
- SYMLINK_CHANGED symlink target swapped
- CONFIG_DISABLED a watched config key no longer equals its required value
                  (the OpenAI "Sol" pattern: no_notify flipped to true)
- LEDGER_TAMPER   the audit chain itself was edited
- BASELINE_CORRUPT / WATCHER_ERROR  infrastructure failures -- fail OPEN:
                  loud alert, non-zero exit, never a silent green
- CHECK_OK        everything intact
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .baseline import BaselineError, BaselineStore
from .fingerprint import check_config_policy, fingerprint_files


@dataclass
class Finding:
    kind: str
    path: str
    detail: str
    old: str | None = None
    new: str | None = None


@dataclass
class WatchResult:
    findings: list[Finding] = field(default_factory=list)
    fatal: str | None = None  # set when the check itself broke (fail-open path)

    @property
    def tampered(self) -> bool:
        return bool(self.findings)

    @property
    def ok(self) -> bool:
        return not self.findings and self.fatal is None


def _store_hygiene(store: BaselineStore) -> list[Finding]:
    """The store must not be writable by everyone: otherwise the agent being
    watched could rewrite the baseline. Fail OPEN if hygiene is bad."""
    findings = []
    if store.store_dir.exists():
        mode = store.store_dir.stat().st_mode
        if mode & 0o002:
            findings.append(
                Finding(
                    kind="STORE_WORLD_WRITABLE",
                    path=str(store.store_dir),
                    detail="store dir is world-writable; the watched agent could "
                    "rewrite the baseline. Fix permissions or move the store "
                    "to a path the agent cannot write.",
                )
            )
    return findings


def run_check(
    store: BaselineStore,
    watchlist: dict,
    now_manifest: dict | None = None,
) -> WatchResult:
    result = WatchResult()

    # 0. store hygiene (privilege separation signal)
    result.findings.extend(_store_hygiene(store))

    # 1. baseline must exist and verify; anything else is a fail-open fatal.
    try:
        baseline = store.read_baseline()
    except BaselineError as e:
        result.fatal = f"BASELINE_CORRUPT: {e}"
        return result
    except OSError as e:
        result.fatal = f"WATCHER_ERROR: cannot read baseline: {e}"
        return result

    # 2. ledger chain must be intact -- "who watches the watcher"
    chain_ok, chain_msg = store.verify_chain()
    if not chain_ok:
        result.findings.append(
            Finding(
                kind="LEDGER_TAMPER",
                path=str(store.ledger_path),
                detail=f"audit ledger chain broken: {chain_msg}. "
                "Someone edited or deleted history.",
            )
        )

    base_manifest: dict = baseline.get("manifest", {})
    targets: list[str] = watchlist.get("targets", baseline.get("watchlist", {}).get("targets", []))
    if now_manifest is None:
        try:
            now_manifest = fingerprint_files(targets)
        except OSError as e:
            result.fatal = f"WATCHER_ERROR: cannot fingerprint targets: {e}"
            return result

    # 3. compare file by file
    for path, old in base_manifest.items():
        cur = now_manifest.get(path)
        if cur is None:
            result.findings.append(
                Finding(kind="REMOVED", path=path,
                        detail="watched file was deleted", old=old.get("sha256"))
            )
            continue
        if old.get("error") or cur.get("error"):
            result.findings.append(
                Finding(kind="UNREADABLE", path=path,
                        detail=f"was={old.get('error')} now={cur.get('error')}")
            )
            continue
        if old.get("is_symlink") or cur.get("is_symlink"):
            if old.get("link_target") != cur.get("link_target"):
                result.findings.append(
                    Finding(kind="SYMLINK_CHANGED", path=path,
                            detail="symlink target swapped",
                            old=str(old.get("link_target")),
                            new=str(cur.get("link_target")))
                )
            continue
        if old.get("sha256") != cur.get("sha256"):
            result.findings.append(
                Finding(kind="MODIFIED", path=path,
                        detail=f"content changed ({old.get('size')} -> {cur.get('size')} bytes)",
                        old=old.get("sha256"), new=cur.get("sha256"))
            )
    for path in now_manifest:
        if path not in base_manifest:
            result.findings.append(
                Finding(kind="ADDED", path=path,
                        detail="new file appeared under a watched path "
                        "(could be a replacement hook or a bypass)")
            )

    # 4. config policy checks -- the "quietly disabled" detector
    config_checks = watchlist.get(
        "config_checks", baseline.get("watchlist", {}).get("config_checks", [])
    )
    for cc in config_checks:
        cpath = cc.get("file", "")
        key = cc.get("key", "")
        must_equal = cc.get("must_equal")
        if not Path(cpath).exists():
            result.findings.append(
                Finding(kind="REMOVED", path=cpath,
                        detail=f"watched config file missing (policy key '{key}' unchecked)")
            )
            continue
        ok, actual, present = check_config_policy(cpath, key, must_equal)
        if not ok:
            result.findings.append(
                Finding(kind="CONFIG_DISABLED", path=cpath,
                        detail=f"config key '{key}' must equal {must_equal!r} "
                        f"but is {actual!r} (present={present}) -- "
                        "guardrail was weakened without a file being deleted")
            )

    return result
