"""CLI: init | check | audit | keygen

Typical setup (run as the HUMAN's user, outside the agent's control plane):

    python -m watchtower_guard keygen --key-file ~/.config/watchtower/key
    python -m watchtower_guard init --watchlist watchlist.json --store /var/lib/watchtower --key-file ~/.config/watchtower/key

Then on a schedule the agent cannot touch (systemd user timer, cron, separate UID):

    python -m watchtower_guard check --store /var/lib/watchtower --key-file ~/.config/watchtower/key --webhook https://...

Exit codes: 0 = intact, 1 = tampering detected, 2 = watcher/infra failure (fail-open).
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from .alerts import fire_alerts
from .audit import render_timeline
from .baseline import BaselineError, BaselineStore
from .fingerprint import fingerprint_files, load_json
from .watcher import run_check

DEFAULT_KEY_ENV = "WATCHTOWER_KEY"


def _load_key(args) -> bytes:
    if getattr(args, "key_file", None):
        data = Path(args.key_file).read_bytes().strip()
        return data
    env = os.environ.get(DEFAULT_KEY_ENV)
    if env:
        return env.encode("utf-8")
    sys.stderr.write(
        f"error: no key. Use --key-file or set {DEFAULT_KEY_ENV} "
        "(generate one with: python -m watchtower_guard keygen)\n"
    )
    sys.exit(2)


def _load_watchlist(path: str) -> dict:
    try:
        wl = load_json(path)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        sys.stderr.write(f"error: cannot read watchlist {path}: {e}\n")
        sys.exit(2)
    if not isinstance(wl, dict) or not wl.get("targets"):
        sys.stderr.write("error: watchlist must be JSON with a non-empty 'targets' list\n")
        sys.exit(2)
    return wl


def cmd_keygen(args) -> int:
    key = BaselineStore.generate_key().hex()
    if args.key_file:
        p = Path(args.key_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key + "\n")
        print(f"wrote key to {p} (mode 0600)")
    else:
        print(key)
    return 0


def cmd_init(args) -> int:
    watchlist = _load_watchlist(args.watchlist)
    key = _load_key(args)
    store = BaselineStore(args.store, key)
    manifest = fingerprint_files(watchlist["targets"])
    payload = store.write_baseline(manifest, watchlist)
    store.append("BASELINE_CREATED", {
        "files": len(manifest),
        "targets": watchlist["targets"],
        "config_checks": watchlist.get("config_checks", []),
    })
    print(f"baseline written to {store.baseline_path} "
          f"({len(manifest)} files, created {payload['created']})")
    print("IMPORTANT: keep the key and the store outside the watched agent's reach.")
    return 0


def cmd_check(args) -> int:
    key = _load_key(args)
    store = BaselineStore(args.store, key)
    watchlist = _load_watchlist(args.watchlist) if args.watchlist else {}
    try:
        result = run_check(store, watchlist)
    except Exception as e:  # total watcher failure -- fail OPEN, loudly
        print(f"WATCHTOWER-GUARD WATCHER FAILURE: {e}", file=sys.stderr)
        try:
            store.append("WATCHER_ERROR", {"fatal": str(e)})
        except Exception as le:
            print(f"could not write ledger either: {le}", file=sys.stderr)
        return 2
    delivered = fire_alerts(store, result, webhook_url=args.webhook)
    if result.fatal:
        print(f"WATCHER FAILURE (fail-open): {result.fatal}", file=sys.stderr)
        return 2
    if result.tampered:
        print(f"TAMPER DETECTED: {len(result.findings)} finding(s) "
              f"(ledger seq {delivered['ledger_seq']})")
        for f in result.findings:
            print(f"  [{f.kind}] {f.path}: {f.detail}")
        return 1
    print(f"OK: guardrails intact (ledger seq {delivered['ledger_seq']})")
    return 0


def cmd_audit(args) -> int:
    key = _load_key(args)
    store = BaselineStore(args.store, key)
    try:
        baseline = store.read_baseline()
    except BaselineError as e:
        print(f"baseline problem: {e}", file=sys.stderr)
        return 2
    print(f"baseline created: {baseline.get('created')} "
          f"({len(baseline.get('manifest', {}))} files fingerprinted)")
    print(render_timeline(store))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="watchtower_guard",
                                 description="Tamper-evident watcher for an agent's guardrails.")
    key_parent = argparse.ArgumentParser(add_help=False)
    key_parent.add_argument("--key-file", default=None,
                            help="path to HMAC key file (mode 0600)")
    ap.add_argument("--key-file", default=None,
                    help="path to HMAC key file (mode 0600)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen", help="generate an HMAC key", parents=[key_parent])
    kg.set_defaults(func=cmd_keygen)

    ini = sub.add_parser("init", help="create signed baseline + genesis ledger entry", parents=[key_parent])
    ini.add_argument("--watchlist", required=True)
    ini.add_argument("--store", required=True)
    ini.set_defaults(func=cmd_init)

    chk = sub.add_parser("check", help="re-hash, compare, alert (run on a schedule)", parents=[key_parent])
    chk.add_argument("--store", required=True)
    chk.add_argument("--watchlist", default=None,
                     help="re-read targets/config checks (defaults to baseline's)")
    chk.add_argument("--webhook", default=None)
    chk.set_defaults(func=cmd_check)

    aud = sub.add_parser("audit", help="verify chain + print timeline", parents=[key_parent])
    aud.add_argument("--store", required=True)
    aud.set_defaults(func=cmd_audit)

    args = ap.parse_args(argv)
    # key files must not be group/world readable
    kf = getattr(args, "key_file", None)
    if kf and Path(kf).exists():
        mode = stat.S_IMODE(Path(kf).stat().st_mode)
        if mode & 0o077:
            sys.stderr.write(f"error: key file {kf} is too permissive "
                             f"({oct(mode)}); chmod 600 it\n")
            sys.exit(2)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
