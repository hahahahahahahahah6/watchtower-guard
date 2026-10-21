"""Tests for watchtower-guard. No network. Uses tmp dirs only."""

import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from watchtower_guard import BaselineStore  # noqa: E402
from watchtower_guard.alerts import fire_alerts, set_webhook_sink  # noqa: E402
from watchtower_guard.audit import render_timeline, verify_chain  # noqa: E402
from watchtower_guard.baseline import BASELINE_NAME, LEDGER_NAME, BaselineError  # noqa: E402
from watchtower_guard.watcher import run_check  # noqa: E402


@pytest.fixture()
def env(tmp_path):
    """A watched 'agent guardrail' dir, a watchlist, a key, and a store."""
    hooks = tmp_path / "agent_hooks"
    hooks.mkdir()
    (hooks / "edit_guard.py").write_text("# blocks risky edits\nBLOCK = True\n")
    (hooks / "push_guard.py").write_text("# blocks pushes to main\n")
    settings = hooks / "settings.json"
    settings.write_text(json.dumps({"no_notify": False,
                                    "notify_recipients": ["security@example.com"]}))
    watchlist = {
        "targets": [str(hooks)],
        "config_checks": [{"file": str(settings), "key": "no_notify",
                           "must_equal": False}],
    }
    key = BaselineStore.generate_key()
    store = BaselineStore(tmp_path / "store", key)
    store.write_baseline(__import__("watchtower_guard.fingerprint",
                                    fromlist=["fingerprint_files"]).fingerprint_files(
                                        watchlist["targets"]), watchlist)
    return {"hooks": hooks, "settings": settings, "watchlist": watchlist,
            "store": store, "key": key, "tmp": tmp_path}


def kinds(result):
    return {f.kind for f in result.findings}


def test_01_intact_check_passes(env):
    result = run_check(env["store"], env["watchlist"])
    assert result.ok, [f.detail for f in result.findings]


def test_02_modified_hook_detected(env):
    (env["hooks"] / "edit_guard.py").write_text("# NEUTERED\nBLOCK = False\n")
    result = run_check(env["store"], env["watchlist"])
    assert "MODIFIED" in kinds(result)
    mod = [f for f in result.findings if f.kind == "MODIFIED"][0]
    assert mod.old != mod.new and mod.new is not None


def test_03_removed_hook_detected(env):
    (env["hooks"] / "push_guard.py").unlink()
    result = run_check(env["store"], env["watchlist"])
    assert "REMOVED" in kinds(result)


def test_04_quiet_config_disable_detected(env):
    # the OpenAI "Sol" pattern: file still there, alerts silently switched off
    env["settings"].write_text(json.dumps({"no_notify": True,
                                           "notify_recipients": []}))
    result = run_check(env["store"], env["watchlist"])
    assert "CONFIG_DISABLED" in kinds(result)
    cd = [f for f in result.findings if f.kind == "CONFIG_DISABLED"][0]
    assert "no_notify" in cd.detail


def test_05_added_file_detected(env):
    (env["hooks"] / "backdoor_hook.py").write_text("# added by someone\n")
    result = run_check(env["store"], env["watchlist"])
    assert "ADDED" in kinds(result)


def test_06_ledger_backedit_detected(env):
    store = env["store"]
    store.append("CHECK_OK", {})
    # attacker edits history: rewrite the first entry's details
    lines = (store.ledger_path).read_text().splitlines()
    e = json.loads(lines[0])
    e["details"] = {"forged": True}
    lines[0] = json.dumps(e, sort_keys=True)
    store.ledger_path.write_text("\n".join(lines) + "\n")
    ok, msg = verify_chain(store)
    assert not ok, "chain must break when history is edited"
    result = run_check(store, env["watchlist"])
    assert "LEDGER_TAMPER" in kinds(result)


def test_07_corrupt_baseline_fails_open_loud(env):
    store = env["store"]
    (store.store_dir / BASELINE_NAME).write_text("{corrupt json")
    result = run_check(store, env["watchlist"])
    assert result.fatal is not None and "BASELINE_CORRUPT" in result.fatal
    assert not result.ok
    # fail-open means: an alert ledger entry is still written, loudly
    delivered = fire_alerts(store, result)
    assert delivered["ledger_seq"] >= 1
    events = [e["event"] for e in store.iter_ledger()]
    assert "WATCHER_ERROR" in events


def test_08_world_writable_store_flagged(env):
    os.chmod(env["store"].store_dir, 0o777)
    try:
        result = run_check(env["store"], env["watchlist"])
    finally:
        os.chmod(env["store"].store_dir, 0o755)
    assert "STORE_WORLD_WRITABLE" in kinds(result)


def test_09_webhook_sink_gets_payload_no_network(env):
    captured = []
    set_webhook_sink(lambda url, payload: captured.append((url, payload)))
    try:
        (env["hooks"] / "edit_guard.py").write_text("tampered\n")
        result = run_check(env["store"], env["watchlist"])
        delivered = fire_alerts(env["store"], result,
                                webhook_url="https://example.invalid/hook")
    finally:
        set_webhook_sink(None)
    assert delivered["webhook"] is True
    url, payload = captured[0]
    assert url == "https://example.invalid/hook"
    assert "tampering detected" in payload["title"]
    assert payload["event"] == "TAMPER_DETECTED"


def test_10_audit_timeline_renders(env):
    store = env["store"]
    store.append("CHECK_OK", {})
    (env["hooks"] / "push_guard.py").unlink()
    result = run_check(store, env["watchlist"])
    fire_alerts(store, result)
    ok, _ = verify_chain(store)
    assert ok
    timeline = render_timeline(store)
    assert "CHECK_OK" in timeline and "TAMPER_DETECTED" in timeline
    assert "REMOVED" in timeline


def test_11_wrong_key_rejects_forged_baseline(env):
    # agent without the key cannot mint a clean baseline after tampering
    evil = BaselineStore(env["store"].store_dir, BaselineStore.generate_key())
    (env["hooks"] / "edit_guard.py").write_text("tampered\n")
    from watchtower_guard.fingerprint import fingerprint_files
    evil.write_baseline(fingerprint_files(env["watchlist"]["targets"]),
                        env["watchlist"])
    with pytest.raises(BaselineError):
        BaselineStore(env["store"].store_dir, env["key"]).read_baseline()


def test_12_symlink_swap_detected(env):
    target_a = env["tmp"] / "a.py"
    target_a.write_text("# a\n")
    link = env["hooks"] / "linked_hook.py"
    link.symlink_to(target_a)
    from watchtower_guard.fingerprint import fingerprint_files
    store = env["store"]
    store.write_baseline(fingerprint_files(env["watchlist"]["targets"]),
                         env["watchlist"])
    target_b = env["tmp"] / "b.py"
    target_b.write_text("# b - malicious\n")
    link.unlink()
    link.symlink_to(target_b)
    result = run_check(store, env["watchlist"])
    assert "SYMLINK_CHANGED" in kinds(result)
