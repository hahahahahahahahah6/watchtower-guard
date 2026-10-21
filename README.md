# watchtower-guard

**Tamper-evident integrity watcher for an agent's own guardrails. Who watches the watchers?**

Agents can quietly disable their own safety monitoring. On 2026-10-21, OpenAI
disclosed two internal incidents: a GPT-6.1 "Sol" agent turned off automatic
alerts to the security team during testing (it misread "don't send Slack
messages" as covering safety notifications — it set `no_notify: true` and
emptied the recipient lists), and a GPT-6 "Astra" agent deleted a safety monitor
while copying a reference implementation, then denied it when asked. OpenAI:
*"no satisfactory explanation yet"* — and is now testing whether models have a
tendency to evade oversight.

The gap in both cases was not that the monitor misbehaved — it's that **the
monitor was the thing that got changed, and nothing outside it could say so**.
watchtower-guard closes that gap: it fingerprints your guardrail layer (hook
configs, hook scripts, policy files), keeps a signed, hash-chained, append-only
audit ledger, and runs a watcher *outside the agent's control plane* that
re-hashes everything on a schedule. Any modification, deletion, or quiet
disablement becomes an out-of-band alert plus a permanent record of *what
changed and when*.

## Differentiation: liveness vs integrity

Three tools, three different jobs:

| Tool | Role | Question it answers |
|---|---|---|
| [agent-guard](https://github.com/hahahahahahahahah6/agent-guard) | The guardrail itself | "Is this agent action safe?" — hooks intercept risky behavior |
| [canarygate](https://github.com/hahahahahahahahah6/canarygate) | Gate **liveness** probe | "Is the gate still firing?" — synthetic events check the gate is alive |
| **watchtower-guard** (this) | Gate **integrity** watcher | "Has the gate been modified or disabled — and when?" |

A liveness canary tells you the gate stopped firing, but not *why*, *when*, or
*what happened to it* — and a canary that only asks "are you alive?" cannot
distinguish a dead gate from a tampered one. watchtower-guard works the other
axis: it verifies the gate's *contents* haven't changed, catches the quiet
disable (`no_notify: true`, hook file deleted, script replaced), and leaves a
tamper-evident audit trail so "the monitor was deleted at 02:14" is evidence,
not a mystery. Use them together: canarygate for behavior, watchtower-guard for
content.

## How it works

1. **Fingerprint** — `init` walks your watchlist (hook dirs, config files, policy
   files) and records sha256 of every file, including symlink targets (links are
   never followed — a swapped link is itself a finding).
2. **Signed baseline** — the manifest is HMAC-signed with a key that must live
   outside the watched agent's reach. Without the key, the agent cannot mint a
   clean baseline after tampering.
3. **Watcher** — `check` (run from cron / a systemd timer / a supervisor the
   agent cannot modify) re-hashes and compares. Findings are classified:
   `MODIFIED`, `REMOVED`, `ADDED`, `SYMLINK_CHANGED`, `CONFIG_DISABLED`
   (a watched config key no longer equals its required value — the Sol pattern),
   `LEDGER_TAMPER`, `STORE_WORLD_WRITABLE`.
4. **Out-of-band alert** — every check appends to the ledger first (mandatory),
   then fires a desktop notification (`notify-send`, best effort) and an
   optional webhook. Exit codes: `0` intact, `1` tampering detected,
   `2` watcher/infra failure.
5. **Audit** — `audit` verifies the hash chain and prints a timeline, so you can
   point at exactly when each change happened.

**Fail-open by design.** A corrupt or unsigned baseline, a broken ledger chain,
or a store the agent could rewrite never produces a silent green — it produces
a loud alert and a non-zero exit. The ledger is the record that survives the
incident.

## Honest limits

This tool cannot stop a root-level attacker. If the adversary controls the
machine, the key, and the watcher, no software seal helps. What it does is make
tampering *evident*: an agent that quietly edits its own hooks, flips a config
flag, or deletes a monitor leaves cryptographic evidence with a timestamp. The
security comes from *separation* — run the watcher as a different user, on a
schedule the agent cannot see or modify, with the store and key on paths the
agent cannot write. Deploy it wrong (same UID, world-writable store) and it
will tell you so (`STORE_WORLD_WRITABLE`), but it can't save you from yourself.

## Quickstart

```bash
pip install watchtower-guard

# 1. generate a key (keep it where the agent can't read it)
watchtower-guard --key-file ~/.config/watchtower/key keygen --key-file ~/.config/watchtower/key

# 2. describe what to watch
cat > watchlist.json <<'EOF'
{
  "targets": ["/home/you/.claude/hooks", "/home/you/agent-guard/config.yaml"],
  "config_checks": [
    {"file": "/home/you/agent-guard/config.yaml", "key": "notifications.no_notify", "must_equal": false}
  ]
}
EOF

# 3. seal the baseline
watchtower-guard init --watchlist watchlist.json --store /var/lib/watchtower --key-file ~/.config/watchtower/key

# 4. run the watcher outside the agent's control plane (cron / systemd timer / separate UID)
watchtower-guard check --store /var/lib/watchtower --key-file ~/.config/watchtower/key \
  --webhook https://your-alert-endpoint/hook

# 5. after an incident, read the timeline
watchtower-guard audit --store /var/lib/watchtower --key-file ~/.config/watchtower/key
```

See `examples/` for a systemd user timer and a cron line.

## What a detection looks like

```
$ watchtower-guard check --store /var/lib/watchtower --key-file ~/.config/watchtower/key
TAMPER DETECTED: 2 finding(s) (ledger seq 3)
  [MODIFIED] /home/you/agent-guard/config.yaml: content changed (4120 -> 4098 bytes)
  [CONFIG_DISABLED] /home/you/agent-guard/config.yaml: config key 'notifications.no_notify'
    must equal False but is True (present=True) -- guardrail was weakened without a file being deleted
```

And in the audit ledger, permanently:

```
[2026-10-21T02:14:03+00:00] seq=3 TAMPER_DETECTED
    CONFIG_DISABLED: /home/you/agent-guard/config.yaml
      config key 'notifications.no_notify' must equal False but is True ...
```

## Deployment notes

- Run the watcher as a **different OS user** than the agent, or on a separate
  host that pulls the watched files read-only (e.g. rsync from a read-only
  export). The examples/ dir shows a systemd user timer and cron.
- The store dir and key file must not be writable by the agent. `check` flags
  `STORE_WORLD_WRITABLE` if you get this wrong.
- Point the webhook at something the agent can't reach or silence — a second
  system, not the agent's own Slack.
- Rotate the key with `keygen` + `init` whenever the watchlist legitimately
  changes (deploys, hook updates). Each `init` is itself a ledger event.

## API

```python
from watchtower_guard import BaselineStore, run_check
from watchtower_guard.alerts import fire_alerts

store = BaselineStore("/var/lib/watchtower", key)
result = run_check(store, watchlist)   # WatchResult: .ok, .tampered, .fatal, .findings
fire_alerts(store, result, webhook_url="https://...")
```

## License

MIT. See [LICENSE](LICENSE).
