"""watchtower-guard: tamper-evident integrity watcher for an agent's own guardrails.

Who watches the watchers? This package fingerprints the files that make up an
agent's safety layer (hook scripts, hook configs, policy files) and keeps a
signed, hash-chained, append-only audit ledger. A watcher that runs outside the
agent's control plane re-hashes everything on a schedule and raises an
out-of-band alert when anything was modified, removed, added, or quietly
disabled -- with attribution of what changed and when.

It cannot stop a root-level attacker. It only makes tampering evident.
"""

__version__ = "0.1.0"

from .fingerprint import fingerprint_files, sha256_file, load_json
from .baseline import BaselineStore
from .watcher import WatchResult, run_check
from .audit import read_ledger, verify_chain

__all__ = [
    "__version__",
    "fingerprint_files",
    "sha256_file",
    "load_json",
    "BaselineStore",
    "WatchResult",
    "run_check",
    "read_ledger",
    "verify_chain",
]
