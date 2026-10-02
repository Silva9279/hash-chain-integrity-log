# Hash Chain Integrity Log

An append-only log where each entry stores the SHA256 of the previous entry, producing a tamper-evident record chain for audit trails.

```python
from hash_chain_integrity_log import HashChainLog, VerificationResult

log = HashChainLog(clock=lambda: "2024-01-01T00:00:00Z")
log.append({"user": "alice", "action": "login"})
log.append({"user": "alice", "action": "logout"})

result: VerificationResult = log.verify()
assert result.valid

records = log.to_records()          # list of plain dicts for JSON storage
restored = HashChainLog.from_records(records)
assert restored.verify().valid
```

## Why this exists

Audit logs need to survive storage in environments where the store itself cannot be fully trusted — a flat JSON file, a database row a privileged user can touch, or a log shipper that may reorder lines. By chaining each entry's hash to the previous entry's hash, any retroactive edit, deletion, or reordering breaks the chain at that point and is caught by `verify()`.

The trade-off: this is detection, not prevention. It will not stop someone from rewriting the log; it will tell you exactly where the rewrite happened. If you need confidentiality or true immutability, use a WORM device or an external notary service — this library is the lightweight, dependency-free layer for the common case where "I need to know if the log was touched" is enough.

## Edge cases you will hit

- **Payloads must be JSON-serialisable.** The hash is computed over a canonical JSON encoding of the entry, so objects with custom types or non-serialisable values will raise `TypeError` on `append`. Use plain dicts, lists, strings, numbers, booleans, and `None`.
- **Dict key order does not matter.** Serialisation uses `sort_keys=True`, so `{"a": 1, "b": 2}` and `{"b": 2, "a": 1}` hash identically. Do not rely on insertion order for distinctness.
- **The clock is injectable.** The default clock returns an empty string, making the log deterministic without configuration. Pass a callable returning a string (ISO-8601, epoch, a counter — your choice) if you want timestamps in the entries.
- **`from_records` does not recompute hashes.** It trusts the stored hashes and lets `verify()` catch any mismatch. This is intentional: silently recomputing hashes on load would hide exactly the tampering the chain is meant to expose.

## Exported names

- `HashChainLog` — the log class. Constructor: `HashChainLog(clock=None)`. Methods: `append(payload)`, `verify()`, `to_records()`, `from_records(records, clock=None)` (classmethod), `entries` (property), `length` (property), `head()`.
- `ChainEntry` — frozen dataclass for a single entry. Fields: `index`, `timestamp`, `payload`, `prev_hash`, `hash`. Methods: `to_record()`, `compute_hash()`, `from_record(record)` (classmethod).
- `VerificationResult` — frozen dataclass. Fields: `valid` (bool), `broken_at` (int or None), `reason` (str or None).
