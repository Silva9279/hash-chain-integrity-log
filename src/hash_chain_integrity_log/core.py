"""Append-only, tamper-evident log chained by SHA256.

Each entry's hash covers the previous entry's hash plus the entry's own
payload and metadata, so any mutation of a stored entry breaks the chain
at that point and is detectable by :meth:`HashChainLog.verify`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Callable, List, Optional


def _sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(obj: object) -> bytes:
    """Serialise *obj* to deterministic JSON bytes.

    Why deterministic: the chain hash is computed over the serialised entry,
    so a single entry must always serialise to the same bytes regardless of
    dict insertion order or platform. ``sort_keys`` plus fixed separators
    gives that stability.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class ChainEntry:
    """A single record in the chain.

    ``prev_hash`` is the hash of the preceding entry, or the empty string
    for the genesis entry (index 0). ``hash`` is the hash of *this* entry,
    computed over its index, timestamp, payload, and ``prev_hash``.
    """

    index: int
    timestamp: str
    payload: object
    prev_hash: str
    hash: str

    @classmethod
    def from_record(cls, record: dict) -> "ChainEntry":
        """Reconstruct a :class:`ChainEntry` from a plain dict.

        Used when loading persisted records. We deliberately do not recompute
        the hash here; :meth:`HashChainLog.verify` does that, so tampering is
        caught rather than silently papered over.
        """
        return cls(
            index=record["index"],
            timestamp=record["timestamp"],
            payload=record["payload"],
            prev_hash=record["prev_hash"],
            hash=record["hash"],
        )

    def to_record(self) -> dict:
        """Return a plain dict suitable for JSON persistence."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }

    def compute_hash(self) -> str:
        """Recompute this entry's hash from its fields.

        The hash covers index, timestamp, payload, and prev_hash. The payload
        is serialised with deterministic JSON so that arbitrary JSON-able
        objects hash stably.
        """
        body = {
            "index": self.index,
            "timestamp": self.timestamp,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
        }
        return _sha256_hex(_canonical_json_bytes(body))


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of :meth:`HashChainLog.verify`.

    ``valid`` is True only if every entry's stored hash matches its computed
    hash and every entry's ``prev_hash`` matches the previous entry's hash.
    On failure, ``broken_at`` is the index of the first entry where the chain
    was found to be broken, and ``reason`` is a short human-readable string.
    """

    valid: bool
    broken_at: Optional[int]
    reason: Optional[str]


class HashChainLog:
    """An append-only log whose entries form a SHA256 chain.

    The log takes a ``clock`` callable returning a string timestamp, so tests
    can inject a deterministic time source. The timestamp is stored as a plain
    string rather than a numeric epoch so callers are free to use ISO-8601,
    a counter, or any format they prefer; the chain only requires that the
    value be reproducible for hashing.
    """

    def __init__(self, clock: Callable[[], str] = None) -> None:
        # Default to an empty-string timestamp so the log is deterministic
        # out of the box; callers who care about real time pass a clock.
        self._clock: Callable[[], str] = clock if clock is not None else (lambda: "")
        self._entries: List[ChainEntry] = []

    def append(self, payload: object) -> ChainEntry:
        """Append *payload* to the log and return the new entry.

        ``payload`` must be JSON-serialisable (dict, list, str, int, float,
        bool, None, or nested combinations), because it is hashed via a
        canonical JSON encoding. Non-serialisable payloads raise
        ``TypeError`` from ``json.dumps``.
        """
        prev_hash = self._entries[-1].hash if self._entries else ""
        index = len(self._entries)
        entry = ChainEntry(
            index=index,
            timestamp=self._clock(),
            payload=payload,
            prev_hash=prev_hash,
            hash="",
        )
        entry = ChainEntry(
            index=entry.index,
            timestamp=entry.timestamp,
            payload=entry.payload,
            prev_hash=entry.prev_hash,
            hash=entry.compute_hash(),
        )
        self._entries.append(entry)
        return entry

    @property
    def entries(self) -> List[ChainEntry]:
        """Return a shallow copy of the entry list.

        A copy prevents callers from mutating the internal list in place,
        which would desynchronise the chain without updating hashes.
        """
        return list(self._entries)

    @property
    def length(self) -> int:
        """Number of entries currently in the log."""
        return len(self._entries)

    def head(self) -> Optional[ChainEntry]:
        """Return the most recent entry, or ``None`` if the log is empty."""
        return self._entries[-1] if self._entries else None

    def verify(self) -> VerificationResult:
        """Verify the integrity of the entire chain.

        Checks two invariants per entry:
        1. The stored ``hash`` equals the hash recomputed from the entry's
           fields (detects mutation of payload, timestamp, index, or
           prev_hash).
        2. The stored ``prev_hash`` equals the previous entry's stored
           ``hash`` (detects reordering, insertion, or deletion).

        The genesis entry (index 0) must have ``prev_hash == ""``.
        """
        for i, entry in enumerate(self._entries):
            if entry.index != i:
                return VerificationResult(
                    valid=False,
                    broken_at=i,
                    reason=f"index mismatch at {i}: stored {entry.index}",
                )
            if i == 0:
                if entry.prev_hash != "":
                    return VerificationResult(
                        valid=False,
                        broken_at=i,
                        reason="genesis entry prev_hash must be empty",
                    )
            else:
                prev = self._entries[i - 1]
                if entry.prev_hash != prev.hash:
                    return VerificationResult(
                        valid=False,
                        broken_at=i,
                        reason="prev_hash does not match previous entry hash",
                    )
            if entry.hash != entry.compute_hash():
                return VerificationResult(
                    valid=False,
                    broken_at=i,
                    reason="stored hash does not match computed hash",
                )
        return VerificationResult(valid=True, broken_at=None, reason=None)

    @classmethod
    def from_records(cls, records: List[dict], clock: Callable[[], str] = None) -> "HashChainLog":
        """Build a log from previously persisted records.

        The clock is accepted for API symmetry with the constructor but is
        not used during reconstruction, since each record already carries its
        own timestamp. It will, however, be used for any subsequent
        :meth:`append` calls.
        """
        log = cls(clock=clock)
        for record in records:
            log._entries.append(ChainEntry.from_record(record))
        return log

    def to_records(self) -> List[dict]:
        """Serialise the log to a list of plain dicts for persistence."""
        return [entry.to_record() for entry in self._entries]
