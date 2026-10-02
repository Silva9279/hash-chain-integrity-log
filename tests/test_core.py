import json
import unittest

from hash_chain_integrity_log import HashChainLog, ChainEntry, VerificationResult


class TestAppend(unittest.TestCase):
    def test_first_entry_has_empty_prev_hash(self):
        log = HashChainLog(clock=lambda: "t0")
        entry = log.append({"event": "boot"})
        self.assertEqual(entry.index, 0)
        self.assertEqual(entry.prev_hash, "")
        self.assertEqual(entry.timestamp, "t0")
        self.assertEqual(entry.payload, {"event": "boot"})
        self.assertEqual(len(entry.hash), 64)

    def test_second_entry_links_to_first(self):
        log = HashChainLog(clock=lambda: "t0")
        first = log.append("a")
        second = log.append("b")
        self.assertEqual(second.prev_hash, first.hash)
        self.assertEqual(second.index, 1)

    def test_append_returns_immutable_entry(self):
        log = HashChainLog()
        entry = log.append({"x": 1})
        with self.assertRaises(Exception):
            entry.payload = 2  # type: ignore[misc]

    def test_default_clock_yields_empty_string(self):
        log = HashChainLog()
        entry = log.append(42)
        self.assertEqual(entry.timestamp, "")

    def test_payload_must_be_json_serialisable(self):
        log = HashChainLog()
        with self.assertRaises(TypeError):
            log.append(object())


class TestHashDeterminism(unittest.TestCase):
    def test_same_payload_same_clock_produces_same_hash(self):
        log_a = HashChainLog(clock=lambda: "t")
        log_b = HashChainLog(clock=lambda: "t")
        a = log_a.append({"k": [1, 2, 3]})
        b = log_b.append({"k": [1, 2, 3]})
        self.assertEqual(a.hash, b.hash)

    def test_dict_key_order_does_not_affect_hash(self):
        log_a = HashChainLog(clock=lambda: "t")
        log_b = HashChainLog(clock=lambda: "t")
        a = log_a.append({"a": 1, "b": 2})
        b = log_b.append({"b": 2, "a": 1})
        self.assertEqual(a.hash, b.hash)

    def test_compute_hash_matches_stored(self):
        log = HashChainLog(clock=lambda: "t")
        entry = log.append({"n": 7})
        self.assertEqual(entry.hash, entry.compute_hash())


class TestVerify(unittest.TestCase):
    def test_empty_log_is_valid(self):
        log = HashChainLog()
        result = log.verify()
        self.assertTrue(result.valid)
        self.assertIsNone(result.broken_at)
        self.assertIsNone(result.reason)

    def test_fresh_log_is_valid(self):
        log = HashChainLog(clock=lambda: "t")
        log.append("a")
        log.append("b")
        log.append("c")
        self.assertTrue(log.verify().valid)

    def test_mutation_of_payload_breaks_chain(self):
        log = HashChainLog(clock=lambda: "t")
        log.append("a")
        log.append("b")
        # Mutate the first entry's payload in place by rebuilding the list.
        records = log.to_records()
        records[0]["payload"] = "tampered"
        tampered = HashChainLog.from_records(records)
        result = tampered.verify()
        self.assertFalse(result.valid)
        self.assertEqual(result.broken_at, 0)

    def test_mutation_of_timestamp_breaks_chain(self):
        log = HashChainLog(clock=lambda: "t")
        log.append("a")
        log.append("b")
        records = log.to_records()
        records[1]["timestamp"] = "forged"
        tampered = HashChainLog.from_records(records)
        result = tampered.verify()
        self.assertFalse(result.valid)
        self.assertEqual(result.broken_at, 1)

    def test_reordering_breaks_prev_link(self):
        log = HashChainLog(clock=lambda: "t")
        log.append("a")
        log.append("b")
        log.append("c")
        records = log.to_records()
        # Swap entries 1 and 2.
        records[1], records[2] = records[2], records[1]
        tampered = HashChainLog.from_records(records)
        result = tampered.verify()
        self.assertFalse(result.valid)

    def test_genesis_with_nonempty_prev_hash_breaks(self):
        log = HashChainLog(clock=lambda: "t")
        log.append("a")
        records = log.to_records()
        records[0]["prev_hash"] = "deadbeef"
        # Recompute the stored hash so only the prev_hash invariant fails.
        entry = ChainEntry.from_record(records[0])
        records[0]["hash"] = entry.compute_hash()
        tampered = HashChainLog.from_records(records)
        result = tampered.verify()
        self.assertFalse(result.valid)
        self.assertEqual(result.broken_at, 0)
        self.assertIn("genesis", result.reason)

    def test_stored_hash_tamper_is_detected(self):
        log = HashChainLog(clock=lambda: "t")
        log.append("a")
        log.append("b")
        records = log.to_records()
        records[1]["hash"] = "0" * 64
        tampered = HashChainLog.from_records(records)
        result = tampered.verify()
        self.assertFalse(result.valid)
        self.assertEqual(result.broken_at, 1)


class TestPersistence(unittest.TestCase):
    def test_roundtrip_through_json(self):
        log = HashChainLog(clock=lambda: "t0")
        log.append({"user": "alice", "action": "login"})
        log.append({"user": "alice", "action": "logout"})
        dumped = json.dumps(log.to_records())
        loaded = HashChainLog.from_records(json.loads(dumped))
        self.assertEqual(loaded.length, 2)
        self.assertTrue(loaded.verify().valid)
        self.assertEqual(loaded.entries[0].payload["action"], "login")

    def test_clock_used_after_from_records(self):
        log = HashChainLog(clock=lambda: "t0")
        log.append("a")
        records = log.to_records()
        restored = HashChainLog.from_records(records, clock=lambda: "t1")
        new_entry = restored.append("b")
        self.assertEqual(new_entry.timestamp, "t1")
        self.assertEqual(new_entry.prev_hash, records[0]["hash"])


class TestAccessors(unittest.TestCase):
    def test_entries_returns_copy(self):
        log = HashChainLog()
        log.append("a")
        snapshot = log.entries
        snapshot.clear()
        self.assertEqual(log.length, 1)

    def test_head_of_empty_log(self):
        log = HashChainLog()
        self.assertIsNone(log.head())

    def test_head_returns_latest(self):
        log = HashChainLog(clock=lambda: "t")
        log.append("a")
        last = log.append("b")
        self.assertEqual(log.head().hash, last.hash)


class TestResultTypes(unittest.TestCase):
    def test_verification_result_is_frozen(self):
        result = VerificationResult(valid=True, broken_at=None, reason=None)
        with self.assertRaises(Exception):
            result.valid = False  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
