import sys
import os
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.database import AttackDatabase


def _sample_event(**kwargs):
    base = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attacker_ip": "192.168.1.1",
        "attacker_port": 54321,
        "honeypot_type": "SSH",
        "attack_type": "SSH_BRUTE_FORCE",
        "raw_data": "test payload",
        "threat_level": "MEDIUM",
        "attack_pattern": "BRUTE_FORCE",
    }
    base.update(kwargs)
    return base


class TestAttackDatabaseSetup(unittest.TestCase):
    def setUp(self):
        AttackDatabase._reset_instance()
        self.db = AttackDatabase.get_instance(":memory:")

    def tearDown(self):
        AttackDatabase._reset_instance()

    def test_instance_created(self):
        self.assertIsNotNone(self.db)

    def test_singleton(self):
        db2 = AttackDatabase.get_instance(":memory:")
        self.assertIs(self.db, db2)

    def test_reset_creates_new_instance(self):
        AttackDatabase._reset_instance()
        db2 = AttackDatabase.get_instance(":memory:")
        self.assertIsNot(self.db, db2)


class TestRecordAttack(unittest.TestCase):
    def setUp(self):
        AttackDatabase._reset_instance()
        self.db = AttackDatabase.get_instance(":memory:")

    def tearDown(self):
        AttackDatabase._reset_instance()

    def test_record_returns_id(self):
        row_id = self.db.record_attack(_sample_event())
        self.assertIsInstance(row_id, int)
        self.assertGreater(row_id, 0)

    def test_multiple_records_increment_id(self):
        id1 = self.db.record_attack(_sample_event())
        id2 = self.db.record_attack(_sample_event())
        self.assertGreater(id2, id1)


class TestGetAttacks(unittest.TestCase):
    def setUp(self):
        AttackDatabase._reset_instance()
        self.db = AttackDatabase.get_instance(":memory:")
        for i in range(5):
            self.db.record_attack(_sample_event(attacker_ip=f"10.0.0.{i}"))

    def tearDown(self):
        AttackDatabase._reset_instance()

    def test_returns_list(self):
        result = self.db.get_attacks()
        self.assertIsInstance(result, list)

    def test_returns_all_records(self):
        result = self.db.get_attacks(limit=10)
        self.assertEqual(len(result), 5)

    def test_limit_works(self):
        result = self.db.get_attacks(limit=3)
        self.assertEqual(len(result), 3)

    def test_offset_works(self):
        result_all = self.db.get_attacks(limit=10)
        result_offset = self.db.get_attacks(limit=10, offset=2)
        self.assertEqual(len(result_offset), 3)

    def test_filter_by_attack_type(self):
        self.db.record_attack(_sample_event(attack_type="HTTP_PROBE", honeypot_type="HTTP"))
        result = self.db.get_attacks(filters={"attack_type": "HTTP_PROBE"})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["attack_type"], "HTTP_PROBE")

    def test_records_have_expected_keys(self):
        result = self.db.get_attacks(limit=1)
        self.assertTrue(len(result) > 0)
        row = result[0]
        for key in ("id", "timestamp", "attacker_ip", "attack_type", "threat_level"):
            self.assertIn(key, row)


class TestGetAttackById(unittest.TestCase):
    def setUp(self):
        AttackDatabase._reset_instance()
        self.db = AttackDatabase.get_instance(":memory:")
        self.inserted_id = self.db.record_attack(_sample_event())

    def tearDown(self):
        AttackDatabase._reset_instance()

    def test_get_existing(self):
        row = self.db.get_attack_by_id(self.inserted_id)
        self.assertIsNotNone(row)
        self.assertEqual(row["id"], self.inserted_id)

    def test_get_nonexistent_returns_none(self):
        row = self.db.get_attack_by_id(999999)
        self.assertIsNone(row)


class TestGetAttackStatistics(unittest.TestCase):
    def setUp(self):
        AttackDatabase._reset_instance()
        self.db = AttackDatabase.get_instance(":memory:")
        self.db.record_attack(_sample_event(attack_type="SSH_BRUTE_FORCE"))
        self.db.record_attack(_sample_event(attack_type="HTTP_PROBE", honeypot_type="HTTP"))
        self.db.record_attack(_sample_event(attack_type="FTP_BRUTE_FORCE", honeypot_type="FTP"))

    def tearDown(self):
        AttackDatabase._reset_instance()

    def test_statistics_keys(self):
        stats = self.db.get_attack_statistics()
        for key in ("total_attacks", "unique_attackers", "attacks_by_type",
                    "attacks_by_threat_level", "top_attacking_ips"):
            self.assertIn(key, stats)

    def test_total_count(self):
        stats = self.db.get_attack_statistics()
        self.assertEqual(stats["total_attacks"], 3)

    def test_by_type_dict(self):
        stats = self.db.get_attack_statistics()
        self.assertIsInstance(stats["attacks_by_type"], dict)
        self.assertEqual(stats["attacks_by_type"]["SSH_BRUTE_FORCE"], 1)

    def test_top_ips_is_list(self):
        stats = self.db.get_attack_statistics()
        self.assertIsInstance(stats["top_attacking_ips"], list)


if __name__ == "__main__":
    unittest.main()
