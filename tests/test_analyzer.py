import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.analyzer import AttackAnalyzer


def _make_event(ip="1.2.3.4", attack_type="SSH_BRUTE_FORCE"):
    return {
        "attacker_ip": ip,
        "attacker_port": 54321,
        "honeypot_type": "SSH",
        "attack_type": attack_type,
        "raw_data": "test",
    }


class TestAttackAnalyzerSingleton(unittest.TestCase):
    def setUp(self):
        AttackAnalyzer._reset_instance()

    def tearDown(self):
        AttackAnalyzer._reset_instance()

    def test_singleton_same_instance(self):
        a1 = AttackAnalyzer.get_instance()
        a2 = AttackAnalyzer.get_instance()
        self.assertIs(a1, a2)

    def test_reset_creates_new_instance(self):
        a1 = AttackAnalyzer.get_instance()
        AttackAnalyzer._reset_instance()
        a2 = AttackAnalyzer.get_instance()
        self.assertIsNot(a1, a2)


class TestAnalyzeAttack(unittest.TestCase):
    def setUp(self):
        AttackAnalyzer._reset_instance()
        self.analyzer = AttackAnalyzer.get_instance()

    def tearDown(self):
        AttackAnalyzer._reset_instance()

    def test_returns_required_keys(self):
        result = self.analyzer.analyze_attack(_make_event())
        self.assertIn("threat_level", result)
        self.assertIn("attack_pattern", result)
        self.assertIn("recommendations", result)

    def test_recommendations_is_list(self):
        result = self.analyzer.analyze_attack(_make_event())
        self.assertIsInstance(result["recommendations"], list)

    def test_threat_level_values(self):
        result = self.analyzer.analyze_attack(_make_event(attack_type="HTTP_PROBE"))
        self.assertIn(result["threat_level"], ("LOW", "MEDIUM", "HIGH", "CRITICAL"))


class TestThreatEscalation(unittest.TestCase):
    def setUp(self):
        AttackAnalyzer._reset_instance()
        self.analyzer = AttackAnalyzer.get_instance()

    def tearDown(self):
        AttackAnalyzer._reset_instance()

    def test_escalates_to_high_with_repeated_attacks(self):
        ip = "5.5.5.5"
        result = None
        for _ in range(12):
            result = self.analyzer.analyze_attack(_make_event(ip=ip, attack_type="HTTP_PROBE"))
        self.assertIn(result["threat_level"], ("HIGH", "CRITICAL"))

    def test_escalates_to_critical(self):
        ip = "6.6.6.6"
        result = None
        for _ in range(30):
            result = self.analyzer.analyze_attack(_make_event(ip=ip, attack_type="SSH_BRUTE_FORCE"))
        self.assertEqual(result["threat_level"], "CRITICAL")

    def test_brute_force_starts_at_medium(self):
        result = self.analyzer.analyze_attack(_make_event(attack_type="SSH_BRUTE_FORCE"))
        self.assertIn(result["threat_level"], ("MEDIUM", "HIGH", "CRITICAL"))


class TestGetStatistics(unittest.TestCase):
    def setUp(self):
        AttackAnalyzer._reset_instance()
        self.analyzer = AttackAnalyzer.get_instance()

    def tearDown(self):
        AttackAnalyzer._reset_instance()

    def test_statistics_keys(self):
        self.analyzer.analyze_attack(_make_event())
        stats = self.analyzer.get_statistics()
        self.assertIn("attack_counts_by_type", stats)
        self.assertIn("top_attacking_ips", stats)
        self.assertIn("threat_distribution", stats)
        self.assertIn("total_attacks", stats)

    def test_statistics_counts(self):
        for _ in range(3):
            self.analyzer.analyze_attack(_make_event())
        stats = self.analyzer.get_statistics()
        self.assertEqual(stats["total_attacks"], 3)

    def test_top_ips_structure(self):
        self.analyzer.analyze_attack(_make_event())
        stats = self.analyzer.get_statistics()
        self.assertIsInstance(stats["top_attacking_ips"], list)
        if stats["top_attacking_ips"]:
            entry = stats["top_attacking_ips"][0]
            self.assertIn("ip", entry)
            self.assertIn("count", entry)


if __name__ == "__main__":
    unittest.main()
