import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Reset singletons and configure in-memory DB before importing the Flask app
from storage.database import AttackDatabase
from analyzer.analyzer import AttackAnalyzer

AttackDatabase._reset_instance()
AttackAnalyzer._reset_instance()
AttackDatabase.get_instance(":memory:")

from api.app import app, honeypot_registry


class TestAPISetup(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()
        honeypot_registry.clear()

    def tearDown(self):
        honeypot_registry.clear()


class TestHealthEndpoint(TestAPISetup):
    def test_health_returns_200(self):
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)

    def test_health_body(self):
        resp = self.client.get("/api/health")
        data = resp.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("timestamp", data)


class TestAttacksEndpoint(TestAPISetup):
    def test_attacks_returns_200(self):
        resp = self.client.get("/api/attacks")
        self.assertEqual(resp.status_code, 200)

    def test_attacks_has_attacks_key(self):
        resp = self.client.get("/api/attacks")
        data = resp.get_json()
        self.assertIn("attacks", data)
        self.assertIsInstance(data["attacks"], list)

    def test_attacks_has_count_key(self):
        resp = self.client.get("/api/attacks")
        data = resp.get_json()
        self.assertIn("count", data)

    def test_attacks_invalid_limit(self):
        resp = self.client.get("/api/attacks?limit=abc")
        self.assertEqual(resp.status_code, 400)

    def test_attack_not_found(self):
        resp = self.client.get("/api/attacks/999999")
        self.assertEqual(resp.status_code, 404)


class TestStatisticsEndpoint(TestAPISetup):
    def test_statistics_returns_200(self):
        resp = self.client.get("/api/statistics")
        self.assertEqual(resp.status_code, 200)

    def test_statistics_structure(self):
        resp = self.client.get("/api/statistics")
        data = resp.get_json()
        self.assertIn("database", data)
        self.assertIn("analyzer", data)

    def test_statistics_db_keys(self):
        resp = self.client.get("/api/statistics")
        data = resp.get_json()
        db_stats = data["database"]
        for key in ("total_attacks", "unique_attackers", "attacks_by_type"):
            self.assertIn(key, db_stats)


class TestHoneypotsEndpoint(TestAPISetup):
    def test_honeypots_returns_200(self):
        resp = self.client.get("/api/honeypots")
        self.assertEqual(resp.status_code, 200)

    def test_honeypots_returns_list(self):
        resp = self.client.get("/api/honeypots")
        data = resp.get_json()
        self.assertIn("honeypots", data)
        self.assertIsInstance(data["honeypots"], list)

    def test_honeypots_empty_when_none_running(self):
        resp = self.client.get("/api/honeypots")
        data = resp.get_json()
        self.assertEqual(len(data["honeypots"]), 0)

    def test_stop_unknown_type(self):
        resp = self.client.post(
            "/api/honeypots/stop",
            json={"type": "unknown"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_start_unknown_type(self):
        resp = self.client.post(
            "/api/honeypots/start",
            json={"type": "telnet"},
        )
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
