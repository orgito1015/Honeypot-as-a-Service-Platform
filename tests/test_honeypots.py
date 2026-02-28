import sys
import os
import unittest
from unittest.mock import MagicMock, patch

# Ensure repo root is on the path so imports resolve
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from honeypot.ssh_honeypot import SSHHoneypot
from honeypot.http_honeypot import HTTPHoneypot
from honeypot.ftp_honeypot import FTPHoneypot


class TestSSHHoneypotInit(unittest.TestCase):
    def test_defaults(self):
        hp = SSHHoneypot()
        self.assertEqual(hp.host, "0.0.0.0")
        self.assertEqual(hp.port, 2222)
        self.assertEqual(hp.honeypot_type, "SSH")

    def test_custom_params(self):
        hp = SSHHoneypot(host="127.0.0.1", port=9999)
        self.assertEqual(hp.host, "127.0.0.1")
        self.assertEqual(hp.port, 9999)

    def test_not_running_initially(self):
        hp = SSHHoneypot()
        self.assertFalse(hp.is_running)


class TestHTTPHoneypotInit(unittest.TestCase):
    def test_defaults(self):
        hp = HTTPHoneypot()
        self.assertEqual(hp.host, "0.0.0.0")
        self.assertEqual(hp.port, 8080)
        self.assertEqual(hp.honeypot_type, "HTTP")

    def test_not_running_initially(self):
        hp = HTTPHoneypot()
        self.assertFalse(hp.is_running)


class TestFTPHoneypotInit(unittest.TestCase):
    def test_defaults(self):
        hp = FTPHoneypot()
        self.assertEqual(hp.host, "0.0.0.0")
        self.assertEqual(hp.port, 2121)
        self.assertEqual(hp.honeypot_type, "FTP")

    def test_not_running_initially(self):
        hp = FTPHoneypot()
        self.assertFalse(hp.is_running)


class TestLogAttack(unittest.TestCase):
    """Test that log_attack calls the database and analyzer singletons."""

    def _make_mock_db(self):
        mock_db = MagicMock()
        mock_db.record_attack.return_value = 1
        return mock_db

    def _make_mock_analyzer(self):
        mock_analyzer = MagicMock()
        mock_analyzer.analyze_attack.return_value = {
            "threat_level": "MEDIUM",
            "attack_pattern": "BRUTE_FORCE",
            "recommendations": [],
        }
        return mock_analyzer

    def test_log_attack_calls_db_and_analyzer(self):
        hp = SSHHoneypot()
        mock_db = self._make_mock_db()
        mock_analyzer = self._make_mock_analyzer()

        with patch("storage.database.AttackDatabase.get_instance", return_value=mock_db), \
             patch("analyzer.analyzer.AttackAnalyzer.get_instance", return_value=mock_analyzer):
            result = hp.log_attack("1.2.3.4", 54321, "some data", "SSH_BRUTE_FORCE")

        mock_analyzer.analyze_attack.assert_called_once()
        mock_db.record_attack.assert_called_once()
        self.assertEqual(result["threat_level"], "MEDIUM")
        self.assertEqual(result["attack_pattern"], "BRUTE_FORCE")

    def test_log_attack_returns_event_dict(self):
        hp = HTTPHoneypot()
        mock_db = self._make_mock_db()
        mock_analyzer = self._make_mock_analyzer()

        with patch("storage.database.AttackDatabase.get_instance", return_value=mock_db), \
             patch("analyzer.analyzer.AttackAnalyzer.get_instance", return_value=mock_analyzer):
            result = hp.log_attack("10.0.0.1", 80, "GET /", "HTTP_PROBE")

        self.assertIn("timestamp", result)
        self.assertIn("attacker_ip", result)
        self.assertEqual(result["attacker_ip"], "10.0.0.1")


class TestIsRunning(unittest.TestCase):
    def test_stop_sets_is_running_false(self):
        hp = SSHHoneypot()
        hp._is_running = True
        hp.stop()
        self.assertFalse(hp.is_running)


if __name__ == "__main__":
    unittest.main()
