import logging
import threading
from collections import defaultdict
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Thresholds used to determine threat level
_MEDIUM_THRESHOLD = 3
_HIGH_THRESHOLD = 10
_CRITICAL_THRESHOLD = 25

_BRUTE_FORCE_TYPES = {"SSH_BRUTE_FORCE", "FTP_BRUTE_FORCE"}
_RECON_TYPES = {"HTTP_PROBE"}


class AttackAnalyzer:
    """Singleton real-time attack analyzer and behavior tracker."""

    _instance: Optional["AttackAnalyzer"] = None
    _lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------

    def __init__(self):
        self._attack_counts: Dict[str, int] = defaultdict(int)  # keyed by IP
        self._type_counts: Dict[str, int] = defaultdict(int)
        self._threat_counts: Dict[str, int] = defaultdict(int)
        self._data_lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "AttackAnalyzer":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def _reset_instance(cls):
        """Reset singleton – intended for use in tests only."""
        with cls._lock:
            cls._instance = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_attack(self, event_dict: dict) -> dict:
        """Analyze an attack event and return an analysis dictionary."""
        attacker_ip = event_dict.get("attacker_ip", "unknown")
        attack_type = event_dict.get("attack_type", "UNKNOWN")

        with self._data_lock:
            self._attack_counts[attacker_ip] += 1
            self._type_counts[attack_type] += 1
            history = self._attack_counts[attacker_ip]

        threat_level = self._compute_threat_level(history, attack_type)
        attack_pattern = self._detect_pattern(attack_type)
        recommendations = self._build_recommendations(threat_level, attack_pattern, attacker_ip)

        with self._data_lock:
            self._threat_counts[threat_level] += 1

        return {
            "threat_level": threat_level,
            "attack_pattern": attack_pattern,
            "recommendations": recommendations,
        }

    def get_statistics(self) -> dict:
        """Return aggregated statistics about observed attacks."""
        with self._data_lock:
            type_counts = dict(self._type_counts)
            threat_counts = dict(self._threat_counts)
            # Top 10 attacking IPs by count
            top_ips = sorted(self._attack_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "attack_counts_by_type": type_counts,
            "top_attacking_ips": [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
            "threat_distribution": threat_counts,
            "total_attacks": sum(type_counts.values()),
        }

    def _get_attack_history(self, ip: str) -> int:
        """Return the number of previously recorded attacks from *ip*."""
        with self._data_lock:
            return self._attack_counts.get(ip, 0)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_threat_level(history: int, attack_type: str) -> str:
        if history >= _CRITICAL_THRESHOLD:
            return "CRITICAL"
        if history >= _HIGH_THRESHOLD:
            return "HIGH"
        if history >= _MEDIUM_THRESHOLD or attack_type in _BRUTE_FORCE_TYPES:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _detect_pattern(attack_type: str) -> str:
        if attack_type in _BRUTE_FORCE_TYPES:
            return "BRUTE_FORCE"
        if attack_type in _RECON_TYPES:
            return "RECONNAISSANCE"
        return "EXPLOIT_ATTEMPT"

    @staticmethod
    def _build_recommendations(threat_level: str, attack_pattern: str, ip: str) -> List[str]:
        recs: List[str] = []
        if threat_level in ("HIGH", "CRITICAL"):
            recs.append(f"Block IP {ip} immediately at the firewall level.")
        if attack_pattern == "BRUTE_FORCE":
            recs.append("Enable account lockout policies and consider fail2ban.")
            recs.append("Disable password authentication and enforce SSH key-based login.")
        elif attack_pattern == "RECONNAISSANCE":
            recs.append("Review exposed HTTP endpoints and remove unnecessary server banners.")
            recs.append("Enable a Web Application Firewall (WAF).")
        else:
            recs.append("Investigate the source IP and review related logs.")
        if threat_level == "CRITICAL":
            recs.append("Escalate to the incident response team.")
        return recs
