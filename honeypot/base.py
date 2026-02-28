import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_DANGEROUS_KEYWORDS = frozenset({
    "wget", "curl", "chmod", "rm -rf", "bash", "nc ", "python", "perl",
})


def _sanitize(text: str) -> str:
    """Replace HTML special characters with entities to prevent XSS."""
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
    )


class BaseHoneypot(ABC):
    """Abstract base class for all honeypot types."""

    def __init__(self, host: str, port: int, honeypot_type: str):
        self._host = host
        self._port = port
        self._honeypot_type = honeypot_type
        self._is_running = False

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    @property
    def honeypot_type(self) -> str:
        return self._honeypot_type

    @property
    def is_running(self) -> bool:
        return self._is_running

    # ------------------------------------------------------------------
    # Abstract / concrete lifecycle methods
    # ------------------------------------------------------------------

    @abstractmethod
    def start(self):
        """Start the honeypot listener."""

    def stop(self):
        """Stop the honeypot service."""
        self._is_running = False
        logger.info("Honeypot %s stopped on %s:%d", self._honeypot_type, self._host, self._port)

    # ------------------------------------------------------------------
    # Attack logging
    # ------------------------------------------------------------------

    def log_attack(self, attacker_ip: str, attacker_port: int, data: str, attack_type: str) -> dict:
        """Record an attack event in the database and run the analyzer."""
        # Import here to avoid circular imports at module load time
        from storage.database import AttackDatabase
        from analyzer.analyzer import AttackAnalyzer

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attacker_ip": attacker_ip,
            "attacker_port": attacker_port,
            "honeypot_type": self._honeypot_type,
            "attack_type": attack_type,
            "raw_data": _sanitize(data),
        }

        try:
            analysis = AttackAnalyzer.get_instance().analyze_attack(event)
            event["threat_level"] = analysis.get("threat_level", "LOW")
            event["attack_pattern"] = analysis.get("attack_pattern", "UNKNOWN")
        except Exception:
            logger.exception("Analyzer error for event %s", event)
            event["threat_level"] = "LOW"
            event["attack_pattern"] = "UNKNOWN"

        try:
            inserted_id = AttackDatabase.get_instance().record_attack(event)
            event["id"] = inserted_id
        except Exception:
            logger.exception("Database error for event %s", event)

        # Raise an alert for high-severity events or dangerous commands
        data_lower = data.lower()
        has_dangerous = any(kw in data_lower for kw in _DANGEROUS_KEYWORDS)
        if event.get("threat_level") in ("HIGH", "CRITICAL") or has_dangerous:
            alert_type = "DANGEROUS_COMMAND" if has_dangerous else "HIGH_THREAT"
            try:
                AttackDatabase.get_instance().record_alert({
                    "timestamp": event["timestamp"],
                    "attacker_ip": attacker_ip,
                    "alert_type": alert_type,
                    "detail": (
                        f"threat_level={event.get('threat_level')} "
                        f"attack_type={attack_type} data={event.get('raw_data', '')[:200]}"
                    ),
                    "attack_id": event.get("id"),
                })
            except Exception:
                logger.exception("Alert recording error for event %s", event)

        logger.warning(
            "[%s] Attack from %s:%d | type=%s | threat=%s",
            self._honeypot_type,
            attacker_ip,
            attacker_port,
            attack_type,
            event.get("threat_level", "UNKNOWN"),
        )
        return event
