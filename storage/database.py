import logging
import sqlite3
import threading
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_ALLOWED_FILTER_COLS = frozenset({"honeypot_type", "attack_type", "attacker_ip", "threat_level"})

_DDL = """
CREATE TABLE IF NOT EXISTS attack_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT    NOT NULL,
    attacker_ip    TEXT    NOT NULL,
    attacker_port  INTEGER NOT NULL,
    honeypot_type  TEXT    NOT NULL,
    attack_type    TEXT    NOT NULL,
    raw_data       TEXT,
    threat_level   TEXT,
    attack_pattern TEXT
);
CREATE INDEX IF NOT EXISTS idx_timestamp    ON attack_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_attacker_ip  ON attack_events(attacker_ip);
CREATE INDEX IF NOT EXISTS idx_honeypot_type ON attack_events(honeypot_type);
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    attacker_ip TEXT    NOT NULL,
    alert_type  TEXT    NOT NULL,
    detail      TEXT,
    attack_id   INTEGER
);
"""


class AttackDatabase:
    """Singleton SQLite-backed storage for attack events."""

    _instance: Optional["AttackDatabase"] = None
    _class_lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------

    def __init__(self, db_path: str = "honeypot.db"):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        # executescript() is required to run multiple DDL statements at once;
        # it commits automatically after each statement.
        self._conn.executescript(_DDL)

    @classmethod
    def get_instance(cls, db_path: str = "honeypot.db") -> "AttackDatabase":
        if cls._instance is None:
            with cls._class_lock:
                if cls._instance is None:
                    cls._instance = cls(db_path)
        return cls._instance

    @classmethod
    def _reset_instance(cls):
        """Reset singleton – intended for use in tests only."""
        with cls._class_lock:
            if cls._instance is not None:
                try:
                    cls._instance._conn.close()
                except Exception:
                    pass
            cls._instance = None

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def record_attack(self, event_dict: dict) -> int:
        """Insert an attack event and return the new row id."""
        sql = """
        INSERT INTO attack_events
            (timestamp, attacker_ip, attacker_port, honeypot_type,
             attack_type, raw_data, threat_level, attack_pattern)
        VALUES
            (:timestamp, :attacker_ip, :attacker_port, :honeypot_type,
             :attack_type, :raw_data, :threat_level, :attack_pattern)
        """
        row = {
            "timestamp": event_dict.get("timestamp", ""),
            "attacker_ip": event_dict.get("attacker_ip", ""),
            "attacker_port": int(event_dict.get("attacker_port", 0)),
            "honeypot_type": event_dict.get("honeypot_type", ""),
            "attack_type": event_dict.get("attack_type", ""),
            "raw_data": event_dict.get("raw_data", ""),
            "threat_level": event_dict.get("threat_level", "LOW"),
            "attack_pattern": event_dict.get("attack_pattern", "UNKNOWN"),
        }
        with self._lock:
            cursor = self._conn.execute(sql, row)
            self._conn.commit()
            return cursor.lastrowid

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_attacks(
        self,
        limit: int = 100,
        offset: int = 0,
        filters: Optional[Dict] = None,
    ) -> List[dict]:
        """Retrieve attack events with optional column=value filters."""
        where_clauses = []
        params: list = []
        if filters:
            for col, val in filters.items():
                if col not in _ALLOWED_FILTER_COLS:
                    raise ValueError(f"Filter column '{col}' is not allowed")
                where_clauses.append(f"{col} = ?")
                params.append(val)

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        sql = f"SELECT * FROM attack_events {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?"
        params += [limit, offset]

        with self._lock:
            cursor = self._conn.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_attack_by_id(self, attack_id: int) -> Optional[dict]:
        """Return a single attack event by primary key, or None."""
        sql = "SELECT * FROM attack_events WHERE id = ?"
        with self._lock:
            cursor = self._conn.execute(sql, (attack_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_attack_statistics(self) -> dict:
        """Return aggregated statistics across all stored events."""
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM attack_events").fetchone()[0]
            unique_ips = self._conn.execute(
                "SELECT COUNT(DISTINCT attacker_ip) FROM attack_events"
            ).fetchone()[0]
            by_type = {
                row[0]: row[1]
                for row in self._conn.execute(
                    "SELECT attack_type, COUNT(*) FROM attack_events GROUP BY attack_type"
                ).fetchall()
            }
            by_threat = {
                row[0]: row[1]
                for row in self._conn.execute(
                    "SELECT threat_level, COUNT(*) FROM attack_events GROUP BY threat_level"
                ).fetchall()
            }
            top_ips = [
                {"ip": row[0], "count": row[1]}
                for row in self._conn.execute(
                    "SELECT attacker_ip, COUNT(*) as cnt FROM attack_events "
                    "GROUP BY attacker_ip ORDER BY cnt DESC LIMIT 10"
                ).fetchall()
            ]

        return {
            "total_attacks": total,
            "unique_attackers": unique_ips,
            "attacks_by_type": by_type,
            "attacks_by_threat_level": by_threat,
            "top_attacking_ips": top_ips,
        }

    # ------------------------------------------------------------------
    # Alert operations
    # ------------------------------------------------------------------

    def record_alert(self, alert_dict: dict) -> int:
        """Insert an alert and return the new row id."""
        sql = """
        INSERT INTO alerts (timestamp, attacker_ip, alert_type, detail, attack_id)
        VALUES (:timestamp, :attacker_ip, :alert_type, :detail, :attack_id)
        """
        row = {
            "timestamp": alert_dict.get("timestamp", ""),
            "attacker_ip": alert_dict.get("attacker_ip", ""),
            "alert_type": alert_dict.get("alert_type", ""),
            "detail": alert_dict.get("detail", ""),
            "attack_id": alert_dict.get("attack_id"),
        }
        with self._lock:
            cursor = self._conn.execute(sql, row)
            self._conn.commit()
            return cursor.lastrowid

    def get_alerts(self, limit: int = 100, offset: int = 0) -> List[dict]:
        """Retrieve alerts ordered by most recent first."""
        sql = "SELECT * FROM alerts ORDER BY id DESC LIMIT ? OFFSET ?"
        with self._lock:
            cursor = self._conn.execute(sql, (limit, offset))
            return [dict(row) for row in cursor.fetchall()]
