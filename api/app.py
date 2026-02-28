import logging
import sys
import os
from datetime import datetime, timezone
from typing import Dict

from flask import Flask, jsonify, request, send_from_directory

# Allow running as `python -m api.app` from the repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.database import AttackDatabase
from analyzer.analyzer import AttackAnalyzer
from honeypot.ssh_honeypot import SSHHoneypot
from honeypot.http_honeypot import HTTPHoneypot
from honeypot.ftp_honeypot import FTPHoneypot

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard")

app = Flask(__name__)


@app.route("/")
def dashboard():
    return send_from_directory(_DASHBOARD_DIR, "index.html")

# Global registry of running honeypot instances keyed by type string
honeypot_registry: Dict[str, object] = {}

_HONEYPOT_CLASSES = {
    "ssh": SSHHoneypot,
    "http": HTTPHoneypot,
    "ftp": FTPHoneypot,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ok(data, status: int = 200):
    return jsonify(data), status


def _err(message: str, status: int = 400):
    return jsonify({"error": message}), status


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


@app.route("/api/health", methods=["GET"])
def health():
    return _ok({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})


# ---------------------------------------------------------------------------
# Attacks
# ---------------------------------------------------------------------------


@app.route("/api/attacks", methods=["GET"])
def list_attacks():
    try:
        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))
    except ValueError:
        return _err("limit and offset must be integers")

    filters = {}
    for col in ("honeypot_type", "attack_type"):
        val = request.args.get(col)
        if val:
            filters[col] = val

    db = AttackDatabase.get_instance()
    attacks = db.get_attacks(limit=limit, offset=offset, filters=filters or None)
    return _ok({"attacks": attacks, "count": len(attacks)})


@app.route("/api/attacks/<int:attack_id>", methods=["GET"])
def get_attack(attack_id: int):
    db = AttackDatabase.get_instance()
    attack = db.get_attack_by_id(attack_id)
    if attack is None:
        return _err("Attack not found", 404)
    return _ok(attack)


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


@app.route("/api/statistics", methods=["GET"])
def get_statistics():
    db_stats = AttackDatabase.get_instance().get_attack_statistics()
    analyzer_stats = AttackAnalyzer.get_instance().get_statistics()
    return _ok({"database": db_stats, "analyzer": analyzer_stats})


# ---------------------------------------------------------------------------
# Honeypots
# ---------------------------------------------------------------------------


@app.route("/api/honeypots", methods=["GET"])
def list_honeypots():
    result = []
    for hp_type, hp in honeypot_registry.items():
        result.append(
            {
                "type": hp_type,
                "host": hp.host,
                "port": hp.port,
                "is_running": hp.is_running,
            }
        )
    return _ok({"honeypots": result})


@app.route("/api/honeypots/start", methods=["POST"])
def start_honeypot():
    body = request.get_json(silent=True) or {}
    hp_type = (body.get("type") or "").lower()
    host = body.get("host", "0.0.0.0")

    if hp_type not in _HONEYPOT_CLASSES:
        return _err(f"Unknown honeypot type '{hp_type}'. Valid types: {list(_HONEYPOT_CLASSES)}")

    if hp_type in honeypot_registry and honeypot_registry[hp_type].is_running:
        return _err(f"Honeypot '{hp_type}' is already running", 409)

    cls = _HONEYPOT_CLASSES[hp_type]
    default_ports = {"ssh": 2222, "http": 8080, "ftp": 2121}
    port = int(body.get("port", default_ports[hp_type]))

    try:
        hp = cls(host=host, port=port)
        hp.start()
        honeypot_registry[hp_type] = hp
    except Exception as exc:
        logger.exception("Failed to start %s honeypot", hp_type)
        return _err(str(exc), 500)

    return _ok(
        {"message": f"{hp_type.upper()} honeypot started", "host": host, "port": port},
        201,
    )


@app.route("/api/honeypots/stop", methods=["POST"])
def stop_honeypot():
    body = request.get_json(silent=True) or {}
    hp_type = (body.get("type") or "").lower()

    if hp_type not in _HONEYPOT_CLASSES:
        return _err(f"Unknown honeypot type '{hp_type}'. Valid types: {list(_HONEYPOT_CLASSES)}")

    hp = honeypot_registry.get(hp_type)
    if hp is None or not hp.is_running:
        return _err(f"Honeypot '{hp_type}' is not running", 404)

    hp.stop()
    honeypot_registry.pop(hp_type, None)
    return _ok({"message": f"{hp_type.upper()} honeypot stopped"})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
