import csv
import io
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from functools import wraps
from typing import Dict

from flask import Flask, Response, jsonify, request, send_from_directory

# Allow running as `python -m api.app` from the repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.database import AttackDatabase
from analyzer.analyzer import AttackAnalyzer
from honeypot.ssh_honeypot import SSHHoneypot
from honeypot.http_honeypot import HTTPHoneypot
from honeypot.ftp_honeypot import FTPHoneypot


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "service": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_data)


logging.basicConfig(level=logging.INFO)
_json_handler = logging.StreamHandler()
_json_handler.setFormatter(JsonFormatter())
logging.getLogger().handlers = [_json_handler]

logger = logging.getLogger(__name__)

_DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard")

app = Flask(__name__)

# Global registry of running honeypot instances keyed by type string
honeypot_registry: Dict[str, object] = {}

_HONEYPOT_CLASSES = {
    "ssh": SSHHoneypot,
    "http": HTTPHoneypot,
    "ftp": FTPHoneypot,
}

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

_API_KEY = os.environ.get("API_KEY") or None


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if _API_KEY:
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer ") or auth[len("Bearer "):] != _API_KEY:
                return _err("Unauthorized", 401)
        return f(*args, **kwargs)
    return decorated


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


@app.route("/")
def dashboard():
    return send_from_directory(_DASHBOARD_DIR, "index.html")


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

    if limit <= 0 or offset < 0:
        return _err("limit must be > 0 and offset must be >= 0")

    filters = {}
    for col in ("honeypot_type", "attack_type"):
        val = request.args.get(col)
        if val:
            filters[col] = val

    db = AttackDatabase.get_instance()
    try:
        attacks = db.get_attacks(limit=limit, offset=offset, filters=filters or None)
    except ValueError as exc:
        return _err(str(exc))
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


@app.route("/api/stats/summary", methods=["GET"])
def stats_summary():
    db = AttackDatabase.get_instance()
    stats = db.get_attack_statistics()

    # Most targeted service
    by_type = stats.get("attacks_by_type", {})
    most_targeted = max(by_type, key=by_type.get) if by_type else None

    # Busiest hour in last 24h
    with db._lock:
        rows = db._conn.execute(
            "SELECT strftime('%H', timestamp) as hr, COUNT(*) as cnt "
            "FROM attack_events "
            "WHERE timestamp >= datetime('now', '-24 hours') "
            "GROUP BY hr ORDER BY cnt DESC LIMIT 1"
        ).fetchall()
    busiest_hour = rows[0][0] if rows else None

    return _ok({
        "total_attacks": stats["total_attacks"],
        "unique_attackers": stats["unique_attackers"],
        "most_targeted_service": most_targeted,
        "busiest_hour_last_24h": busiest_hour,
        "attacks_by_threat_level": stats["attacks_by_threat_level"],
    })


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


@app.route("/api/alerts", methods=["GET"])
def list_alerts():
    try:
        limit = max(1, min(int(request.args.get("limit", 100)), 1000))
        offset = max(0, int(request.args.get("offset", 0)))
    except ValueError:
        return _err("limit and offset must be integers")
    db = AttackDatabase.get_instance()
    alerts = db.get_alerts(limit=limit, offset=offset)
    return _ok({"alerts": alerts, "count": len(alerts)})


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


@app.route("/api/export/csv", methods=["GET"])
def export_csv():
    db = AttackDatabase.get_instance()
    attacks = db.get_attacks(limit=100000)
    output = io.StringIO()
    if attacks:
        writer = csv.DictWriter(output, fieldnames=list(attacks[0].keys()))
        writer.writeheader()
        writer.writerows(attacks)
    else:
        output.write("")
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=attacks.csv"},
    )


@app.route("/api/export/json", methods=["GET"])
def export_json():
    db = AttackDatabase.get_instance()
    attacks = db.get_attacks(limit=100000)
    return Response(
        json.dumps({"attacks": attacks}),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=attacks.json"},
    )


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
@require_api_key
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
@require_api_key
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
    try:
        if os.getuid() == 0:
            logger.warning("WARNING: Running as root is not recommended!")
    except AttributeError:
        pass  # Windows

    def _shutdown(signum, frame):
        logger.info("Received signal %s – shutting down honeypots", signum)
        for hp in list(honeypot_registry.values()):
            try:
                hp.stop()
            except Exception:
                pass
        honeypot_registry.clear()
        logger.info("Clean shutdown complete")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    app.run(host="0.0.0.0", port=5000, debug=False)
