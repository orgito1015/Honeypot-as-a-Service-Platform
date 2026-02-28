# Honeypot-as-a-Service Platform

A production-ready, virtualized decoy system to attract, capture, and analyze attacker behavior in real-time.  
It exposes fake SSH, HTTP, and FTP services, stores every interaction in a local SQLite database, performs live threat analysis, and surfaces everything through a Flask REST API and a dark-theme web dashboard.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          Attackers                              │
└──────────┬──────────────────┬───────────────────┬──────────────┘
           │ :2222 (SSH)      │ :8080 (HTTP)      │ :2121 (FTP)
           ▼                  ▼                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                      Honeypot Layer                              │
│  SSHHoneypot   HTTPHoneypot   FTPHoneypot  (daemon threads)      │
│                    (honeypot/)                                    │
└─────────────────────────┬────────────────────────────────────────┘
                          │ log_attack()
           ┌──────────────┴──────────────┐
           ▼                             ▼
┌──────────────────┐          ┌─────────────────────┐
│  AttackAnalyzer  │          │   AttackDatabase     │
│  (analyzer/)     │          │   (storage/)         │
│  • threat_level  │          │   SQLite honeypot.db │
│  • attack_pattern│          │   attack_events table│
│  • recommendations│         │   alerts table       │
└──────────────────┘          └─────────────────────┘
           ▲                             ▲
           └──────────────┬──────────────┘
                          │
                 ┌────────────────┐
                 │  Flask API     │
                 │  (api/app.py)  │
                 │  :5000         │
                 └───────┬────────┘
                         │
               ┌─────────────────┐
               │   Dashboard     │
               │  dashboard/     │
               │  index.html     │
               └─────────────────┘
```

### Directory layout

```
honeypot/           – Honeypot emulators
  base.py           – Abstract BaseHoneypot
  ssh_honeypot.py   – SSH emulator (port 2222)
  http_honeypot.py  – HTTP emulator (port 8080)
  ftp_honeypot.py   – FTP emulator (port 2121)

analyzer/
  analyzer.py       – Singleton real-time threat analyzer

storage/
  database.py       – Singleton SQLite storage (attack_events + alerts tables)

api/
  app.py            – Flask REST API (port 5000)

dashboard/
  index.html        – Single-page dark-theme monitoring dashboard

tests/              – unittest test suite
requirements.txt
Dockerfile
docker-compose.yml
.env.example
```

---

## Quick Start

### Local

```bash
git clone <repo-url>
cd Honeypot-as-a-Service-Platform
pip install -r requirements.txt
python -m api.app
```

Python 3.8+ is required. All storage is handled via the built-in `sqlite3` module — no external database is needed.

Open `http://localhost:5000` in your browser to view the live dashboard.

### Docker

```bash
# Build and start
docker compose up -d

# View logs
docker compose logs -f

# Stop
docker compose down
```

---

## Configuration

Copy `.env.example` to `.env` and adjust as needed:

```bash
cp .env.example .env
```

| Variable        | Default        | Description                            |
|-----------------|----------------|----------------------------------------|
| `API_KEY`       | *(empty)*      | Bearer token for write endpoints. Empty = disabled |
| `SSH_PORT`      | `2222`         | SSH honeypot listen port               |
| `HTTP_PORT`     | `8080`         | HTTP honeypot listen port              |
| `FTP_PORT`      | `2121`         | FTP honeypot listen port               |
| `DASHBOARD_PORT`| `5000`         | Flask API / dashboard port             |
| `DB_PATH`       | `honeypot.db`  | SQLite database file path              |
| `LOG_LEVEL`     | `INFO`         | Logging verbosity                      |

---

## Starting Honeypots

Honeypots are started via the REST API:

```bash
# Start SSH honeypot on port 2222
curl -X POST http://localhost:5000/api/honeypots/start \
     -H 'Content-Type: application/json' \
     -d '{"type": "ssh", "host": "0.0.0.0", "port": 2222}'

# Start HTTP honeypot on port 8080
curl -X POST http://localhost:5000/api/honeypots/start \
     -H 'Content-Type: application/json' \
     -d '{"type": "http", "host": "0.0.0.0", "port": 8080}'

# Start FTP honeypot on port 2121
curl -X POST http://localhost:5000/api/honeypots/start \
     -H 'Content-Type: application/json' \
     -d '{"type": "ftp", "host": "0.0.0.0", "port": 2121}'
```

If `API_KEY` is set, include the header: `-H 'Authorization: Bearer <key>'`

---

## API Reference

All endpoints return JSON.

### Health

| Method | Path         | Description                               |
|--------|--------------|-------------------------------------------|
| GET    | /api/health  | Returns `{"status":"ok","timestamp":"…"}` |

### Attacks

| Method | Path                | Description                                                          |
|--------|---------------------|----------------------------------------------------------------------|
| GET    | /api/attacks        | List attacks. Query: `limit`, `offset`, `honeypot_type`, `attack_type` |
| GET    | /api/attacks/\<id\> | Get a single attack event by ID                                      |

### Statistics

| Method | Path                | Description                              |
|--------|---------------------|------------------------------------------|
| GET    | /api/statistics     | Full aggregated stats from DB + analyzer |
| GET    | /api/stats/summary  | Summary: totals, top service, busiest hour |

### Alerts

| Method | Path         | Description                                  |
|--------|--------------|----------------------------------------------|
| GET    | /api/alerts  | List alerts. Query: `limit`, `offset`        |

### Export

| Method | Path               | Description                           |
|--------|--------------------|---------------------------------------|
| GET    | /api/export/csv    | Download all attacks as CSV           |
| GET    | /api/export/json   | Download all attacks as JSON          |

### Honeypots (write endpoints require `API_KEY` if set)

| Method | Path                   | Description                                                                    |
|--------|------------------------|--------------------------------------------------------------------------------|
| GET    | /api/honeypots         | List all running honeypots                                                     |
| POST   | /api/honeypots/start   | Start a honeypot. Body: `{"type":"ssh"\|"http"\|"ftp","host":"0.0.0.0","port":2222}` |
| POST   | /api/honeypots/stop    | Stop a honeypot. Body: `{"type":"ssh"\|"http"\|"ftp"}`                         |

---

## Running Tests

```bash
python -m pytest tests/ -v
# or
python -m unittest discover tests/
```

---

## Data Structures

### Attack Event

Each attack event returned by `/api/attacks` contains:

| Field           | Type    | Description                                      |
|-----------------|---------|--------------------------------------------------|
| `id`            | integer | Auto-incremented primary key                     |
| `timestamp`     | string  | ISO 8601 UTC timestamp of the attack             |
| `attacker_ip`   | string  | Source IP address of the attacker                |
| `attacker_port` | integer | Source port of the attacker                      |
| `honeypot_type` | string  | `ssh`, `http`, or `ftp`                          |
| `attack_type`   | string  | e.g. `SSH_BRUTE_FORCE`, `HTTP_PROBE`, `FTP_BRUTE_FORCE` |
| `raw_data`      | string  | Sanitized payload (HTML special chars escaped)   |
| `threat_level`  | string  | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`           |
| `attack_pattern`| string  | `BRUTE_FORCE`, `RECONNAISSANCE`, or `EXPLOIT_ATTEMPT` |

### Alert

Each alert returned by `/api/alerts` contains:

| Field        | Type    | Description                                           |
|--------------|---------|-------------------------------------------------------|
| `id`         | integer | Auto-incremented primary key                          |
| `timestamp`  | string  | ISO 8601 UTC timestamp of the alert                   |
| `attacker_ip`| string  | Source IP address that triggered the alert            |
| `alert_type` | string  | `HIGH_THREAT` or `DANGEROUS_COMMAND`                  |
| `detail`     | string  | Summary of threat level, attack type, and raw data    |
| `attack_id`  | integer | Foreign key to the associated attack event            |

---

## Threat Levels

| Level    | Condition                                         |
|----------|---------------------------------------------------|
| LOW      | First contact via a non-brute-force probe         |
| MEDIUM   | ≥ 3 hits from the same IP, or any brute-force attempt |
| HIGH     | ≥ 10 hits from the same IP                        |
| CRITICAL | ≥ 25 hits from the same IP                        |

HIGH and CRITICAL events automatically generate a `HIGH_THREAT` alert in the `alerts` table.  
Connections containing any of the following dangerous command keywords also trigger a `DANGEROUS_COMMAND` alert:

`wget`, `curl`, `chmod`, `rm -rf`, `bash`, `nc`, `python`, `perl`

---

## Security Hardening

The platform incorporates several hardening measures:

- **SQL injection prevention** – filter columns are validated against an allowlist (`honeypot_type`, `attack_type`, `attacker_ip`, `threat_level`) before being used in queries.
- **XSS sanitization** – raw payload data has HTML special characters escaped (`&`, `<`, `>`, `"`, `'`) before storage.
- **Connection timeout** – each honeypot client connection has a 30-second socket timeout to prevent slow-loris style resource exhaustion.
- **API key authentication** – write endpoints (`/api/honeypots/start`, `/api/honeypots/stop`) require a `Bearer` token when `API_KEY` is configured.
- **Structured JSON logging** – all log output is formatted as JSON for easy ingestion by log aggregators (e.g. ELK, Splunk).
- **Graceful shutdown** – `SIGTERM` and `SIGINT` signals stop all running honeypots cleanly before the process exits.
- **Non-root warning** – the application logs a warning if started as root; the provided Dockerfile runs as a dedicated non-root user.

---

## Security Notice

This platform is designed to run in isolated/controlled environments.  
Do **not** expose honeypot ports to the public internet without proper network segmentation and monitoring.  
Running as root is not recommended; the provided Dockerfile uses a dedicated non-root user.

