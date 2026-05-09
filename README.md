# IDS Dashboard

A working Python IDS dashboard built with Flask. It analyzes real log files
instead of showing mock alerts. You can upload a log through the browser, call
the JSON API, or run the command-line analyzer directly.

## What This Project Does

This project reads plain-text security logs, extracts useful fields, applies
detection rules, and displays alerts in a web dashboard. It is designed as a
safe cybersecurity learning project for local logs and authorized systems.

The IDS can detect:

- Repeated failed login attempts from the same source IP.
- Possible port scans from firewall/key-value network logs.
- Suspicious web requests, including SQL injection, XSS, path traversal, and
  command injection patterns.
- Traffic spikes from a single source IP.
- Known suspicious IPs or domains listed in `data/blocklist.txt`.

## Technologies Used

- Python 3
- Flask 3.1.0
- HTML5
- CSS3
- Python `unittest`
- Git/GitHub

## How It Works

1. A user uploads a `.log`, `.txt`, or `.csv` file from the dashboard.
2. `ids_engine.py` parses each line and tries to identify timestamps, source
   IPs, destination IPs, destination ports, web request paths, and event types.
3. The rule engine checks the parsed events for suspicious behavior.
4. Alerts are assigned severity levels such as `critical`, `high`, and
   `medium`.
5. `app.py` displays the summary, alert list, top source IPs, event types, and
   parsed events in the Flask dashboard.

## Features

- Upload and analyze real log files from the browser.
- CLI mode for quick terminal analysis.
- JSON API endpoint for sample analysis.
- Dashboard with alert counts, severity counts, source IP statistics, and
  parsed event table.
- Local threat indicator list in `data/blocklist.txt`.
- Realistic sample logs in the `samples/` folder.

## Supported Log Examples

The parser accepts common plain-text formats, including:

- SSH/auth style lines:
  `2026-05-09 18:10:01 Failed password for admin from 10.0.0.8 port 52844 ssh2`
- Web access logs:
  `10.0.0.5 - - [09/May/2026:18:10:03 +0530] "GET /login?id=1' OR '1'='1 HTTP/1.1" 200 512`
- Firewall/key-value logs:
  `2026-05-09T18:10:05 src=10.0.0.9 dst=10.0.0.2 dpt=22 action=DENY proto=TCP`

## Run

Install dependencies:

```powershell
pip install -r requirements.txt
```

Start the web app:

```powershell
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## CLI Usage

```powershell
python ids_engine.py samples/sample_mixed.log
```

Try the larger sample:

```powershell
python ids_engine.py samples/sample_enterprise_incident.log
```

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Project Structure

- `app.py` - Flask web application.
- `ids_engine.py` - Log parser and IDS rule engine.
- `data/blocklist.txt` - Local threat indicator list.
- `samples/sample_mixed.log` - Realistic sample log for testing.
- `samples/sample_enterprise_incident.log` - Larger sample incident log.
- `templates/index.html` - Dashboard UI.
- `static/styles.css` - Styling.
- `tests/test_ids_engine.py` - Unit tests for parser and detection behavior.

## Ethical Use

Use this only on logs and systems you own or have permission to monitor.
