# OpenVAS → Cribl → Graylog Pipeline — Operations Guide

> Step-by-step setup for the vulnerability export pipeline: cron-based report extraction from OpenVAS, NDJSON relay through Cribl Stream, and structured ingestion in Graylog.

---

## At a Glance

| Component | Role | Location |
|-----------|------|----------|
| Export script | Connects to GVM socket, extracts XML reports, emits NDJSON | Scanner VM |
| Cron job | Runs exporter every 15 minutes with `flock` | Scanner VM |
| Cribl Stream | TCP JSON input → pass-through pipeline → TCP JSON output | Log relay VM |
| Graylog | Raw TCP input → JSON parse pipeline → searchable fields | SIEM VM |

---

## Prerequisites

- OpenVAS/Greenbone scanner deployed and producing scan reports
- Cribl Stream instance with network access to both scanner and Graylog
- Graylog instance with a free TCP port for a new input
- Python 3 on the scanner VM
- `python-gvm` library installed (or use raw socket — see script)

---

## 1 — Scanner VM: Export Script Setup

### 1.1 Create the working directory

```bash
sudo mkdir -p /opt/openvas-vuln-export/reports
sudo chown $USER:$USER /opt/openvas-vuln-export
```

### 1.2 Deploy the export script

Copy `openvas_to_cribl.py` to the scanner VM:

```bash
scp openvas_to_cribl.py <user>@<scanner-ip>:/opt/openvas-vuln-export/
```

The script does:

1. Authenticate to the Greenbone manager through the local Unix socket
2. Query completed scan reports
3. Skip report IDs already in `processed_reports.txt`
4. Download full XML for each unprocessed report
5. Parse result records into normalized JSON events (prefixed with `openvas_`)
6. Send events as NDJSON to Cribl over raw TCP
7. Mark the report ID as processed only after export succeeds

### 1.3 Create the wrapper script

```bash
cat > /opt/openvas-vuln-export/send_openvas_to_cribl.sh << 'EOF'
#!/bin/bash
# Wrapper for cron — sets environment and runs the exporter
cd /opt/openvas-vuln-export || exit 1
python3 openvas_to_cribl.py
EOF

chmod +x /opt/openvas-vuln-export/send_openvas_to_cribl.sh
```

### 1.4 Create the processed reports state file

```bash
touch /opt/openvas-vuln-export/processed_reports.txt
```

### 1.5 Test the exporter manually

```bash
cd /opt/openvas-vuln-export
python3 openvas_to_cribl.py
```

Check the log output and verify events appear at the Cribl input.

---

## 2 — Scanner VM: Cron Configuration

### 2.1 Install the cron job

```bash
(crontab -l 2>/dev/null; cat << 'EOF'
# OpenVAS report export — every 15 minutes with flock to prevent overlap
*/15 * * * * cd /opt/openvas-vuln-export && /usr/bin/flock -n /tmp/openvas_to_cribl.lock ./send_openvas_to_cribl.sh >> /var/log/openvas_to_cribl.log 2>&1

# Clean up old XML reports (older than 30 days)
0 3 * * * find /opt/openvas-vuln-export/reports -type f -name '*.xml' -mtime +30 -delete
EOF
) | crontab -
```

### 2.2 Verify

```bash
crontab -l | grep openvas
```

### 2.3 Why `flock`?

The exporter runs every 15 minutes, but large XML reports can take longer to download and parse. `flock -n` prevents overlapping runs and keeps the state file consistent.

---

## 3 — Cribl Stream: TCP JSON Input

### 3.1 Create the input

In Cribl Stream UI → Sources → TCP JSON:

| Setting | Value |
|---------|-------|
| Input ID | `openvas_in` |
| Address | `0.0.0.0` |
| Port | `20020` |
| Format | NDJSON (one JSON object per line) |

### 3.2 Create the pipeline (minimal pass-through)

In Cribl → Pipelines → Create pipeline:

- Name: `openvas_passthrough`
- Functions: (optional) Add a field: `cribl_pipe` = `openvas_passthrough`
- No deep transformation — the exporter already normalizes fields

### 3.3 Create the output

In Cribl → Destinations → TCP JSON:

| Setting | Value |
|---------|-------|
| Output ID | `graylog_openvas` |
| Address | `<graylog-ip>` |
| Port | `20025` |
| Format | JSON (newline-delimited) |

### 3.4 Route

In Cribl → Routes:

- Filter: `cribl_pipe=='openvas_passthrough'` or route by input
- Pipeline: `openvas_passthrough`
- Output: `graylog_openvas`

---

## 4 — Graylog: Raw TCP Input

### 4.1 Create the input

In Graylog UI → System → Inputs → Launch new input:

| Setting | Value |
|---------|-------|
| Input type | Raw/Plaintext TCP |
| Node | (your Graylog node) |
| Port | `20025` |
| Bind address | `0.0.0.0` |
| No delimiter | (one JSON object per line, terminated by newline) |

### 4.2 Create a stream

Create a stream to capture OpenVAS events:

- Name: `OpenVAS Findings`
- Rule: Field `openvas_nvt_name` exists (or match on source input)

### 4.3 Create a pipeline rule for JSON parsing

In Graylog → System → Pipelines → Create pipeline:

**Stage 0 — Parse JSON:**

```
rule "parse openvas json"
when
  has_field("message") AND contains(to_string($message.message), "openvas_")
then
  let json = parse_json(to_string($message.message));
  set_field("openvas_host", json.openvas_host);
  set_field("openvas_port", json.openvas_port);
  set_field("openvas_threat", json.openvas_threat);
  set_field("openvas_severity", json.openvas_severity);
  set_field("openvas_cvss_base", json.openvas_cvss_base);
  set_field("openvas_nvt_name", json.openvas_nvt_name);
  set_field("openvas_nvt_oid", json.openvas_nvt_oid);
  set_field("openvas_nvt_family", json.openvas_nvt_family);
  set_field("openvas_qod", json.openvas_qod);
  set_field("openvas_description", json.openvas_description);
  set_field("openvas_solution_type", json.openvas_solution_type);
  set_field("openvas_solution", json.openvas_solution);
  set_field("openvas_report_id", json.openvas_report_id);
  set_field("openvas_task_name", json.openvas_task_name);
end
```

### 4.4 Connect pipeline to stream

Attach the pipeline to the `OpenVAS Findings` stream (or the "All messages" stream if you want broad coverage).

---

## 5 — Validation

### 5.1 End-to-end test

1. Run a scan in OpenVAS that produces at least one finding
2. Wait for the scan to complete
3. Manually trigger the exporter:
   ```bash
   cd /opt/openvas-vuln-export && python3 openvas_to_cribl.py
   ```
4. Check Cribl → Monitoring → verify events flowing through `openvas_in`
5. Check Graylog → Search → query: `openvas_severity:>0`

### 5.2 Verify listeners

```bash
# On Cribl host
ss -tlnp | grep 20020

# On Graylog host
ss -tlnp | grep 20025
```

### 5.3 Verify cron is running

```bash
tail -20 /var/log/openvas_to_cribl.log
```

---

## 6 — Replaying a Report

To re-send a previously processed report:

1. Edit the state file and remove the report UUID:
   ```bash
   vim /opt/openvas-vuln-export/processed_reports.txt
   # Delete the line containing the report ID
   ```

2. Wait for the next cron cycle (or run manually):
   ```bash
   cd /opt/openvas-vuln-export && python3 openvas_to_cribl.py
   ```

> **Note:** This will produce duplicate events in Graylog for that report's findings. Use time-bounded searches to isolate replayed data.

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| No events in Cribl | Exporter can't connect to TCP port 20020 | Verify Cribl input is running: `ss -tlnp \| grep 20020` |
| Events in Cribl but not Graylog | Cribl output not reaching Graylog | Verify Graylog input on 20025, check Cribl output status |
| Fields show as `message` blob in Graylog | Pipeline rule not attached or not parsing | Verify pipeline is connected to the correct stream |
| Severity range queries fail | Field indexed as string | Emit severity as JSON number in exporter; check Graylog field type |
| Export job runs twice | Previous cycle still running | `flock -n` should prevent this — check if lock file is stale |
| `processed_reports.txt` growing large | Normal over time | Prune old entries periodically (reports older than retained data) |
| GMP socket connection refused | gvmd container not running | Restart gvmd container on scanner VM |
| Python `gvm` version mismatch | Host library vs container GVM version | Use raw XML over Unix socket instead of python-gvm |

---

## Quick Reference

```bash
# Manual export run
cd /opt/openvas-vuln-export && python3 openvas_to_cribl.py

# Check cron log
tail -30 /var/log/openvas_to_cribl.log

# Check processed reports
wc -l /opt/openvas-vuln-export/processed_reports.txt

# Verify Cribl input
curl -s http://<cribl-ip>:9000/api/v1/system/inputs | jq '.items[] | select(.id=="openvas_in")'

# Query Graylog for recent findings
curl -u admin:REDACTED "http://<graylog-ip>:9000/api/search/universal/relative?query=openvas_severity:>0&range=3600&limit=5" \
  -H "Accept: application/json" -H "X-Requested-By: cli"

# Replay a specific report
sed -i '/<report-uuid>/d' /opt/openvas-vuln-export/processed_reports.txt
```

---

## File Layout on Scanner VM

```
/opt/openvas-vuln-export/
├── openvas_to_cribl.py          # GMP socket → XML → JSON → TCP
├── send_openvas_to_cribl.sh     # wrapper used by cron
├── processed_reports.txt        # sent report IDs (state file)
└── reports/                     # temporary XML report cache (auto-cleaned)
```

---

Last updated: 2026-07-04
