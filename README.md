# Home Lab Vulnerability Scanning Pipeline

## Overview

This write-up documents how I built and operate a vulnerability scanning pipeline in my home lab. The environment includes 7 hypervisors, roughly 75 networked devices, and a mix of Linux servers, containers, network infrastructure, IoT devices, and workstations. The pipeline runs weekly authenticated scans, exports structured findings, and forwards them into centralized log aggregation so vulnerability data can be searched, alerted on, and correlated with other operational telemetry.

The goal was not just to run a scanner. I wanted a repeatable vulnerability management workflow with scheduled scan waves, durable report export, structured SIEM fields, and operational guardrails for feed updates, deduplication, and recovery.

| Area | Implementation |
|------|----------------|
| Scanner | Greenbone Community Edition / OpenVAS |
| Scanner host | Debian-based Docker VM |
| Scan model | Weekly authenticated scanning plus inventory/discovery coverage |
| Targets | Hypervisors, Linux workloads, network devices, workstations, and IoT devices |
| Log relay | Cribl Stream TCP JSON pipeline |
| SIEM | Graylog with structured field extraction |
| Export cadence | Every 15 minutes via cron |
| Feed updates | Weekly feed refresh before scheduled scan waves |
| Idempotency | `flock` lock around export job and processed-report state file |

---

## Architecture

The scanner runs as a containerized Greenbone stack on a dedicated VM. The design keeps scanner services isolated while still allowing authenticated checks against Linux targets and unauthenticated probes across mixed device classes.

```text
┌────────────────────────────────────────────────────────────────┐
│  Scanner VM                                                     │
│  Docker Compose: Greenbone Community Edition                    │
│                                                                │
│  ┌──────────┐    ┌──────────┐    ┌────────────────────────┐   │
│  │   GSA    │───▶│  gvmd    │───▶│   ospd-openvas         │   │
│  │ web UI   │    │ manager  │    │   scanner engine       │   │
│  └──────────┘    └──────────┘    └────────────────────────┘   │
│                       │                    │                   │
│                       ▼                    ▼                   │
│                ┌──────────┐        ┌──────────┐               │
│                │ postgres │        │  redis   │               │
│                │ GVM data │        │ VT cache │               │
│                └──────────┘        └──────────┘               │
│                                                                │
│  Feed volumes: vulnerability tests, Notus data, SCAP data,     │
│  CERT data, report formats, data objects, and GPG metadata     │
└────────────────────────────────────────────────────────────────┘
         │
         │ Authenticated SSH checks and network probes
         ▼
┌────────────────────────────────────────────────────────────────┐
│  Scan Targets                                                   │
│  • Hypervisors                                                  │
│  • Linux VMs and containers                                     │
│  • Network infrastructure                                       │
│  • Workstations, NAS devices, cameras, and IoT systems          │
└────────────────────────────────────────────────────────────────┘
```

The reporting path is separate from the scan execution path. Completed reports are exported from the scanner, serialized as newline-delimited JSON, passed through a log relay, and flattened in the SIEM.

```text
┌──────────────────┐     TCP / NDJSON      ┌──────────────────┐     TCP / JSON       ┌──────────────────┐
│  Scanner VM      │     port 20020        │  Log relay        │     port 20025       │  SIEM server      │
│                  │──────────────────────▶│                  │─────────────────────▶│                  │
│  report exporter │                       │  TCP JSON input   │                      │  raw TCP input    │
│  cron job        │                       │  pass-through     │                      │  JSON flattening  │
└──────────────────┘                       └──────────────────┘                      └──────────────────┘
```

---

## Pipeline: OpenVAS To Cribl To Graylog

### OpenVAS Export

The export script connects to the Greenbone manager over the local Unix socket and looks for completed reports that have not already been processed. For each new report, it downloads the full XML, parses individual `<result>` elements, normalizes important fields, and sends one JSON event per finding.

Core behavior:

1. Authenticate to the Greenbone manager through the local socket.
2. Query completed scan reports.
3. Skip report IDs already present in the processed-report state file.
4. Download full XML for each unprocessed report.
5. Parse result records into normalized JSON events.
6. Send events as NDJSON to the log relay over raw TCP.
7. Mark the report ID as processed only after export succeeds.

The exporter intentionally preserves the original report XML for a limited retention window. That makes troubleshooting easier when a parsed field looks wrong or a downstream pipeline changes.

```text
/opt/openvas-vuln-export/
├── openvas_to_cribl.py          # GMP socket -> XML -> JSON -> TCP
├── send_openvas_to_cribl.sh     # wrapper used by cron
├── processed_reports.txt        # sent report IDs
└── reports/                     # temporary XML report cache
```

### Cribl Relay

Cribl receives NDJSON over a TCP JSON input and forwards the events to the SIEM as TCP JSON. In this design, Cribl acts primarily as a reliable relay and routing layer rather than the place where vulnerability fields are deeply transformed.

Cribl responsibilities:

| Stage | Purpose |
|-------|---------|
| TCP JSON input | Accept newline-delimited scanner events |
| Pipeline | Add routing metadata and preserve event shape |
| TCP JSON output | Forward structured JSON to the SIEM input |

Keeping the relay lightweight reduced operational risk. When the exporter added new fields, the downstream SIEM flattening pipeline could discover them without requiring a Cribl deployment change.

### Graylog Ingestion

Graylog receives the forwarded JSON on a raw TCP input. A pipeline rule parses the JSON payload and flattens nested OpenVAS fields into searchable fields.

This gives the SIEM native range queries, stream routing, dashboards, and alert conditions such as:

```text
openvas_severity:>7.0
openvas_threat:High
openvas_nvt_family:"Debian Local Security Checks"
openvas_cves_0:*
```

---

## Field Schema

Each OpenVAS result is emitted as one JSON event. Fields are prefixed with `openvas_` so they remain easy to identify after SIEM flattening and do not collide with generic log fields such as `host`, `source`, or `message`.

| Field | Type | Description |
|-------|------|-------------|
| `openvas_host` | string | Target host address, sanitized or internal-only in public exports |
| `openvas_port` | string | Port and protocol, for example `443/tcp` |
| `openvas_threat` | string | OpenVAS threat label such as `High`, `Medium`, `Low`, or `Log` |
| `openvas_severity` | number | Numeric CVSS-style severity used for range queries |
| `openvas_cvss_base` | number | NVT CVSS base score when available |
| `openvas_nvt_name` | string | Vulnerability test or check name |
| `openvas_nvt_oid` | string | OpenVAS NVT identifier |
| `openvas_nvt_family` | string | NVT family, such as local security checks or web servers |
| `openvas_cves` | array | CVE identifiers associated with the finding |
| `openvas_qod` | number | Quality of detection score from 0 to 100 |
| `openvas_description` | string | Finding description |
| `openvas_solution_type` | string | Remediation category, such as `VendorFix` or `Mitigation` |
| `openvas_solution` | string | Remediation guidance |
| `openvas_report_id` | string | Scanner report UUID |
| `openvas_task_name` | string | Scanner task name |
| `@timestamp` | timestamp | Scan completion or export timestamp |
| `cribl_pipe` | string | Log relay pipeline metadata |

Example event:

```json
{
  "openvas_host": "10.x.x.x",
  "openvas_port": "443/tcp",
  "openvas_threat": "Medium",
  "openvas_severity": 5.3,
  "openvas_cvss_base": 5.3,
  "openvas_nvt_name": "Example TLS Configuration Finding",
  "openvas_nvt_oid": "1.3.6.1.4.1.25623.1.0.xxxxx",
  "openvas_nvt_family": "SSL and TLS",
  "openvas_cves": [],
  "openvas_qod": 80,
  "openvas_solution_type": "Mitigation",
  "openvas_solution": "Review and harden the affected service configuration.",
  "openvas_report_id": "<report-uuid>",
  "openvas_task_name": "Linux Servers - Weekly Authenticated",
  "@timestamp": "2026-07-04T05:30:00Z"
}
```

Severity is emitted as a numeric value, not a string. That small choice matters because it enables SIEM queries like `openvas_severity:>=7.0`, histogram dashboards, and alert thresholds without string parsing.

---

## Automation

The scanner uses two recurring automation patterns: weekly scanner maintenance and frequent report export.

### Feed Updates

Feeds are refreshed before the weekly scan window so vulnerability tests, SCAP data, and report formats are current before authenticated scans begin.

```cron
# Weekly feed refresh before scan waves
0 0 * * 6 /opt/greenbone-community-container/feed-update.sh
```

The update sequence matters:

1. Pull updated feed images.
2. Start or refresh feed-populating containers.
3. Restart the scanner engine so it reloads vulnerability tests.
4. Restart the manager after the scanner engine has loaded tests.
5. Confirm the manager has completed its VT sync before scan waves begin.

### Scan Waves

Authenticated scans are split into waves. Hypervisors, general Linux workloads, and mixed device groups are scanned in separate windows to reduce contention and avoid saturating shared links.

| Wave | Target group | Schedule pattern | Rationale |
|------|--------------|------------------|-----------|
| Wave 1 | Linux workloads and mixed endpoints | Weekly, early maintenance window | Covers the broadest device set first |
| Wave 2 | Hypervisors and heavier infrastructure | Weekly, offset later | Avoids stacking intensive checks against critical hosts |
| Discovery | Full subnet inventory | On demand or low-frequency | Useful for visibility without credentialed checks |

### Report Export

The export job runs every 15 minutes and uses `flock` to prevent overlapping executions. This matters when a large XML report takes longer than expected to download, parse, or send.

```cron
*/15 * * * * cd /opt/openvas-vuln-export && /usr/bin/flock -n /tmp/openvas_to_cribl.lock ./send_openvas_to_cribl.sh >> /var/log/openvas_to_cribl.log 2>&1
0 3 * * * find /opt/openvas-vuln-export/reports -type f -name '*.xml' -mtime +30 -delete
```

The state file stores processed report IDs:

```text
processed_reports.txt
<report-uuid-1>
<report-uuid-2>
<report-uuid-3>
```

To replay a report, remove its ID from the state file and allow the next export cycle to process it again.

---

## Troubleshooting

| Problem | Likely Cause | Operational Fix |
|---------|--------------|-----------------|
| Scanner manager or scanner engine fails after restart | Native services are running alongside the containerized stack | Ensure only the containerized Greenbone services are active |
| Vulnerability test count is unexpectedly low | Feed volumes did not populate correctly | Refresh feed containers, restart scanner engine, then restart manager |
| Tasks remain interrupted after a host reboot | Manager has not finished syncing vulnerability tests from the scanner engine | Wait for VT sync completion, then restart interrupted tasks |
| Web UI login works but API calls fail | Session cookie and anti-CSRF token handling differ by endpoint | Use the Greenbone Management Protocol socket for automation |
| Python GVM client reports unsupported GMP version | Client library version does not match the containerized GVM version | Use raw GMP XML over the local Unix socket for stable automation |
| Findings arrive but SIEM fields are missing | JSON was ingested as an opaque message | Verify SIEM JSON parsing and flattening pipeline is attached to the stream |
| Severity range queries do not work | Severity was indexed as a string | Emit severity as a JSON number and verify field type mapping |
| Export job runs twice at the same time | Previous export cycle has not finished | Wrap cron execution with `flock -n` |
| Duplicate findings appear after replay | Report ID was removed from state and resent intentionally | Rebuild affected dashboard time windows or deduplicate by report ID and NVT |
| Authenticated checks return shallow results | Scan service account lacks local permissions | Confirm the account has the required least-privilege elevation for local checks |

Useful verification points:

```bash
# Confirm scanner containers are healthy
docker ps --filter "name=greenbone"

# Confirm the scanner engine has loaded vulnerability tests
docker logs <scanner-engine-container> --tail 20

# Confirm the exporter is running successfully
tail -20 /var/log/openvas_to_cribl.log

# Confirm relay and SIEM listeners are available
ss -tlnp | grep 20020
ss -tlnp | grep 20025
```

For public documentation, queries should use placeholders:

```bash
curl -s -u "REDACTED:REDACTED" \
  "http://<siem-server>:9000/api/search/universal/relative?query=openvas*&range=86400&limit=5" \
  -H "Accept: application/json" \
  -H "X-Requested-By: cli"
```

---

## Design Decisions

### TCP JSON Over HTTP For Pipeline Reliability

I chose newline-delimited JSON over raw TCP between the scanner, relay, and SIEM because the workload is append-only event streaming. The exporter does not need a complex request/response API; it needs a simple transport that can send many events quickly, fail obviously, and be retried by report ID. TCP JSON also maps cleanly onto Cribl and Graylog inputs without requiring custom HTTP handlers or per-event API calls.

### JSON Flattening At The SIEM Layer

The exporter emits already-normalized `openvas_` fields, while the SIEM owns final parsing and flattening. I intentionally avoided deep transformation in the relay so the pipeline could evolve with minimal coordination. When new fields such as CVEs, NVT family, or solution text are added, the SIEM flattening rule can index them without a relay-side schema rewrite.

### Numeric Severity For Range Queries

Severity is stored as a JSON number rather than a string. This enables practical analyst workflows: threshold alerts, dashboard buckets, and queries like `openvas_severity:>7.0`. Treating severity as text would make those workflows brittle and would push type conversion into every query.

### Scan Wave Scheduling To Avoid Bandwidth Saturation

The lab has a diverse set of targets, and authenticated scans can be noisy. I split weekly scans into waves so infrastructure checks, Linux package checks, and mixed endpoint probes do not all compete for the same bandwidth and host resources at once. The result is a quieter maintenance window and fewer false operational signals from scan-induced load.

### `flock` For Cron Idempotency

The exporter runs frequently, but XML report size and downstream availability can vary. Wrapping the cron job with `flock -n` prevents overlapping runs and keeps the state file consistent. This is a small control, but it prevents a common class of duplicate-send and partial-state problems.

### Socket-Based GMP Automation

For scanner automation, I prefer the Greenbone Management Protocol over the local Unix socket. It avoids web-form behavior, session-token edge cases, and version-specific UI assumptions. The socket approach is boring in the best way: local, explicit, scriptable, and easy to reason about during recovery.

---

## Operating Notes

The most important lesson from this build is that vulnerability scanning becomes more valuable when treated as an operations pipeline rather than a standalone tool. The scanner finds issues, but the surrounding system makes those findings durable: scheduled waves, authenticated checks, normalized fields, SIEM queries, replayable exports, and predictable troubleshooting paths.

For a home lab, this is intentionally more structured than a one-off scanner install. That structure pays off when comparing weekly changes, validating remediation, and demonstrating security engineering practices in a realistic environment.
