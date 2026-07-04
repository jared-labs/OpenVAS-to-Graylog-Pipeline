#!/usr/bin/env python3
"""
openvas_to_cribl.py

Single-shot export of OpenVAS scan results to a log relay (Cribl) as NDJSON over TCP.
Designed to run via cron every 15 minutes with flock for idempotency.

Workflow:
- Connects to gvmd over Unix socket (GMP protocol).
- Finds completed tasks and their latest reports.
- For each report that hasn't been sent yet:
    - Downloads full XML report (bypasses the default 10-result limit).
    - Saves XML under ./reports/<report_id>.xml for retention/debugging.
    - Parses all <result> elements into structured JSON events.
    - Sends events to the log relay over TCP as NDJSON.
    - Marks report_id as processed in processed_reports.txt.

Dependencies:
    pip install python-gvm

Environment variables (all optional, with defaults):
    GVM_SOCKET_PATH  - Path to gvmd Unix socket
    GVM_USERNAME     - GMP authentication username
    GVM_PASSWORD     - GMP authentication password
    CRIBL_HOST       - Log relay hostname/IP
    CRIBL_PORT       - Log relay TCP port
"""

import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Set

from xml.etree import ElementTree as ET

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp


# --- Config ---
GVM_SOCKET_PATH = os.environ.get("GVM_SOCKET_PATH", "/var/lib/gvm/gvmd/gvmd.sock")
GVM_USERNAME = os.environ.get("GVM_USERNAME", "admin")
GVM_PASSWORD = os.environ.get("GVM_PASSWORD", "CHANGE_ME")

CRIBL_HOST = os.environ.get("CRIBL_HOST", "CHANGE_ME")
CRIBL_PORT = int(os.environ.get("CRIBL_PORT", "20020"))

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
STATE_FILE = BASE_DIR / "processed_reports.txt"


def log(msg: str) -> None:
    """Timestamped log output for cron job visibility."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z")
    print(f"[{now}] {msg}")


def load_processed_ids() -> Set[str]:
    """Load report IDs that have already been exported."""
    ids: Set[str] = set()
    if STATE_FILE.exists():
        with STATE_FILE.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    ids.add(line)
    return ids


def save_processed_ids(ids: Set[str]) -> None:
    """Persist processed report IDs to state file."""
    with STATE_FILE.open("w", encoding="utf-8") as f:
        for rid in sorted(ids):
            f.write(rid + "\n")


def ensure_reports_dir() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _to_root(xml_data):
    """Helper to parse XML regardless of whether GMP returns bytes or str."""
    if isinstance(xml_data, bytes):
        return ET.fromstring(xml_data)
    if isinstance(xml_data, str):
        return ET.fromstring(xml_data.encode("utf-8"))
    return ET.fromstring(xml_data)


def find_xml_report_format_id(gmp: Gmp) -> str:
    """Return the report_format id for the 'XML' format."""
    log("[+] Fetching report formats to find XML format id...")
    rf_xml = gmp.get_report_formats()
    root = _to_root(rf_xml)

    for rf in root.findall(".//report_format"):
        name = rf.findtext("name") or ""
        if name.strip().upper() == "XML":
            rf_id = rf.get("id")
            if rf_id:
                log(f"[+] Using report format 'XML' with id={rf_id}")
                return rf_id

    raise RuntimeError("Could not find XML report format in report formats.")


def get_completed_task_reports(gmp: Gmp) -> Dict[str, Dict[str, str]]:
    """
    Returns mapping: report_id -> {'task_name': str}
    for each task whose status is 'Done' and has a last_report.
    """
    log("[+] Fetching tasks from gvmd...")
    tasks_xml = gmp.get_tasks()
    root = _to_root(tasks_xml)

    reports: Dict[str, Dict[str, str]] = {}

    for task in root.findall(".//task"):
        status = (task.findtext("status") or "").strip()
        if status != "Done":
            continue

        task_name = task.findtext("name") or "UNKNOWN_TASK"

        last_report = task.find("last_report/report")
        if last_report is None:
            continue

        rid = last_report.get("id")
        if not rid:
            continue

        reports[rid] = {"task_name": task_name}

    log(f"[+] Found {len(reports)} completed task report(s) in gvmd.")
    return reports


def build_events_from_report_xml(report_id: str, task_name: str, report_xml) -> List[Dict]:
    """Parse XML report and convert <result> elements to structured event dicts."""
    root = _to_root(report_xml)

    # Derive a timestamp for the report
    report_node = root.find(".//report")
    ts = None
    if report_node is not None:
        ts = report_node.findtext("scan_end") or report_node.findtext("creation_time")
    report_timestamp = ts if ts else datetime.now(timezone.utc).isoformat()

    events: List[Dict] = []

    for result in root.findall(".//result"):
        host = result.findtext("host") or ""
        port = result.findtext("port") or ""
        threat = result.findtext("threat") or ""
        severity = result.findtext("severity") or ""
        description = result.findtext("description") or ""

        # NVT (Network Vulnerability Test) metadata
        nvt = result.find("nvt")
        nvt_oid = nvt.get("oid") if nvt is not None else ""
        nvt_name = ""
        nvt_family = ""
        cvss_base = ""
        cve_refs: List[str] = []
        if nvt is not None:
            nvt_name = nvt.findtext("name") or ""
            nvt_family = nvt.findtext("family") or ""
            cvss_base = nvt.findtext("cvss_base") or ""
            for ref in nvt.findall("refs/ref"):
                if ref.get("type") == "cve":
                    cve_id = ref.get("id", "")
                    if cve_id:
                        cve_refs.append(cve_id)

        # Quality of Detection
        qod_val = ""
        qod = result.find("qod")
        if qod is not None:
            qod_val = qod.findtext("value") or ""

        # Solution / remediation info
        solution_elem = result.find("solution")
        solution_type = ""
        solution_text = ""
        if solution_elem is not None:
            solution_type = solution_elem.get("type", "")
            solution_text = (solution_elem.text or "").strip()

        event = {
            "@timestamp": report_timestamp,
            "openvas_report_id": report_id,
            "openvas_task_name": task_name,
            "openvas_host": host,
            "openvas_port": port,
            "openvas_threat": threat,
            "openvas_severity": float(severity) if severity else 0.0,
            "openvas_description": description,
            "openvas_nvt_oid": nvt_oid,
            "openvas_nvt_name": nvt_name,
            "openvas_nvt_family": nvt_family,
            "openvas_cvss_base": float(cvss_base) if cvss_base else 0.0,
            "openvas_cves": cve_refs if cve_refs else [],
            "openvas_qod": qod_val,
            "openvas_solution_type": solution_type,
            "openvas_solution": solution_text,
        }

        events.append(event)

    log(f"[+] Parsed {len(events)} result(s) from report {report_id}.")
    return events


def send_events_to_cribl(events: Iterable[Dict], host: str, port: int, timeout: float = 5.0) -> None:
    """Send list of events as NDJSON over raw TCP to the log relay."""
    events = list(events)
    if not events:
        log("[*] No events to send.")
        return

    log(f"[+] Sending {len(events)} event(s) to {host}:{port} ...")

    data_lines = [
        json.dumps(ev, separators=(",", ":")) + "\n"
        for ev in events
    ]
    payload = "".join(data_lines).encode("utf-8")

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(payload)
    except Exception as exc:
        raise RuntimeError(f"Failed to send events to {host}:{port}: {exc}") from exc

    log("[+] Successfully sent events.")


def main() -> int:
    log("===== OpenVAS → Cribl export start =====")

    if GVM_PASSWORD == "CHANGE_ME":
        log("[!] GVM_PASSWORD is not set. Set GVM_USERNAME/GVM_PASSWORD env vars or edit the script.")
        return 1

    if CRIBL_HOST == "CHANGE_ME":
        log("[!] CRIBL_HOST is not set. Set CRIBL_HOST env var or edit the script.")
        return 1

    ensure_reports_dir()

    processed_ids = load_processed_ids()
    log(f"[*] Currently have {len(processed_ids)} processed report id(s) recorded.")

    # Connect to gvmd
    log(f"[+] Connecting to gvmd on {GVM_SOCKET_PATH} ...")
    try:
        connection = UnixSocketConnection(path=GVM_SOCKET_PATH)
    except Exception as exc:
        log(f"[!] Failed to create UnixSocketConnection: {exc}")
        return 1

    try:
        with Gmp(connection=connection) as gmp:
            log(f"[+] Authenticating to gvmd as '{GVM_USERNAME}' ...")
            gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)
            log("[+] Authenticated to gvmd.")

            xml_format_id = find_xml_report_format_id(gmp)
            completed_reports = get_completed_task_reports(gmp)

            new_report_ids = [
                rid for rid in completed_reports.keys()
                if rid not in processed_ids
            ]

            if not new_report_ids:
                log("[*] No new completed reports to process.")
                return 0

            log(f"[+] Found {len(new_report_ids)} new report(s) to process: {', '.join(new_report_ids)}")

            for rid in new_report_ids:
                task_name = completed_reports[rid]["task_name"]
                log(f"[+] Fetching XML report {rid} for task '{task_name}' ...")

                report_xml = gmp.get_report(rid, report_format_id=xml_format_id, details=True)

                # Save XML to disk for debugging/retention
                report_path = REPORTS_DIR / f"{rid}.xml"
                try:
                    if isinstance(report_xml, (bytes, bytearray)):
                        report_bytes = report_xml
                    else:
                        report_bytes = str(report_xml).encode("utf-8")
                    with report_path.open("wb") as f:
                        f.write(report_bytes)
                    log(f"[+] Saved XML report to {report_path}")
                except Exception as exc:
                    log(f"[!] Failed to save XML report {rid} to disk: {exc}")

                # Build structured events from XML results
                events = build_events_from_report_xml(rid, task_name, report_xml)

                # Send to log relay
                if events:
                    send_events_to_cribl(events, CRIBL_HOST, CRIBL_PORT)
                else:
                    log(f"[*] No events parsed from report {rid}, skipping send.")

                # Mark as processed only after successful export
                processed_ids.add(rid)
                save_processed_ids(processed_ids)
                log(f"[+] Marked report {rid} as processed.")
    except Exception as exc:
        log(f"[!] Fatal error: {exc}")
        return 1

    log("[+] Run complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
