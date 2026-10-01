"""
Network Anomaly Detector
A lightweight, beginner-friendly Python script that parses network traffic logs (CSV)
and detects three security anomalies: Port Scans, Off-Hours Access, and Large Data Transfers.
"""

import csv
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# --- Configuration & Detection Thresholds ---
LARGE_TRANSFER_THRESHOLD = 500 * 1024 * 1024  # 500 MB in bytes
OFF_HOURS_START = 18                          # 18:00 (6:00 PM)
OFF_HOURS_END = 8                             # 08:00 (8:00 AM)
PORT_SCAN_THRESHOLD = 5                       # 5 or more unique destination ports


def format_bytes(byte_count):
    """Convert byte count into readable MB or GB string."""
    if byte_count >= 1024 ** 3:
        return f"{byte_count / (1024 ** 3):.2f} GB"
    return f"{byte_count / (1024 ** 2):.2f} MB"


def load_traffic_log(filepath):
    """Load and parse network traffic records from CSV."""
    records = []
    path = Path(filepath)
    if not path.is_file():
        print(f"[-] File not found: {filepath}")
        return records

    try:
        with open(path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append({
                    "timestamp": datetime.strptime(row["timestamp"].strip(), "%Y-%m-%d %H:%M:%S"),
                    "src_ip": row["src_ip"].strip(),
                    "dst_ip": row["dst_ip"].strip(),
                    "src_port": int(row["src_port"].strip()),
                    "dst_port": int(row["dst_port"].strip()),
                    "protocol": row["protocol"].strip().upper(),
                    "bytes_transferred": int(row["bytes_transferred"].strip())
                })
        print(f"[+] Loaded {len(records)} traffic records from {path.name}")
    except Exception as e:
        print(f"[-] Error parsing log: {e}")
    return records


def detect_port_scans(records):
    """Flag source IPs connecting to 5 or more unique destination ports."""
    ip_to_ports = defaultdict(set)
    ip_to_targets = defaultdict(set)

    for r in records:
        ip_to_ports[r["src_ip"]].add(r["dst_port"])
        ip_to_targets[r["src_ip"]].add(r["dst_ip"])

    anomalies = []
    for src_ip, ports in ip_to_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            targets = ", ".join(sorted(ip_to_targets[src_ip]))
            anomalies.append({
                "type": "PORT SCAN",
                "severity": "HIGH",
                "src_ip": src_ip,
                "dst_ip": targets,
                "detail": f"Probed {len(ports)} unique ports: {sorted(ports)} on target(s): {targets}"
            })
    return anomalies


def detect_off_hours_access(records):
    """Flag connections outside business hours (08:00 - 18:00)."""
    anomalies = []
    for r in records:
        hour = r["timestamp"].hour
        if hour < OFF_HOURS_END or hour >= OFF_HOURS_START:
            time_str = r["timestamp"].strftime("%H:%M:%S")
            anomalies.append({
                "type": "OFF-HOURS ACCESS",
                "severity": "MEDIUM",
                "src_ip": r["src_ip"],
                "dst_ip": f"{r['dst_ip']}:{r['dst_port']}",
                "detail": f"Connected at {time_str} outside business hours ({OFF_HOURS_END:02d}:00-{OFF_HOURS_START:02d}:00)"
            })
    return anomalies


def detect_large_transfers(records):
    """Flag transfers equal to or exceeding 500 MB."""
    anomalies = []
    for r in records:
        bytes_sent = r["bytes_transferred"]
        if bytes_sent >= LARGE_TRANSFER_THRESHOLD:
            anomalies.append({
                "type": "LARGE DATA TRANSFER",
                "severity": "CRITICAL",
                "src_ip": r["src_ip"],
                "dst_ip": f"{r['dst_ip']}:{r['dst_port']}",
                "detail": f"Transferred {format_bytes(bytes_sent)} ({bytes_sent:,} bytes) via {r['protocol']}"
            })
    return anomalies


def print_anomalies(anomalies):
    """Display flagged anomalies formatted by severity in terminal."""
    print("\n" + "=" * 60)
    print("               NETWORK ANOMALY REPORT")
    print("=" * 60)

    if not anomalies:
        print("[+] No anomalies detected.")
        return

    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_anomalies = sorted(anomalies, key=lambda a: rank.get(a["severity"], 9))

    for idx, a in enumerate(sorted_anomalies, 1):
        print(f"\n#{idx} [{a['severity']}] {a['type']}")
        print(f"    Source IP : {a['src_ip']}")
        print(f"    Dest IP   : {a['dst_ip']}")
        print(f"    Detail    : {a['detail']}")

    counts = defaultdict(int)
    for a in anomalies:
        counts[a["severity"]] += 1

    print("\n" + "-" * 60)
    print(f"Summary: {len(anomalies)} anomalies flagged | CRITICAL: {counts['CRITICAL']} | HIGH: {counts['HIGH']} | MEDIUM: {counts['MEDIUM']}")
    print("=" * 60 + "\n")


def save_report(anomalies, filename=None):
    """Export anomalies to a CSV report."""
    if not anomalies:
        return
    filename = filename or f"anomaly_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    fieldnames = ["severity", "type", "src_ip", "dst_ip", "detail"]
    with open(filename, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(anomalies)
    print(f"[+] Report saved: {filename}")


def main():
    default_log = Path(__file__).resolve().parent / "sample_data" / "sample_traffic.csv"
    target_csv = Path(sys.argv[1]) if len(sys.argv) > 1 else default_log

    records = load_traffic_log(target_csv)
    if not records:
        return

    anomalies = []
    anomalies.extend(detect_large_transfers(records))
    anomalies.extend(detect_port_scans(records))
    anomalies.extend(detect_off_hours_access(records))

    print_anomalies(anomalies)
    save_report(anomalies)


if __name__ == "__main__":
    main()
