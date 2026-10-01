# Network Anomaly Detector

A lightweight, rule-based network traffic analysis tool written in Python. It ingests connection logs from CSV files to detect common suspicious network behaviors: **port scanning**, **off-hours activity**, and **unauthorized bulk data exfiltration**.

---

## Features and Detection Modules

| Threat Type | Severity | MITRE ATT&CK | Detection Logic |
|-------------|----------|--------------|-----------------|
| **Large Data Transfer** | `CRITICAL` | [T1048](https://attack.mitre.org/techniques/T1048/) (Exfiltration) | Flags any single connection transferring data exceeding `500 MB` (configurable). Detects bulk file theft or data dumps. |
| **Port Scanning** | `HIGH` | [T1046](https://attack.mitre.org/techniques/T1046/) (Service Discovery) | Flags any source IP that probes `>= 5` unique destination ports. Detects reconnaissance tools like Nmap. |
| **Off-Hours Access** | `MEDIUM` | [T1078](https://attack.mitre.org/techniques/T1078/) (Valid Accounts) | Flags connections occurring outside standard business hours (`08:00 - 18:00`). Useful for spotting unauthorized after-hours activity. |

---

## Project Structure

```text
Network-Anomaly-Detector-main/
|
|-- anomaly_detector.py      # Core detection engine and CLI tool
|-- LICENSE                  # MIT Open Source License
|-- README.md                # Project documentation
|-- .gitignore               # Ignored output files and Python caches
|
`-- sample_data/
    `-- sample_traffic.csv   # 30-line sample dataset for demonstration
```

---

## Requirements

- Python 3.7 or higher
- Standard library only (no external dependencies required)

---

## Quick Start

### 1. Run with Sample Data
Analyze the included sample dataset:
```bash
python anomaly_detector.py
```

### 2. Run with a Custom Log File
Pass the path to any custom CSV file as an argument:
```bash
python anomaly_detector.py path/to/your_traffic_log.csv
```

---

## Input Log Format

The detector expects a CSV file containing the following columns:

```csv
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes_transferred
2026-03-15 09:12:33,192.168.1.22,10.0.0.5,53413,443,TCP,8920
```

- **`timestamp`**: Connection time in `YYYY-MM-DD HH:MM:SS` format.
- **`src_ip`**: Originating IP address.
- **`dst_ip`**: Target destination IP address.
- **`src_port`**: Source port number.
- **`dst_port`**: Destination port number.
- **`protocol`**: Transport protocol (`TCP`, `UDP`, etc.).
- **`bytes_transferred`**: Total bytes transferred during the connection.

---

## Sample Dataset Breakdown (`sample_traffic.csv`)

The provided sample dataset contains 30 records demonstrating both baseline traffic and simulated threat activities:

1. **Baseline Traffic (Lines 2-7, 15-26):**
   - Standard business-hour web (ports 80, 443) and DNS (port 53) connections with normal transfer sizes (100 B - 15 KB).
2. **Port Scan (Lines 8-14):**
   - Host `192.168.1.105` probes ports `21, 22, 23, 80, 443, 3389, 8080` on server `10.0.0.5` within a 6-second window.
3. **Data Exfiltration (Line 20):**
   - Host `192.168.1.50` transfers `850,000,000 bytes` (~810.6 MB) to external host `203.0.113.88:443`.
4. **Off-Hours Connections (Lines 27-31):**
   - Activity outside the 08:00 - 18:00 window, including night-time SSH (`02:15`), FTP (`04:40`), and RDP (`23:10`).

---

## Example Output

### Terminal Output
```text
[+] Loaded 30 traffic records from sample_traffic.csv

============================================================
               NETWORK ANOMALY REPORT
============================================================

#1 [CRITICAL] LARGE DATA TRANSFER
    Source IP : 192.168.1.50
    Dest IP   : 203.0.113.88:443
    Detail    : Transferred 810.62 MB (850,000,000 bytes) via TCP

#2 [HIGH] PORT SCAN
    Source IP : 192.168.1.105
    Dest IP   : 10.0.0.5
    Detail    : Probed 7 unique ports: [21, 22, 23, 80, 443, 3389, 8080] on target(s): 10.0.0.5

#3 [MEDIUM] OFF-HOURS ACCESS
    Source IP : 192.168.1.10
    Dest IP   : 10.0.0.5:443
    Detail    : Connected at 19:15:42 outside business hours (08:00-18:00)

#4 [MEDIUM] OFF-HOURS ACCESS
    Source IP : 192.168.1.99
    Dest IP   : 10.0.0.12:3389
    Detail    : Connected at 23:10:05 outside business hours (08:00-18:00)

#5 [MEDIUM] OFF-HOURS ACCESS
    Source IP : 192.168.1.75
    Dest IP   : 10.0.0.5:22
    Detail    : Connected at 02:15:33 outside business hours (08:00-18:00)

#6 [MEDIUM] OFF-HOURS ACCESS
    Source IP : 192.168.1.80
    Dest IP   : 10.0.0.8:21
    Detail    : Connected at 04:40:12 outside business hours (08:00-18:00)

#7 [MEDIUM] OFF-HOURS ACCESS
    Source IP : 192.168.1.12
    Dest IP   : 10.0.0.1:53
    Detail    : Connected at 07:10:55 outside business hours (08:00-18:00)

------------------------------------------------------------
Summary: 7 anomalies flagged | CRITICAL: 1 | HIGH: 1 | MEDIUM: 5
============================================================

[+] Report saved: anomaly_report_20261001_151928.csv
```

### Exported CSV Report
Each execution automatically writes findings to a timestamped file (`anomaly_report_YYYYMMDD_HHMMSS.csv`) with the columns:
- `severity`
- `type`
- `src_ip`
- `dst_ip`
- `detail`

---

## Configuration

Thresholds can be adjusted directly in [anomaly_detector.py](file:///d:/projects/Network-Anomaly-Detector-main/anomaly_detector.py):

```python
# Flag transfers exceeding this size (in bytes)
LARGE_TRANSFER_THRESHOLD = 500 * 1024 * 1024  # 500 MB

# Business hours window (24-hour format)
OFF_HOURS_START = 18                          # 18:00 (6:00 PM)
OFF_HOURS_END = 8                             # 08:00 (8:00 AM)

# Minimum unique destination ports to trigger a port scan alert
PORT_SCAN_THRESHOLD = 5
```

---

## License

This project is licensed under the [MIT License](file:///d:/projects/Network-Anomaly-Detector-main/LICENSE).
