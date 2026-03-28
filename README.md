# NetScanner

**Network Discovery & Port Scanning Tool**

A lightweight, multi-threaded Python tool for discovering active hosts on a network and scanning for open ports and running services. Built for network administrators, IT support professionals, and cybersecurity learners.

---

## Features

- **Host Discovery** — Scan entire subnets using ICMP ping or TCP connect methods
- **Port Scanning** — Identify open ports with service detection and banner grabbing
- **Multi-threaded** — Fast concurrent scanning with configurable thread count
- **Custom Port Ranges** — Scan common ports, extended lists, or specify your own
- **Service Identification** — Automatically maps 50+ well-known ports to service names
- **Banner Grabbing** — Extracts service version info from open ports
- **Report Generation** — Exports results in JSON, CSV, and plain text formats
- **Cross-Platform** — Works on Windows, macOS, and Linux
- **Colored Output** — Clean, readable terminal interface with progress indicators

---

## Prerequisites

- **Python 3.8+** — Download from [python.org](https://www.python.org/downloads/)
- **Git** (optional) — Download from [git-scm.com](https://git-scm.com/downloads)

No external Python packages required — the tool uses only the standard library.

## Installation

**Option 1: Clone with Git**

```bash
git clone https://github.com/osama-l/netscanner.git
cd netscanner
python netscanner.py --help
```

**Option 2: Download ZIP (no Git required)**

1. Go to the [repository page](https://github.com/osama-l/netscanner)
2. Click the green **Code** button → **Download ZIP**
3. Extract the ZIP and open a terminal in the extracted folder

```bash
cd netscanner
python netscanner.py --help
```

---

## Usage

### Quick Start

```bash
# Discover active hosts on your local network
python netscanner.py -t 192.168.1.0/24

# Discover hosts AND scan their open ports
python netscanner.py -t 192.168.1.0/24 --scan-ports

# Scan a single host
python netscanner.py -t 192.168.1.1 --scan-ports
```

### Host Discovery Methods

```bash
# Default: ICMP ping (may require admin/root on some systems)
python netscanner.py -t 192.168.1.0/24 -m ping

# TCP connect (works when ICMP is blocked by firewalls)
python netscanner.py -t 192.168.1.0/24 -m tcp
```

### Port Scanning Options

```bash
# Scan common ports (24 well-known ports)
python netscanner.py -t 192.168.1.0/24 --scan-ports

# Scan extended port list (50+ ports)
python netscanner.py -t 192.168.1.0/24 --scan-ports --extended

# Scan specific ports
python netscanner.py -t 192.168.1.0/24 --scan-ports --ports 22,80,443,3389

# Scan a port range
python netscanner.py -t 192.168.1.0/24 --scan-ports --ports 1-1024

# Mix individual ports and ranges
python netscanner.py -t 192.168.1.0/24 --scan-ports --ports 22,80,100-200,443
```

### Performance Tuning

```bash
# Increase threads for faster scanning
python netscanner.py -t 192.168.1.0/24 --scan-ports --threads 100

# Increase timeout for slow networks
python netscanner.py -t 10.0.0.0/24 --scan-ports --timeout 3

# Quiet mode — minimal output
python netscanner.py -t 192.168.1.0/24 --scan-ports -q
```

### Output & Reports

```bash
# Reports are saved automatically to ./reports/
python netscanner.py -t 192.168.1.0/24 --scan-ports

# Custom output directory
python netscanner.py -t 192.168.1.0/24 --scan-ports -o ./my-scans

# Disable colored output (useful for piping)
python netscanner.py -t 192.168.1.0/24 --no-color
```

Each scan generates three report files:
- `scan_YYYYMMDD_HHMMSS.json` — Structured data for programmatic use
- `scan_YYYYMMDD_HHMMSS.csv` — Spreadsheet-compatible format
- `scan_YYYYMMDD_HHMMSS.txt` — Human-readable summary

---

## Example Output

```
  ╔═╗╔═╗╔╦╗  ╔═╗╔═╗╔═╗╔╗╔╔╗╔╔═╗╦═╗
  ║║║║╣  ║   ╚═╗║  ╠═╣║║║║║║║╣ ╠╦╝
  ╝╚╝╚═╝ ╩   ╚═╝╚═╝╩ ╩╝╚╝╝╚╝╚═╝╩╚═
  Network Discovery & Port Scanning Tool

[*] Scanning 254 hosts on 192.168.1.0/24 (method: ping)
    Threads: 50 | Timeout: 1s

[✓] Host discovery completed in 5.2s

[✓] Found 4 active host(s):
    192.168.1.1 (router.local)
    192.168.1.10
    192.168.1.25 (desktop-pc.local)
    192.168.1.30

[*] Starting port scan on 4 host(s)...

  Scanning 24 ports on 192.168.1.1
    ●    80/tcp  HTTP             HTTP/1.1 200 OK
    ●   443/tcp  HTTPS
    ●    53/tcp  DNS

══════════════════════════════════════════════════════
  SCAN SUMMARY
══════════════════════════════════════════════════════
  Target     : 192.168.1.0/24
  Date       : 2025-03-15 14:30:22
  Duration   : 12.4s
  Hosts Found: 4
──────────────────────────────────────────────────────
  192.168.1.1 (router.local) — 3 open
  192.168.1.10 — no open ports
  192.168.1.25 (desktop-pc.local) — 2 open
  192.168.1.30 — 1 open
──────────────────────────────────────────────────────
  Total open ports: 6
══════════════════════════════════════════════════════

[✓] Reports saved:
    JSON → reports/scan_20250315_143022.json
    CSV  → reports/scan_20250315_143022.csv
    TXT  → reports/scan_20250315_143022.txt
```

---

## Project Structure

```
netscanner/
├── netscanner.py      # Main scanner script
├── README.md          # Documentation
├── LICENSE            # MIT License
├── .gitignore         # Git ignore rules
└── reports/           # Generated scan reports (auto-created)
    ├── scan_*.json
    ├── scan_*.csv
    └── scan_*.txt
```

---

## How It Works

1. **Host Discovery** — Sends ICMP echo requests (ping) or TCP SYN packets to every address in the target subnet. Multi-threading allows scanning an entire /24 network in seconds.

2. **Port Scanning** — For each discovered host, attempts TCP connections on specified ports. Open ports accept the connection; closed ports refuse it; filtered ports time out.

3. **Banner Grabbing** — On open ports, the scanner sends protocol-appropriate requests (e.g., HTTP HEAD) and captures the server's response to identify software versions.

4. **Report Generation** — All findings are compiled into structured reports (JSON for automation, CSV for spreadsheets, TXT for quick review).

---

## Important Notes

- **Permissions**: ICMP ping may require administrator/root privileges on some systems. Use `--method tcp` as an alternative.
- **Legal Use**: Only scan networks you own or have explicit permission to scan. Unauthorized scanning may violate laws in your jurisdiction.
- **Firewalls**: If hosts appear offline with ping, try TCP method (`-m tcp`) as many firewalls block ICMP.

---

## Technologies Used

- **Python 3** — Core language
- **socket** — TCP/IP connections and port scanning
- **ipaddress** — Network address parsing and host enumeration
- **concurrent.futures** — Thread pool for parallel scanning
- **argparse** — Command-line interface
- **subprocess** — ICMP ping execution

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Author

**Osama Al-Shahri**
- Portfolio: [osama-l.github.io](https://osama-l.github.io)
- Email: o.alshahri@outlook.com
