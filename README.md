# NetScanner

**Network Discovery & Port Scanning Tool**

> **Note:** This is a re-upload. The original repo was uploaded to my private account and had some issues so I cleaned what i could and pushed it again.

A Python tool I built to scan local networks, find active devices, and check what ports are open on them. Pretty useful for learning how networks actually work, or just seeing what's going on in your home setup.

No external packages needed - it runs on Python's built-in libraries only.

---

## What It Does

- **Finds devices** on your network (using ping or TCP connect)
- **Scans ports** and tells you what services are running (HTTP, SSH, SMB, etc.)
- **Grabs banners** - tries to identify what software is behind each open port
- **Generates reports** in JSON, CSV, and plain text so you can review results later
- **Multi-threaded** - scans fast by checking multiple hosts/ports at the same time
- Works on **Windows, macOS, and Linux**

---

## Prerequisites

- **Python 3.8+** - Download from [python.org](https://www.python.org/downloads/)
- **Git** (optional) - Download from [git-scm.com](https://git-scm.com/downloads)

## Getting Started

**Option 1: Clone with Git**

```bash
git clone https://github.com/osama-l/netscanner.git
cd netscanner
python netscanner.py --help
```

**Option 2: Download ZIP (no Git required)**

1. Go to the [repository page](https://github.com/osama-l/netscanner)
2. Click the green **Code** button → **Download ZIP**
3. Extract it, open a terminal in the folder, and run:

```bash
python netscanner.py --help
```

---

## How to Use It

### Basic Scans

```bash
# Find all active devices on your network
python netscanner.py -t 192.168.1.0/24

# Find devices AND check their open ports
python netscanner.py -t 192.168.1.0/24 --scan-ports

# Scan just one device
python netscanner.py -t 192.168.1.1 --scan-ports
```

Not sure what your network range is? Run `ipconfig` (Windows) or `ifconfig` (Mac/Linux) and look for your IPv4 address. If it's `192.168.1.X`, your network is `192.168.1.0/24`.

### If Ping Doesn't Work

Some firewalls block ping. Try TCP mode instead:

```bash
python netscanner.py -t 192.168.1.0/24 -m tcp
```

### Scanning Specific Ports

```bash
# Scan only certain ports
python netscanner.py -t 192.168.1.0/24 --scan-ports --ports 22,80,443,3389

# Scan a range
python netscanner.py -t 192.168.1.0/24 --scan-ports --ports 1-1024

# Use the extended port list (50+ ports)
python netscanner.py -t 192.168.1.0/24 --scan-ports --extended
```

### Other Options

```bash
# More threads = faster scanning
python netscanner.py -t 192.168.1.0/24 --scan-ports --threads 100

# Longer timeout for slow networks
python netscanner.py -t 192.168.1.0/24 --scan-ports --timeout 3

# No colors (if your terminal shows weird characters like ←[92m)
python netscanner.py -t 192.168.1.0/24 --scan-ports --no-color

# Save reports to a custom folder
python netscanner.py -t 192.168.1.0/24 --scan-ports -o ./my-scans
```

---

## Example Output

```
  ╔═╗╔═╗╔╦╗  ╔═╗╔═╗╔═╗╔╗╔╔╗╔╔═╗╦═╗
  ║║║║╣  ║   ╚═╗║  ╠═╣║║║║║║║╣ ╠╦╝
  ╝╚╝╚═╝ ╩   ╚═╝╚═╝╩ ╩╝╚╝╝╚╝╚═╝╩╚═
  Network Discovery & Port Scanning Tool

[*] Scanning 254 hosts on 192.168.1.0/24 (method: ping)

[✓] Found 4 active host(s):
    192.168.1.1 (router.local)
    192.168.1.10
    192.168.1.25 (desktop-pc.local)
    192.168.1.30

  Scanning 24 ports on 192.168.1.1
    ●    80/tcp  HTTP             HTTP/1.1 200 OK
    ●   443/tcp  HTTPS
    ●    53/tcp  DNS

══════════════════════════════════════════════════════
  SCAN SUMMARY
══════════════════════════════════════════════════════
  Target     : 192.168.1.0/24
  Hosts Found: 4
  Total open ports: 6
══════════════════════════════════════════════════════

[✓] Reports saved:
    JSON → reports/scan_20250315_143022.json
    CSV  → reports/scan_20250315_143022.csv
    TXT  → reports/scan_20250315_143022.txt
```

Each scan automatically saves 3 report files - JSON for data, CSV for spreadsheets, TXT for quick reading.

---

## Project Structure

```
netscanner/
├── netscanner.py      # The main script - everything lives here
├── README.md          # You're reading this
├── LICENSE            # MIT License
├── .gitignore         # Git ignore rules
└── reports/           # Auto-created when you run a scan
```

---

## Quick Explainer: What Are Ports?

If your network is an apartment building, each device is a unit and its IP address is the apartment number. **Ports** are the doors inside each apartment - each one has a number, and behind each door is a service doing a specific job:

| Port | Service | What It Does |
|------|---------|-------------|
| 22 | SSH | Remote terminal access |
| 53 | DNS | Translates domain names to IPs |
| 80 | HTTP | Web traffic (unencrypted) |
| 443 | HTTPS | Web traffic (encrypted) |
| 445 | SMB | File sharing between computers |
| 3389 | RDP | Remote desktop (Windows) |

This tool knocks on those doors and tells you which ones are open.

---

## Heads Up

- **Permissions**: Ping might need admin/root on some systems. Use `-m tcp` if it doesn't work.
- **Legal**: Only scan networks you own or have permission to scan. Scanning other people's networks without consent can get you in trouble.
- **Firewalls**: If devices show as offline with ping, try TCP mode (`-m tcp`).

---

## Built With

- Python 3 (standard library only - no pip installs needed)
- `socket` for TCP connections
- `ipaddress` for network math
- `concurrent.futures` for multi-threading
- `argparse` for the CLI

---

## License

MIT - do whatever you want with it.

---

## Author

**Osama Al-Shahri**
- Portfolio: [osama-l.github.io](https://osama-l.github.io)
- Email: o.alshahri@outlook.com
