#!/usr/bin/env python3
"""
NetScanner - Network Discovery & Port Scanning Tool
====================================================
A lightweight Python-based network scanner that discovers active hosts
on a local network and identifies open ports and running services.

Author: Osama Al-Shahri
GitHub: https://github.com/osama-l/netscanner
"""

import argparse
import csv
import ipaddress
import json
import os
import platform
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

# Common ports and their associated services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MS-SQL",
    1434: "MS-SQL-UDP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    27017: "MongoDB",
}

# Extended port list for thorough scans
EXTENDED_PORTS = {
    **COMMON_PORTS,
    69: "TFTP",
    111: "RPCBind",
    161: "SNMP",
    162: "SNMP-Trap",
    389: "LDAP",
    514: "Syslog",
    636: "LDAPS",
    873: "Rsync",
    1080: "SOCKS",
    1521: "Oracle-DB",
    2049: "NFS",
    2181: "ZooKeeper",
    3000: "Grafana",
    5000: "Flask-Dev",
    5672: "RabbitMQ",
    6379: "Redis",
    8000: "HTTP-Dev",
    8081: "HTTP-Alt-2",
    9090: "Prometheus",
    9200: "Elasticsearch",
    27018: "MongoDB-Alt",
}

# ──────────────────────────────────────────────
# ANSI Color Codes for Terminal Output
# ──────────────────────────────────────────────

class Colors:
    """ANSI escape codes for colored terminal output."""
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @staticmethod
    def disable():
        """Disable colors for non-supporting terminals."""
        Colors.HEADER = ""
        Colors.BLUE = ""
        Colors.CYAN = ""
        Colors.GREEN = ""
        Colors.YELLOW = ""
        Colors.RED = ""
        Colors.BOLD = ""
        Colors.DIM = ""
        Colors.RESET = ""


# ──────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────

BANNER = f"""
{Colors.CYAN}{Colors.BOLD}
  ╔═╗╔═╗╔╦╗  ╔═╗╔═╗╔═╗╔╗╔╔╗╔╔═╗╦═╗
  ║║║║╣  ║   ╚═╗║  ╠═╣║║║║║║║╣ ╠╦╝
  ╝╚╝╚═╝ ╩   ╚═╝╚═╝╩ ╩╝╚╝╝╚╝╚═╝╩╚═
{Colors.RESET}{Colors.DIM}  Network Discovery & Port Scanning Tool
  By Osama Al-Shahri{Colors.RESET}
"""


# ──────────────────────────────────────────────
# Host Discovery
# ──────────────────────────────────────────────

def ping_host(ip: str, timeout: int = 1) -> bool:
    """
    Check if a host is alive using ICMP ping.

    Args:
        ip: Target IP address as a string.
        timeout: Seconds to wait for a response.

    Returns:
        True if the host responds, False otherwise.
    """
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_flag = "-w" if platform.system().lower() == "windows" else "-W"

    try:
        result = subprocess.run(
            ["ping", param, "1", timeout_flag, str(timeout), str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def tcp_ping(ip: str, port: int = 80, timeout: float = 1.0) -> bool:
    """
    Check if a host is alive using a TCP connection attempt.
    Useful when ICMP is blocked by firewalls.

    Args:
        ip: Target IP address.
        port: Port to attempt connection on.
        timeout: Connection timeout in seconds.

    Returns:
        True if connection succeeds or is refused (host is alive).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((str(ip), port))
        sock.close()
        # connect_ex returns 0 on success, or errno on failure
        # Connection refused (111) still means the host is alive
        return result == 0 or result == 111
    except (socket.timeout, OSError):
        return False


def discover_hosts(network: str, timeout: int = 1, threads: int = 50,
                   method: str = "ping") -> list:
    """
    Scan a network range and return a list of active hosts.

    Args:
        network: Network in CIDR notation (e.g., '192.168.1.0/24').
        timeout: Timeout per host in seconds.
        threads: Number of concurrent threads.
        method: Discovery method - 'ping' (ICMP) or 'tcp' (TCP connect).

    Returns:
        Sorted list of active IP addresses as strings.
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        print(f"{Colors.RED}[ERROR] Invalid network: {e}{Colors.RESET}")
        return []

    hosts = list(net.hosts())
    total = len(hosts)
    active_hosts = []

    print(f"\n{Colors.BLUE}[*] Scanning {total} hosts on {network} "
          f"(method: {method}){Colors.RESET}")
    print(f"{Colors.DIM}    Threads: {threads} | Timeout: {timeout}s{Colors.RESET}\n")

    scan_func = ping_host if method == "ping" else tcp_ping
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit all scan tasks
        future_to_ip = {
            executor.submit(scan_func, str(ip), timeout): str(ip)
            for ip in hosts
        }

        completed = 0
        for future in as_completed(future_to_ip):
            completed += 1
            ip = future_to_ip[future]

            # Progress indicator
            progress = int((completed / total) * 40)
            bar = f"{'█' * progress}{'░' * (40 - progress)}"
            print(f"\r  {Colors.DIM}[{bar}] {completed}/{total}{Colors.RESET}",
                  end="", flush=True)

            try:
                if future.result():
                    active_hosts.append(ip)
            except Exception:
                pass

    elapsed = time.time() - start_time
    print(f"\r  {'':60}")  # Clear progress bar
    print(f"\r{Colors.GREEN}[✓] Host discovery completed in "
          f"{elapsed:.1f}s{Colors.RESET}")

    # Sort by IP address numerically
    active_hosts.sort(key=lambda x: ipaddress.ip_address(x))
    return active_hosts


# ──────────────────────────────────────────────
# Port Scanning
# ──────────────────────────────────────────────

def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    """
    Scan a single port on a target host.

    Args:
        ip: Target IP address.
        port: Port number to scan.
        timeout: Connection timeout in seconds.

    Returns:
        Dictionary with port info if open, None if closed.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))

        if result == 0:
            # Try to grab the service banner
            banner = grab_banner(sock, ip, port)
            service = EXTENDED_PORTS.get(port, "Unknown")
            sock.close()
            return {
                "port": port,
                "state": "open",
                "service": service,
                "banner": banner,
            }
        sock.close()
        return None

    except (socket.timeout, OSError):
        return None


def grab_banner(sock: socket.socket, ip: str, port: int) -> str:
    """
    Attempt to grab a service banner from an open port.

    Args:
        sock: Connected socket object.
        ip: Target IP (for HTTP requests).
        port: Target port number.

    Returns:
        Banner string if retrieved, empty string otherwise.
    """
    try:
        # For HTTP/HTTPS ports, send a HEAD request
        if port in (80, 443, 8080, 8443, 8000, 8888, 3000, 8081, 9090):
            sock.send(f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode())

        sock.settimeout(2)
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()

        # Clean up the banner - take only the first line
        if banner:
            first_line = banner.split("\n")[0].strip()
            return first_line[:80]  # Limit length
        return ""
    except (socket.timeout, OSError, UnicodeDecodeError):
        return ""


def scan_host_ports(ip: str, ports: dict = None, timeout: float = 1.0,
                    threads: int = 30) -> list:
    """
    Scan multiple ports on a single host.

    Args:
        ip: Target IP address.
        ports: Dictionary of {port: service_name} to scan.
        timeout: Timeout per port.
        threads: Number of concurrent threads.

    Returns:
        List of dictionaries containing open port information.
    """
    if ports is None:
        ports = COMMON_PORTS

    port_list = list(ports.keys())
    open_ports = []

    print(f"\n  {Colors.CYAN}Scanning {len(port_list)} ports on "
          f"{Colors.BOLD}{ip}{Colors.RESET}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in port_list
        }

        for future in as_completed(future_to_port):
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
                    print(f"    {Colors.GREEN}● {result['port']:>5}/tcp  "
                          f"{Colors.BOLD}{result['service']:15}{Colors.RESET}"
                          f"{Colors.DIM} {result['banner']}{Colors.RESET}")
            except Exception:
                pass

    if not open_ports:
        print(f"    {Colors.YELLOW}No open ports found{Colors.RESET}")

    # Sort by port number
    open_ports.sort(key=lambda x: x["port"])
    return open_ports


# ──────────────────────────────────────────────
# Hostname Resolution
# ──────────────────────────────────────────────

def resolve_hostname(ip: str) -> str:
    """
    Attempt to resolve an IP address to a hostname.

    Args:
        ip: IP address to resolve.

    Returns:
        Hostname string, or 'N/A' if resolution fails.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return "N/A"


# ──────────────────────────────────────────────
# Report Generation
# ──────────────────────────────────────────────

def generate_report(scan_results: dict, output_dir: str = "reports") -> dict:
    """
    Generate scan reports in JSON and CSV formats.

    Args:
        scan_results: Complete scan data dictionary.
        output_dir: Directory to save reports.

    Returns:
        Dictionary with paths to generated report files.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    paths = {}

    # ── JSON Report ──
    json_path = os.path.join(output_dir, f"scan_{timestamp}.json")
    with open(json_path, "w") as f:
        json.dump(scan_results, f, indent=2, default=str)
    paths["json"] = json_path

    # ── CSV Report ──
    csv_path = os.path.join(output_dir, f"scan_{timestamp}.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP Address", "Hostname", "Port", "State",
                         "Service", "Banner"])

        for host in scan_results.get("hosts", []):
            if host["open_ports"]:
                for port in host["open_ports"]:
                    writer.writerow([
                        host["ip"],
                        host["hostname"],
                        port["port"],
                        port["state"],
                        port["service"],
                        port["banner"],
                    ])
            else:
                writer.writerow([
                    host["ip"], host["hostname"],
                    "—", "—", "—", "—",
                ])
    paths["csv"] = csv_path

    # ── Text Summary ──
    txt_path = os.path.join(output_dir, f"scan_{timestamp}.txt")
    with open(txt_path, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("  NetScanner — Scan Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"  Target Network : {scan_results['target']}\n")
        f.write(f"  Scan Date      : {scan_results['scan_date']}\n")
        f.write(f"  Duration       : {scan_results['duration']}\n")
        f.write(f"  Hosts Found    : {scan_results['hosts_found']}\n")
        f.write(f"  Scan Method    : {scan_results['method']}\n\n")
        f.write("-" * 60 + "\n\n")

        for host in scan_results.get("hosts", []):
            f.write(f"  Host: {host['ip']}")
            if host["hostname"] != "N/A":
                f.write(f" ({host['hostname']})")
            f.write("\n")

            if host["open_ports"]:
                for port in host["open_ports"]:
                    f.write(f"    {port['port']:>5}/tcp  {port['service']:15}"
                            f"  {port['banner']}\n")
            else:
                f.write("    No open ports detected\n")
            f.write("\n")

        f.write("=" * 60 + "\n")
        f.write("  End of Report\n")
        f.write("=" * 60 + "\n")

    paths["txt"] = txt_path
    return paths


# ──────────────────────────────────────────────
# Display Functions
# ──────────────────────────────────────────────

def print_summary(scan_results: dict):
    """Print a formatted summary of scan results to the terminal."""

    print(f"\n{'═' * 58}")
    print(f"  {Colors.BOLD}SCAN SUMMARY{Colors.RESET}")
    print(f"{'═' * 58}")
    print(f"  Target     : {scan_results['target']}")
    print(f"  Date       : {scan_results['scan_date']}")
    print(f"  Duration   : {scan_results['duration']}")
    print(f"  Hosts Found: {Colors.GREEN}{Colors.BOLD}"
          f"{scan_results['hosts_found']}{Colors.RESET}")
    print(f"{'─' * 58}")

    total_open = 0
    for host in scan_results.get("hosts", []):
        num_ports = len(host["open_ports"])
        total_open += num_ports
        status = f"{Colors.GREEN}{num_ports} open" if num_ports > 0 \
            else f"{Colors.YELLOW}no open ports"
        hostname_str = f" ({host['hostname']})" \
            if host["hostname"] != "N/A" else ""

        print(f"  {Colors.BOLD}{host['ip']}{Colors.RESET}"
              f"{hostname_str} — {status}{Colors.RESET}")

    print(f"{'─' * 58}")
    print(f"  Total open ports: {Colors.BOLD}{total_open}{Colors.RESET}")
    print(f"{'═' * 58}\n")


# ──────────────────────────────────────────────
# CLI Argument Parser
# ──────────────────────────────────────────────

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        prog="netscanner",
        description="NetScanner — Network Discovery & Port Scanning Tool",
        epilog="Example: python netscanner.py -t 192.168.1.0/24 --scan-ports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target network in CIDR notation (e.g., 192.168.1.0/24) "
             "or single IP address",
    )
    parser.add_argument(
        "-m", "--method",
        choices=["ping", "tcp"],
        default="ping",
        help="Host discovery method: 'ping' (ICMP) or 'tcp' (TCP connect). "
             "Default: ping",
    )
    parser.add_argument(
        "-p", "--scan-ports",
        action="store_true",
        help="Scan common ports on discovered hosts",
    )
    parser.add_argument(
        "--extended",
        action="store_true",
        help="Use extended port list (50+ ports) instead of common ports",
    )
    parser.add_argument(
        "--ports",
        type=str,
        default=None,
        help="Custom port range to scan (e.g., '80,443,8080' or '1-1024')",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Timeout per host/port in seconds. Default: 1.0",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Number of concurrent threads. Default: 50",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="reports",
        help="Output directory for reports. Default: reports/",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Minimal output — only show results",
    )

    return parser.parse_args()


def parse_custom_ports(port_str: str) -> dict:
    """
    Parse a custom port string into a port dictionary.

    Supports formats:
        '80,443,8080'   → individual ports
        '1-1024'        → port range
        '22,80,100-200' → mixed

    Args:
        port_str: Comma-separated ports or ranges.

    Returns:
        Dictionary of {port: service_name}.
    """
    ports = {}
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            for p in range(int(start), int(end) + 1):
                service = EXTENDED_PORTS.get(p, "Unknown")
                ports[p] = service
        else:
            p = int(part)
            service = EXTENDED_PORTS.get(p, "Unknown")
            ports[p] = service
    return ports


# ──────────────────────────────────────────────
# Main Entry Point
# ──────────────────────────────────────────────

def main():
    """Main function — orchestrates the scan workflow."""

    args = parse_arguments()

    # Disable colors if requested or if output is piped
    if args.no_color or not sys.stdout.isatty():
        Colors.disable()

    if not args.quiet:
        print(BANNER)

    # ── Validate target ──
    target = args.target
    if "/" not in target:
        # Single IP — treat as /32
        target = f"{target}/32"

    # ── Start scan timer ──
    scan_start = time.time()

    # ── Phase 1: Host Discovery ──
    active_hosts = discover_hosts(
        network=target,
        timeout=int(args.timeout),
        threads=args.threads,
        method=args.method,
    )

    if not active_hosts:
        print(f"\n{Colors.YELLOW}[!] No active hosts found on "
              f"{target}{Colors.RESET}")
        print(f"{Colors.DIM}    Try using --method tcp if ICMP is "
              f"blocked{Colors.RESET}\n")
        return

    print(f"\n{Colors.GREEN}[✓] Found {len(active_hosts)} active host(s):"
          f"{Colors.RESET}")
    for ip in active_hosts:
        hostname = resolve_hostname(ip)
        hn_display = f" ({hostname})" if hostname != "N/A" else ""
        print(f"    {Colors.BOLD}{ip}{Colors.RESET}{hn_display}")

    # ── Phase 2: Port Scanning ──
    hosts_data = []

    if args.scan_ports:
        # Determine which ports to scan
        if args.ports:
            port_dict = parse_custom_ports(args.ports)
        elif args.extended:
            port_dict = EXTENDED_PORTS
        else:
            port_dict = COMMON_PORTS

        print(f"\n{Colors.BLUE}[*] Starting port scan on "
              f"{len(active_hosts)} host(s)...{Colors.RESET}")

        for ip in active_hosts:
            hostname = resolve_hostname(ip)
            open_ports = scan_host_ports(
                ip=ip,
                ports=port_dict,
                timeout=args.timeout,
                threads=args.threads,
            )
            hosts_data.append({
                "ip": ip,
                "hostname": hostname,
                "open_ports": open_ports,
            })
    else:
        # No port scan — just record discovered hosts
        for ip in active_hosts:
            hostname = resolve_hostname(ip)
            hosts_data.append({
                "ip": ip,
                "hostname": hostname,
                "open_ports": [],
            })

    # ── Calculate duration ──
    scan_duration = time.time() - scan_start
    duration_str = f"{scan_duration:.1f}s"

    # ── Build results ──
    scan_results = {
        "target": target,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duration": duration_str,
        "method": args.method,
        "hosts_found": len(active_hosts),
        "hosts": hosts_data,
    }

    # ── Print summary ──
    print_summary(scan_results)

    # ── Generate reports ──
    report_paths = generate_report(scan_results, args.output)
    print(f"{Colors.GREEN}[✓] Reports saved:{Colors.RESET}")
    for fmt, path in report_paths.items():
        print(f"    {Colors.DIM}{fmt.upper():4} → {path}{Colors.RESET}")
    print()


if __name__ == "__main__":
    main()
