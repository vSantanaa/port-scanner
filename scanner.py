#!/usr/bin/env python3
"""
PortScan - Advanced Port Scanner
Author: [Your Name]
Description: Multithreaded port scanner with banner grabbing, service detection,
             and report generation (JSON/HTML).
Usage: python3 scanner.py -h
"""

import socket
import threading
import argparse
import json
import sys
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# ─── Common service banners ──────────────────────────────────────────────────

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

BANNER_PROBES = {
    21:  b"",
    22:  b"",
    25:  b"EHLO scanner\r\n",
    80:  b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",
    3306: b"",
}


# ─── Core scanning functions ──────────────────────────────────────────────────

def grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """Attempt to grab the service banner from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            probe = BANNER_PROBES.get(port, b"\r\n")
            if probe:
                s.send(probe)
            banner = s.recv(1024).decode("utf-8", errors="replace").strip()
            return banner[:200] if banner else None
    except Exception:
        return None


def scan_port(host: str, port: int, timeout: float, grab: bool) -> dict:
    """Scan a single port. Returns a result dict."""
    result = {
        "port": port,
        "state": "closed",
        "service": COMMON_PORTS.get(port, "unknown"),
        "banner": None,
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            code = s.connect_ex((host, port))
            if code == 0:
                result["state"] = "open"
                if grab:
                    result["banner"] = grab_banner(host, port, timeout)
    except socket.error:
        pass
    return result


def resolve_host(target: str) -> str:
    """Resolve hostname to IP. Exits on failure."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"[!] Cannot resolve host: {target}")
        sys.exit(1)


# ─── Scan orchestration ───────────────────────────────────────────────────────

def run_scan(host: str, ports: list[int], threads: int,
             timeout: float, grab_banners: bool) -> dict:
    """Run the full scan using a thread pool."""
    ip = resolve_host(host)
    started_at = datetime.utcnow().isoformat() + "Z"
    open_ports = []
    total = len(ports)
    done = 0
    lock = threading.Lock()

    print(f"\n  Target  : {host} ({ip})")
    print(f"  Ports   : {total} ports")
    print(f"  Threads : {threads}")
    print(f"  Banners : {'yes' if grab_banners else 'no'}")
    print(f"  Started : {started_at}\n")
    print("  " + "─" * 50)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, ip, p, timeout, grab_banners): p
            for p in ports
        }
        for future in as_completed(futures):
            result = future.result()
            with lock:
                done += 1
                pct = int((done / total) * 40)
                bar = "█" * pct + "░" * (40 - pct)
                print(f"\r  [{bar}] {done}/{total}", end="", flush=True)
                if result["state"] == "open":
                    open_ports.append(result)

    print()  # newline after progress bar

    finished_at = datetime.utcnow().isoformat() + "Z"
    open_ports.sort(key=lambda x: x["port"])

    return {
        "host": host,
        "ip": ip,
        "scan_started": started_at,
        "scan_finished": finished_at,
        "total_ports_scanned": total,
        "open_ports_count": len(open_ports),
        "open_ports": open_ports,
    }


# ─── Output formatters ────────────────────────────────────────────────────────

def print_results(data: dict):
    print(f"\n  {'─'*50}")
    print(f"  SCAN COMPLETE — {data['open_ports_count']} open port(s) found")
    print(f"  {'─'*50}\n")
    if not data["open_ports"]:
        print("  No open ports found.\n")
        return
    print(f"  {'PORT':<8}{'STATE':<10}{'SERVICE':<16}BANNER")
    print(f"  {'─'*8}{'─'*10}{'─'*16}{'─'*30}")
    for p in data["open_ports"]:
        banner = (p["banner"] or "")[:50].replace("\n", " ")
        print(f"  {p['port']:<8}{p['state']:<10}{p['service']:<16}{banner}")
    print()


def save_json(data: dict, path: str):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  [+] JSON report saved → {path}")


def save_html(data: dict, path: str):
    rows = ""
    for p in data["open_ports"]:
        banner = (p["banner"] or "—").replace("<", "&lt;").replace(">", "&gt;")
        rows += f"""
        <tr>
          <td>{p['port']}</td>
          <td><span class="badge open">open</span></td>
          <td>{p['service']}</td>
          <td class="banner">{banner[:120]}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PortScan Report — {data['host']}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
    --green: #3fb950; --red: #f85149; --font: 'Courier New', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); padding: 2rem; }}
  h1 {{ font-size: 1.4rem; color: var(--accent); margin-bottom: 0.25rem; }}
  .meta {{ color: var(--muted); font-size: 0.8rem; margin-bottom: 2rem; }}
  .stats {{ display: flex; gap: 1.5rem; margin-bottom: 2rem; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border);
            border-radius: 6px; padding: 1rem 1.5rem; }}
  .stat-val {{ font-size: 1.8rem; font-weight: bold; color: var(--accent); }}
  .stat-label {{ color: var(--muted); font-size: 0.75rem; margin-top: 2px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ text-align: left; padding: 0.6rem 1rem; color: var(--muted);
        border-bottom: 1px solid var(--border); font-weight: normal; }}
  td {{ padding: 0.6rem 1rem; border-bottom: 1px solid var(--border); }}
  tr:hover td {{ background: var(--surface); }}
  .badge {{ padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; }}
  .open {{ background: rgba(63,185,80,0.15); color: var(--green);
           border: 1px solid rgba(63,185,80,0.4); }}
  .banner {{ color: var(--muted); font-size: 0.78rem; max-width: 400px;
             white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
</style>
</head>
<body>
  <h1>PortScan Report</h1>
  <p class="meta">Target: {data['host']} ({data['ip']}) &nbsp;|&nbsp;
     Started: {data['scan_started']} &nbsp;|&nbsp;
     Finished: {data['scan_finished']}</p>

  <div class="stats">
    <div class="stat">
      <div class="stat-val">{data['total_ports_scanned']}</div>
      <div class="stat-label">ports scanned</div>
    </div>
    <div class="stat">
      <div class="stat-val" style="color:#3fb950">{data['open_ports_count']}</div>
      <div class="stat-label">open ports</div>
    </div>
    <div class="stat">
      <div class="stat-val">{data['total_ports_scanned'] - data['open_ports_count']}</div>
      <div class="stat-label">closed/filtered</div>
    </div>
  </div>

  <table>
    <thead>
      <tr><th>Port</th><th>State</th><th>Service</th><th>Banner</th></tr>
    </thead>
    <tbody>{rows if rows else '<tr><td colspan="4" style="color:var(--muted);padding:2rem">No open ports found.</td></tr>'}
    </tbody>
  </table>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)
    print(f"  [+] HTML report saved → {path}")


# ─── Port range parser ────────────────────────────────────────────────────────

def parse_ports(port_str: str) -> list[int]:
    """Parse port specification: '80', '1-1024', '22,80,443', 'top100'."""
    TOP100 = [
        21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
        1723,3306,3389,5900,8080,8443,8888,27017,6379,5432,
        1433,1521,2049,111,587,465,25,143,993,995,110,119,
        161,162,389,636,500,4500,1194,1701,1702,5060,5061,
        69,67,68,123,137,138,139,445,514,520,631,1080,
        1194,1433,1521,2082,2083,2086,2087,2095,2096,
        3000,3128,4899,5000,5800,5900,6000,6001,6002,
        7001,7002,8000,8001,8008,8080,8443,8888,9000,
        9090,9200,9300,10000,10443,11211,27017,28017,
    ]
    if port_str == "top100":
        return sorted(set(TOP100))
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


# ─── CLI entry point ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="PortScan — Multithreaded port scanner with banner grabbing",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
examples:
  python3 scanner.py scanme.nmap.org
  python3 scanner.py 192.168.1.1 -p 1-1000 -t 200
  python3 scanner.py 10.0.0.1 -p top100 --banners -o report
  python3 scanner.py 10.0.0.1 -p 22,80,443,3306 --banners --html

disclaimer:
  For authorized testing only. Unauthorized scanning is illegal.
        """,
    )
    parser.add_argument("target", help="Hostname or IP address to scan")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Ports: '1-1024', '22,80,443', 'top100' (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("--banners", action="store_true",
                        help="Attempt banner grabbing on open ports")
    parser.add_argument("-o", "--output",
                        help="Output file base name (no extension)")
    parser.add_argument("--json", action="store_true",
                        help="Save JSON report")
    parser.add_argument("--html", action="store_true",
                        help="Save HTML report")

    args = parser.parse_args()

    print("""
  ██████╗  ██████╗ ██████╗ ████████╗███████╗ ██████╗ █████╗ ███╗  ██╗
  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗ ██║
  ██████╔╝██║   ██║██████╔╝   ██║   ███████╗██║     ███████║██╔██╗██║
  ██╔═══╝ ██║   ██║██╔══██╗   ██║   ╚════██║██║     ██╔══██║██║╚████║
  ██║     ╚██████╔╝██║  ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚███║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝
    """)

    ports = parse_ports(args.ports)
    data = run_scan(
        host=args.target,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout,
        grab_banners=args.banners,
    )

    print_results(data)

    base = args.output or f"scan_{args.target}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

    if args.json:
        save_json(data, f"{base}.json")
    if args.html:
        save_html(data, f"{base}.html")
    if not args.json and not args.output:
        # always save JSON by default when -o is given
        pass

    print()


if __name__ == "__main__":
    main()
