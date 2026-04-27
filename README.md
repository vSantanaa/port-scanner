# PortScan 🔍

> Multithreaded port scanner with service detection, banner grabbing, and report generation (JSON/HTML).

Built as part of a cybersecurity portfolio. Educational purposes only — always obtain explicit authorization before scanning any target.

---

## Features

- **Multithreaded scanning** — configurable thread count for fast sweeps
- **Banner grabbing** — active service fingerprinting on open ports
- **Service detection** — maps ports to known services (SSH, HTTP, RDP, etc.)
- **Flexible port ranges** — single ports, ranges, comma-separated, or `top100`
- **JSON report** — structured output for integration with other tools
- **HTML report** — visual terminal-themed report for documentation
- **Progress bar** — real-time scan progress in the terminal

---

## Usage

```bash
# Basic scan (ports 1–1024)
python3 scanner.py scanme.nmap.org

# Custom port range with banner grabbing
python3 scanner.py 192.168.1.1 -p 1-10000 --banners

# Top 100 common ports, HTML output
python3 scanner.py 10.0.0.1 -p top100 --banners --html -o report

# Specific ports, fast scan with 200 threads
python3 scanner.py 10.0.0.1 -p 22,80,443,3306,8080 -t 200

# Full options
python3 scanner.py <target> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p`, `--ports` | Port spec: `1-1024`, `22,80,443`, `top100` | `1-1024` |
| `-t`, `--threads` | Number of concurrent threads | `100` |
| `--timeout` | Connection timeout (seconds) | `1.0` |
| `--banners` | Enable banner grabbing | off |
| `-o`, `--output` | Output file base name | auto-generated |
| `--json` | Save JSON report | off |
| `--html` | Save HTML report | off |

---

## Example Output

```
  Target  : scanme.nmap.org (45.33.32.156)
  Ports   : 1024 ports
  Threads : 100
  Banners : yes
  Started : 2024-11-01T14:22:05Z

  ████████████████████████████████████████ 1024/1024

  ──────────────────────────────────────────────────
  SCAN COMPLETE — 3 open port(s) found
  ──────────────────────────────────────────────────

  PORT    STATE     SERVICE         BANNER
  ────────────────────────────────────────────────
  22      open      SSH             SSH-2.0-OpenSSH_6.6.1p1
  80      open      HTTP            HTTP/1.1 200 OK
  443     open      HTTPS
```

---

## Reports

### JSON
```json
{
  "host": "scanme.nmap.org",
  "ip": "45.33.32.156",
  "scan_started": "2024-11-01T14:22:05Z",
  "scan_finished": "2024-11-01T14:22:18Z",
  "total_ports_scanned": 1024,
  "open_ports_count": 3,
  "open_ports": [
    { "port": 22, "state": "open", "service": "SSH", "banner": "SSH-2.0-OpenSSH_6.6.1p1" },
    { "port": 80, "state": "open", "service": "HTTP", "banner": "HTTP/1.1 200 OK" },
    { "port": 443, "state": "open", "service": "HTTPS", "banner": null }
  ]
}
```

### HTML
Terminal-themed visual report with scan stats and port table. Suitable for pentest documentation.

---

## Project Structure

```
port-scanner/
├── scanner.py       # Main scanner
└── README.md        # This file
```

---

## Technical Details

| Aspect | Implementation |
|--------|---------------|
| Concurrency | `ThreadPoolExecutor` with configurable workers |
| Socket | `AF_INET / SOCK_STREAM` (TCP) |
| Banner probes | Protocol-aware probes per port (HTTP HEAD, SMTP EHLO, etc.) |
| Encoding | UTF-8 with `errors='replace'` for binary banners |
| Output | JSON (machine-readable) + HTML (human-readable) |

---

## Concepts Demonstrated

- TCP connect scanning
- Multithreading with `concurrent.futures`
- Socket programming and banner grabbing
- Service fingerprinting
- Structured output / report generation

---

## Legal Disclaimer

This tool is for **authorized testing and educational purposes only**.  
Scanning systems without explicit permission is illegal and unethical.  
The author assumes no liability for misuse.

---

## Author

**[Your Name]**  
Cybersecurity Graduate Student  
[LinkedIn](https://linkedin.com/in/yourprofile) · [GitHub](https://github.com/yourusername)
