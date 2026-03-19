# Java Port Scanner

A fast, multithreaded TCP/UDP port scanner written in Java 21. Built for network reconnaissance, security auditing, and infrastructure mapping. Features service detection, banner grabbing, TLS inspection, CVE lookup, SNMP probing, OS fingerprinting, REST API mode, interactive REPL, and export in 10+ formats including Metasploit-compatible output.

> **Ethical notice:** Only scan systems you own or have explicit written authorization to scan. Port scanning without authorization may violate computer misuse laws in your jurisdiction. The tool enforces a mandatory confirmation prompt before scanning any non-localhost host.

---

## Features

| Category | Feature |
|----------|---------|
| **Scanning** | TCP connect scan, UDP scan, SNMP probe (SNMPv2c), CIDR/subnet scan, multi-host file scan, auto-discover local subnets |
| **Performance** | Java 21 virtual threads, up to 1000 concurrent connections, nmap-style timing profiles (T0–T5) |
| **Detection** | Service identification (220+ ports), banner grabbing, protocol-specific probes (HTTP, SSH, FTP, SMTP, MySQL, PostgreSQL, Redis, Memcached), service version extraction, OS/TTL fingerprinting |
| **Enrichment** | TLS/SSL certificate inspection, HTTP header analysis, CVE lookup with CVSS v3/v2 scores (NVD API + local SQLite cache), unauthenticated service detection (Redis, FTP, Elasticsearch, Memcached, Prometheus, Actuator), IP geolocation, AbuseIPDB reputation, GreyNoise threat intel, ASN lookup |
| **Network** | IPv6 support, SOCKS5 proxy routing, traceroute, DNS subdomain brute-force, DNS security audit (AXFR, open resolver, DNSSEC), host discovery (ping sweep) |
| **Output** | JSON, CSV, TXT, HTML, XML, Nmap-XML, Markdown, PDF, Metasploit `.rc` resource scripts, Graphviz/Mermaid topology diagrams, scan diff mode |
| **Automation** | REST API server, watch/scheduled mode, webhook notifications (Slack/Discord/custom), scan history database |
| **Usability** | Interactive REPL shell, full-screen TUI, YAML config file, scan profiles, top-ports list (nmap frequency order), external plugin system |

---

## Requirements

- **Java 21+** (JDK, not JRE)
- **Maven 3.9+** (or use the bundled `run.bat` on Windows)

---

## Building

```bash
# Compile and package a fat JAR
mvn package -DskipTests

# Run all tests
mvn test

# GraalVM native image (requires GraalVM JDK 21+)
mvn -Pnative package
```

The output JAR is at `target/port-scanner-1.0-shaded.jar`.

### Windows (no Maven on PATH)

Use `run.bat` from the project root — it automatically builds the project and runs the scanner:

```powershell
.\run.bat                                        # scan localhost 1-1024 (default)
.\run.bat --host 192.168.1.1 --ports 1-65535
```

---

## Native Installers

Use `jpackage` (bundled in JDK 21+) to create a platform installer that bundles the JRE:

```bash
# Linux — .deb (default) or .rpm
./scripts/jpackage-linux.sh deb
sudo dpkg -i target/port-scanner_1.0_amd64.deb

# Windows — MSI installer (run in CMD, not PowerShell)
scripts\jpackage-win.bat
```

After installation the `port-scanner` command is on the system PATH.

---

## Docker

The scanner is available as a Docker image — no Java installation required on the host.

```bash
# Build locally
docker build -t port-scanner .

# Scan localhost inside the container
docker run -it --rm --network=host port-scanner --host localhost --ports 1-1024

# Save the report to a local directory
docker run -it --rm --network=host \
  -v ./reports:/reports \
  port-scanner --host localhost --ports 1-1024 -o /reports/scan.html
```

Convenience wrappers (`docker-run.sh` / `docker-run.ps1`) create a `reports/` directory and pass all flags through.

| Concern | Details |
|---------|---------|
| **LAN access** | `--network=host` is Linux-only. On Windows/Mac, Docker runs inside a VM so the container sees the VM's network. Use `run.bat` to scan your LAN on Windows. |
| **UDP / SNMP** | Requires `--cap-add=NET_RAW` (included in the wrapper scripts). |
| **Interactive prompt** | Always use `-it` — the ethical confirmation prompt reads from stdin. |
| **Output files** | Mount a volume with `-v ./reports:/reports` and write to `/reports/`. |

---

## Quick Start

```bash
JAR=target/port-scanner-1.0-shaded.jar

# Scan localhost ports 1–1024
java -jar $JAR --host localhost

# Banner grabbing + TLS inspection
java -jar $JAR --host example.com --ports 1-1024 --banner --tls

# Scan the 100 most common ports (nmap frequency order)
java -jar $JAR --host 192.168.1.1 --top-ports 100 -T4

# Scan a subnet
java -jar $JAR --subnet 192.168.1.0/24 --ports 22,80,443

# Auto-discover and scan all local subnets
java -jar $JAR --auto-discover --ports 22,80,443,3389

# OS fingerprinting + SNMP probe
java -jar $JAR --host 192.168.1.1 --os --snmp --banner

# Watch mode — re-scan every 5 minutes, show only changes
java -jar $JAR --host 192.168.1.1 --watch --watch-interval 5

# Interactive REPL shell
java -jar $JAR shell
```

---

## All CLI Options

### Target (required — pick one)

| Option | Description |
|--------|-------------|
| `-h`, `--host <host>` | Target hostname or IP address |
| `-s`, `--subnet <cidr>` | CIDR subnet to scan, e.g. `192.168.1.0/24` |
| `--auto-discover` | Scan all local network interfaces automatically |
| `--hosts-file <file>` | Scan multiple hosts from a newline-separated file |

### Port Selection

| Option | Default | Description |
|--------|---------|-------------|
| `-p`, `--ports <range>` | `1-1024` | Port range (`1-1024`) or list (`80,443,8080`) |
| `--top-ports <N>` | — | Scan the N most commonly open ports in nmap frequency order (max 1000). Overrides `--ports`. |

### Scan Behaviour

| Option | Default | Description |
|--------|---------|-------------|
| `--protocol <proto>` | `tcp` | Protocol: `tcp`, `udp`, or `both` |
| `--timeout`, `-t <ms>` | `200` | Connection timeout in milliseconds (50–5000). Overridden by timing profiles. |
| `--threads <n>` | `100` | Max concurrent connections (max 1000, uses virtual threads) |
| `-T`, `--timing <profile>` | `NORMAL` | Timing profile — see [Timing Profiles](#timing-profiles) |
| `--profile <name>` | — | Apply a named scan profile from `~/.portscanner/profiles/` |
| `--rate <pps>` | `0` | Max packets per second (0 = unlimited). Enables randomised port order when set. |
| `--host-parallelism <n>` | `4` | Max concurrent host scans when using `--hosts-file` |
| `--skip-discovery` | false | Skip ICMP reachability check before scanning |
| `--use-nio` | false | Use NIO non-blocking scanner (legacy) |
| `--quick` | false | Phase-1 fast sweep: 1000 threads, 100 ms timeout, no enrichment. Combine with `--deep` for a two-phase pipeline. |
| `--deep` | false | Phase-2 deep enrichment on open ports (banner, TLS, CVE, unauth-detect, etc.). Runs standalone or automatically after `--quick`. |

### Service Detection

| Option | Description |
|--------|-------------|
| `--banner` | Grab the first line from each open port's input stream |
| `--probes` | Use protocol-specific probes for richer banners (requires `--banner`). Supports HTTP, SSH, FTP, SMTP, MySQL, PostgreSQL, Redis, Memcached. |
| `--tls` | Inspect TLS/SSL certificates on open ports (subject, issuer, expiry, SANs) |
| `--http` | Analyse HTTP response headers on web ports (server, status, security headers) |
| `--cve` | Look up CVEs for detected services via NVD API (requires `--banner`, adds latency) |
| `--os` | OS fingerprinting via TTL, SSH banner, HTTP `Server` header, and open port signals (RDP/SMB/WinRM) |
| `--snmp` | Probe UDP port 161 for SNMP after the TCP scan (retrieves sysDescr, sysName, sysLocation, sysContact, ifNumber) |
| `--snmp-community <list>` | `public,private` | Comma-separated SNMPv2c community strings to try in order |
| `--unauth-detect` | Probe open ports for unauthenticated service access (Redis, Memcached, Elasticsearch, FTP anonymous, Prometheus, Spring Actuator) |

### Enrichment

| Option | Description |
|--------|-------------|
| `--geolocate` | Geolocate the target IP via IPinfo.io (`IPINFO_TOKEN` optional) |
| `--abuse-check` | Check IP reputation via AbuseIPDB (requires `ABUSEIPDB_KEY`) |
| `--greynoise` | Check IP via GreyNoise Community API (requires `GREYNOISE_KEY`) |
| `--fail-on-cvss <score>` | Exit with code 2 if any CVE with CVSS score ≥ threshold is found. Requires `--cve`. Example: `--fail-on-cvss 7.0` |

### Network

| Option | Description |
|--------|-------------|
| `--ipv6` | Prefer IPv6 when resolving hostnames |
| `--proxy <spec>` | Route TCP scans via SOCKS5 proxy, e.g. `socks5://127.0.0.1:1080` |
| `--traceroute` | Run a traceroute to the target after scanning |
| `--traceroute-max-hops <n>` | Max hops for traceroute (default: 30) |
| `--dns-brute-enable` | DNS subdomain brute-force using the bundled top-1000 wordlist |
| `--dns-brute <wordlist>` | DNS subdomain brute-force using a custom wordlist file |
| `--dns-audit` | Run DNS security audit: AXFR zone transfer attempt, open resolver check, DNSSEC validation, TCP-53 fallback |
| `--dns-domain <domain>` | Domain for zone-transfer and DNSSEC checks during `--dns-audit`. If omitted, only open-resolver and TCP-53 tests run. |

### Output

| Option | Default | Description |
|--------|---------|-------------|
| `-o`, `--output <file>` | stdout | Output file. Format is auto-detected from extension (see [Output Formats](#output-formats)) |
| `--format <fmt>` | — | Override output format explicitly |
| `--diff <file>` | — | Compare current scan against a previous JSON report; prints added/removed/changed ports |
| `--show-all` | false | Include closed and filtered ports in output |
| `--no-color` | false | Disable ANSI colour output |
| `-v`, `--verbose` | false | Enable debug logging |
| `--topology-output <file>` | — | Write a network topology diagram. Use `.dot` for Graphviz or `.mmd` for Mermaid. |

### History

| Option | Description |
|--------|-------------|
| `--save-history` | Persist the scan result to `~/.portscanner/history.db` (SQLite) |
| `--history-diff` | Print port changes vs the most recent saved scan for this host (requires a prior `--save-history` run) |

### Watch / Scheduled Mode

| Option | Default | Description |
|--------|---------|-------------|
| `--watch` | false | Re-scan repeatedly, printing only diffs. Runs until Ctrl+C. |
| `--watch-interval <min>` | `60` | Minutes between scans in watch mode |
| `--watch-alert` | false | Print an alert line whenever a port opens or closes |

### REST API Mode

| Option | Default | Description |
|--------|---------|-------------|
| `--serve` | false | Start an embedded REST API server instead of running a one-off scan |
| `--serve-port <port>` | `8080` | Port for the REST API server |
| `--serve-auth <key>` | — | Require `X-API-Key: <key>` header on all API requests |

### Webhooks

| Option | Description |
|--------|-------------|
| `--webhook <url>` | POST scan summary JSON to this URL on completion. Slack/Discord webhook URLs are auto-detected and formatted as Block Kit payloads. |
| `--webhook-on-open-only` | Only fire the webhook if at least one open port was found |

### Display

| Option | Description |
|--------|-------------|
| `--tui` | Enable full-screen interactive TUI with live progress, open-ports table, and log panel. Falls back to a progress bar if the terminal doesn't support it. ⚠️ See [Known Issues](#known-issues). |

### Plugins / Scripts

| Option | Description |
|--------|-------------|
| `--scripts <names>` | Comma-separated plugin names to run after scanning, or `all`. Built-in: `http-title`, `ssl-cert`, `ssh-version`. External plugins are loaded from `~/.portscanner/plugins/*.jar`. |

---

## Timing Profiles

Inspired by nmap's `-T` flag. Controls thread count, timeout, and inter-probe delay.

| Profile | Alias | Threads | Timeout | Delay | Use case |
|---------|-------|---------|---------|-------|----------|
| `PARANOID` | `T0` | 1 | 5 min | 5 min | IDS evasion, ultra-slow |
| `SNEAKY` | `T1` | 1 | 15 s | 15 s | IDS evasion |
| `POLITE` | `T2` | 1 | 10 s | 400 ms | Low bandwidth impact |
| `NORMAL` | `T3` | 100 | 1 s | none | **Default** |
| `AGGRESSIVE` | `T4` | 200 | 1.25 s | none | Fast, reliable networks |
| `INSANE` | `T5` | 500 | 300 ms | none | LAN / localhost only |

```bash
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 -T4
java -jar port-scanner-1.0-shaded.jar --host 10.0.0.1 --timing INSANE
```

---

## Output Formats

Format is selected by file extension, or overridden with `--format`.

| Extension | Format flag | Description |
|-----------|-------------|-------------|
| `.json` | `json` | Full structured report with all fields (Jackson) |
| `.csv` | `csv` | Flat spreadsheet — one row per port |
| `.txt` | `txt` / `text` | Human-readable table (same as terminal output) |
| `.html` / `.htm` | `html` | Self-contained HTML report with styled table |
| `.xml` | `xml` | Generic XML report |
| `.nmap` | `nmap-xml` / `nmap` | Nmap-compatible XML — importable into Metasploit (`db_import`), Faraday, and other tools that consume nmap output |
| `.md` | `markdown` | GitHub Flavoured Markdown with GFM tables |
| `.pdf` | `pdf` | A4 PDF report (OpenPDF) |
| `.rc` | `msf` / `metasploit` | Metasploit Framework resource script — see [Metasploit Integration](#metasploit-integration) |
| `.dot` | — | Graphviz DOT network topology diagram (`--topology-output`) |
| `.mmd` / `.mermaid` | — | Mermaid network topology diagram (`--topology-output`) |

```bash
# Save as HTML
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 -o report.html

# Save as PDF
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 -o report.pdf

# Save as Markdown
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 -o report.md

# Diff two scans
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 -o scan1.json
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 -o scan2.json --diff scan1.json
```

---

## REST API Mode

Start an embedded HTTP server to accept scan requests programmatically:

```bash
java -jar port-scanner-1.0-shaded.jar --serve --serve-port 8080 --serve-auth mysecretkey
```

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scan` | Submit a scan job (JSON body: `host`, `ports`, `timeout`, `threads`, `banner`) |
| `GET` | `/scan/{id}` | Poll job status (`PENDING` → `RUNNING` → `DONE` / `FAILED`) |
| `GET` | `/scan/{id}/stream` | Server-Sent Events stream of live scan progress |
| `GET` | `/scans` | List recent jobs (last 50) |
| `DELETE` | `/scan/{id}` | Cancel a running job |

```bash
# Submit a scan
curl -X POST http://localhost:8080/scan \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: mysecretkey' \
  -d '{"host":"192.168.1.1","ports":"1-1024","banner":true}'

# Poll for results
curl http://localhost:8080/scan/<id> -H 'X-API-Key: mysecretkey'
```

---

## Watch Mode

Re-scan a target on a schedule and print only what changed:

```bash
# Scan every 10 minutes, alert on open/close events
java -jar port-scanner-1.0-shaded.jar \
  --host 192.168.1.1 --ports 1-1024 \
  --watch --watch-interval 10 --watch-alert
```

The first scan prints a full summary. Subsequent scans print only opened and closed ports. Press `Ctrl+C` to stop.

---

## Scan History

Persist results to a local SQLite database at `~/.portscanner/history.db`:

```bash
# Save the scan
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 --save-history

# Show changes vs the last saved scan
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 --history-diff

# View history via the history subcommand
java -jar port-scanner-1.0-shaded.jar history --host 192.168.1.1 --last 5
java -jar port-scanner-1.0-shaded.jar history --host 192.168.1.1 --diff
```

---

## Scan Profiles

Named scan templates stored as YAML files in `~/.portscanner/profiles/`:

```yaml
# ~/.portscanner/profiles/web.yaml
ports: "80,443,8080,8443"
banner: true
tls: true
http: true
timing: AGGRESSIVE
```

```bash
java -jar port-scanner-1.0-shaded.jar --host example.com --profile web
```

---

## Webhooks

POST the scan summary to any URL when the scan completes:

```bash
# Generic JSON webhook
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 \
  --webhook https://your-server.example.com/hook

# Slack/Discord (Block Kit payload auto-formatted)
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 \
  --webhook https://hooks.slack.com/services/... \
  --webhook-on-open-only
```

Slack and Discord webhook URLs are auto-detected and sent as formatted Block Kit / Embed payloads. Any other URL receives the raw scan summary as JSON.

---

## OS Fingerprinting

```bash
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 --os
```

Detection layers (high → low confidence):
1. **SSH banner** — kernel version strings (e.g. `Ubuntu`, `Debian`)
2. **HTTP `Server` header** — IIS → Windows, nginx/Apache patterns → Linux
3. **Open port signals** — RDP (3389), SMB (445), WinRM (5985) → Windows
4. **TTL heuristic** via `ping` — TTL 64 → Linux/macOS, TTL 128 → Windows

The OS guess (`os`, `confidence`, `method`) is included in all export formats. When exporting as Nmap-XML the `<os><osmatch>` block is populated so Metasploit can import it.

---

## SNMP Scanning

```bash
# Probe with default communities (public, private)
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 --snmp

# Custom communities
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 \
  --snmp --snmp-community "public,internal,monitor"
```

The scanner queries MIB-II OIDs via SNMPv2c (UDP port 161):

| OID | Field |
|-----|-------|
| `1.3.6.1.2.1.1.1.0` | `sysDescr` |
| `1.3.6.1.2.1.1.5.0` | `sysName` |
| `1.3.6.1.2.1.1.6.0` | `sysLocation` |
| `1.3.6.1.2.1.1.4.0` | `sysContact` |
| `1.3.6.1.2.1.2.1.0` | `ifNumber` (interface count) |

SNMP results are included in all export formats and attached to the port-161 `ScanResult` entry.

---

## Metasploit Integration

### Nmap-XML import

```bash
# Export in Nmap-compatible XML
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 -o scan.nmap

# Import into Metasploit
msfconsole -q -x "db_import scan.nmap; hosts; services; exit"
```

### Resource script (`.rc`)

```bash
# Generate a Metasploit resource script
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 -o scan.rc

# Run it
msfconsole -r scan.rc
```

The `.rc` script:
- Creates a `portscanner` workspace
- Registers the host and all open services via `hosts -a` / `services -a`
- Runs `auxiliary/scanner/portscan/tcp` to verify open ports
- Suggests scanner/exploit modules per service (SSH, HTTP, SMB, MySQL, PostgreSQL, RDP, Redis, MongoDB, FTP, SMTP, Telnet)

---

## Network Topology Visualization

```bash
# Generate a Graphviz DOT diagram
java -jar port-scanner-1.0-shaded.jar --subnet 192.168.1.0/24 \
  --ports 22,80,443 --topology-output topology.dot

# Convert to SVG with Graphviz
dot -Tsvg topology.dot -o topology.svg

# Generate a Mermaid diagram
java -jar port-scanner-1.0-shaded.jar --subnet 192.168.1.0/24 \
  --topology-output topology.mmd
```

Nodes are colour-coded by detected OS: green = Linux, red = Windows, orange = network gear.

---

## Interactive REPL Shell

Start an interactive session with readline-style editing, persistent history, and tab completion:

```bash
java -jar port-scanner-1.0-shaded.jar shell
```

```
portscanner> scan example.com --banner --tls
portscanner> scan 192.168.1.1 --ports 22,80,443 --os
portscanner> history --host 192.168.1.1 --diff
portscanner> diff before.json after.json
portscanner> set timeout 500
portscanner> set ports 1-65535
portscanner> profiles
portscanner> help
portscanner> exit
```

Session-level defaults (timeout, threads, port range) persist for the duration of the REPL session. History is saved to `~/.portscanner/repl_history`.

---

## Configuration File

Persistent defaults in `~/.portscanner/config.yaml`:

```yaml
timeout: 500
threads: 150
ports: "1-1024"
outputDir: "/home/user/scans"
banner: true
showAll: false
webhook: "https://hooks.slack.com/services/..."
webhookOnOpenOnly: true
abuseIpDbKey: "your_key_here"
greynoiseKey: "your_key_here"
ipinfoToken: "your_token_here"
```

CLI flags always override config file values.

---

## Environment Variables

| Variable | Feature |
|----------|---------|
| `ABUSEIPDB_KEY` | `--abuse-check` |
| `GREYNOISE_KEY` | `--greynoise` |
| `IPINFO_TOKEN` | `--geolocate` (optional — free tier works without it) |
| `NVD_API_KEY` | `--cve` (strongly recommended to avoid rate limiting) |

---

## Example Commands

```bash
JAR=port-scanner-1.0-shaded.jar

# Full scan with all enrichment
java -jar $JAR \
  --host example.com --ports 1-10000 \
  --banner --probes --tls --http --os --geolocate \
  -T4 -o report.html

# Quick scan of the 100 most common ports
java -jar $JAR --host 192.168.1.1 --top-ports 100 -T4

# Subnet scan for SSH and web ports
java -jar $JAR --subnet 192.168.1.0/24 --ports 22,80,443,8080 --banner

# UDP scan for common services
java -jar $JAR --host 192.168.1.1 --protocol udp --ports 53,67,68,123,161

# SNMP probe
java -jar $JAR --host 192.168.1.1 --snmp --snmp-community "public,internal"

# Scan through a SOCKS5 proxy with TLS inspection
java -jar $JAR --host 10.0.0.1 --ports 443,8443 --tls --proxy socks5://127.0.0.1:1080

# DNS subdomain brute-force
java -jar $JAR --host example.com --ports 80,443 --dns-brute-enable

# Run with plugins
java -jar $JAR --host 192.168.1.1 --ports 80,443,22 --scripts http-title,ssl-cert,ssh-version

# Slow evasive scan (IDS-aware)
java -jar $JAR --host 10.0.0.1 --ports 22,80,443 -T1

# Scan multiple hosts from a file
java -jar $JAR --hosts-file targets.txt --ports 22,80,443 --banner --save-history

# Watch mode — alert when ports change
java -jar $JAR --host 192.168.1.1 --watch --watch-interval 5 --watch-alert

# REST API server
java -jar $JAR --serve --serve-port 8080 --serve-auth mysecretkey

# Webhook notification on open ports only
java -jar $JAR --host 192.168.1.1 \
  --webhook https://hooks.slack.com/services/... \
  --webhook-on-open-only

# Metasploit resource script
java -jar $JAR --host 192.168.1.1 --os --banner -o scan.rc
msfconsole -r scan.rc

# Two-phase scan: fast sweep then deep enrichment only on open ports
java -jar $JAR --host 192.168.1.1 --ports 1-65535 --quick --deep

# DNS security audit
java -jar $JAR --host 192.168.1.1 --dns-audit --dns-domain example.com

# Unauthenticated service detection
java -jar $JAR --host 192.168.1.1 --banner --unauth-detect

# Fail CI if a critical CVE (CVSS >= 9.0) is found
java -jar $JAR --host 192.168.1.1 --banner --cve --fail-on-cvss 9.0

# Topology diagram
java -jar $JAR --subnet 192.168.1.0/24 --ports 22,80,443 \
  --topology-output network.dot && dot -Tsvg network.dot -o network.svg
```

---

## Architecture

```
com.portscanner/
├── Main.java                        Entry point
├── cli/
│   ├── ScanCommand.java             Picocli @Command — all CLI logic and subcommands
│   ├── HistoryCommand.java          history subcommand
│   ├── ReplCommand.java             shell subcommand (interactive REPL, JLine3)
│   ├── ProgressReporter.java        JLine3 progress bar
│   └── TuiProgressDisplay.java      Lanterna full-screen TUI
├── scanner/
│   ├── PortScanner.java             TCP connect scan (virtual threads)
│   ├── NioPortScanner.java          NIO non-blocking scanner
│   ├── UdpScanner.java              UDP scanner
│   ├── CidrScanner.java             Subnet/CIDR scanner
│   ├── MultiHostScanner.java        Parallel multi-host scanning
│   ├── BannerGrabber.java           Raw banner reading
│   ├── HostDiscovery.java           Ping sweep / reachability
│   ├── TlsInspector.java            TLS certificate parser
│   ├── HttpInspector.java           HTTP header analyser
│   ├── OsFingerprinter.java         OS detection (TTL + banner heuristics)
│   ├── SnmpScanner.java             SNMPv2c GET via snmp4j
│   ├── WatchMode.java               Scheduled re-scan with diff output
│   ├── Traceroute.java              tracert/traceroute wrapper
│   ├── DnsBruteForcer.java          Subdomain enumeration
│   ├── TopPorts.java                nmap-frequency top-1000 port list
│   ├── RateLimiter.java             Token-bucket rate limiting
│   ├── NetworkInterfaceScanner.java Local interface discovery
│   ├── IPv6CidrEnumerator.java      IPv6 CIDR host enumeration
│   ├── NdpCacheReader.java          NDP/ARP cache reader
│   ├── UnauthDetector.java          Unauthenticated service detection coordinator
│   ├── DnsAuditor.java              DNS security audit (AXFR, open resolver, DNSSEC)
│   └── probe/                       Protocol-specific banner probes
│       ├── HttpProbe, SshProbe, FtpProbe, SmtpProbe
│       ├── MysqlProbe, PostgresProbe, RedisProbe, MemcachedProbe
│       └── RedisUnauthProbe, FtpAnonProbe, ElasticsearchUnauthProbe,
│           MemcachedUnauthProbe, PromUnauthProbe, ActuatorUnauthProbe
├── model/
│   ├── ScanResult.java              Per-port result (status, banner, TLS, CVEs, SNMP…)
│   ├── ScanReport.java              Full scan report (includes OsGuess)
│   ├── SubnetReport.java            Aggregated subnet scan
│   ├── MultiHostReport.java         Aggregated multi-host scan
│   ├── OsGuess.java                 OS fingerprint result
│   ├── SnmpInfo.java                SNMP MIB-II data
│   ├── CveEntry.java                CVE with CVSS v3/v2 score, severity, vector, description
│   ├── UnauthResult.java            Unauthenticated access probe result
│   ├── DnsAuditResult.java          DNS security audit findings
│   └── (GeoLocation, TlsInfo, HttpInfo, ThreatInfo, AsnInfo, TracerouteHop, …)
├── service/
│   ├── ServiceMapper.java           Port→service name (220+ entries)
│   ├── VersionExtractor.java        Version string extraction from banners
│   ├── CveLookup.java               NVD API client
│   ├── LocalCveDatabase.java        SQLite-backed CVE cache
│   ├── AbuseIpDbClient.java         AbuseIPDB client
│   ├── GreyNoiseClient.java         GreyNoise client
│   ├── IpInfoClient.java            IPinfo geolocation
│   ├── AsnLookup.java               ASN lookup
│   └── WebhookClient.java           HTTP webhook delivery (Slack/Discord/custom)
├── report/
│   ├── JsonExporter, CsvExporter, TextExporter
│   ├── HtmlExporter, XmlExporter
│   ├── NmapXmlExporter              Nmap-compatible XML (Metasploit db_import)
│   ├── MarkdownExporter             GitHub Flavoured Markdown
│   ├── PdfExporter                  A4 PDF (OpenPDF)
│   ├── MetasploitRcExporter         Metasploit .rc resource scripts
│   ├── TopologyExporter             Graphviz DOT / Mermaid diagrams
│   ├── ReportDiffer.java            Scan diff engine
│   └── ExporterFactory.java         Extension/format → exporter dispatch
├── api/
│   ├── ScanApiServer.java           JDK HttpServer REST API
│   ├── ScanJobManager.java          Virtual-thread job executor
│   └── dto/ScanRequest, ScanResponse
├── config/
│   ├── ScannerConfig.java           Config model (~/.portscanner/config.yaml)
│   ├── ConfigLoader.java            YAML loader
│   ├── ScanProfile.java             Named profile model
│   ├── ProfileLoader.java           Profile file loader
│   └── TimingProfile.java           T0–T5 enum
├── db/
│   ├── ScanHistoryDao.java          SQLite history read/write
│   └── HistorySchema.java           Schema initialisation
└── plugin/
    ├── ScanPlugin.java              Plugin interface
    ├── PluginRegistry.java          Built-in + external JAR loader (URLClassLoader)
    ├── PluginContext.java            Context passed to plugins
    └── builtin/
        ├── HttpTitlePlugin          Fetches HTML <title> from web ports
        ├── SslCertPlugin            Detailed certificate info
        └── SshVersionPlugin         SSH version string extraction
```

---

## External Plugins

Drop a JAR implementing `com.portscanner.plugin.ScanPlugin` (via `ServiceLoader`) into `~/.portscanner/plugins/`. It is automatically discovered and available via `--scripts`:

```bash
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 --scripts my-custom-plugin
```

---

## Known Issues

See [BUGS.md](BUGS.md) for the full list. Key issues:

- **`--tui`** does not work on Windows (Lanterna terminal initialisation failure). Falls back to the JLine3 progress bar automatically.
- **UDP scanning** requires elevated privileges for accurate results on Windows
- **`--traceroute`** may return no results if Windows Firewall blocks ICMP
- **`--cve`** / **`--abuse-check`** / **`--greynoise`** require API keys for reliable results

---

## Tech Stack

| Library | Version | Purpose |
|---------|---------|---------|
| Java | 21 | Virtual threads, records |
| Picocli | 4.7.6 | CLI argument parsing + GraalVM native-image codegen |
| Lombok | 1.18.x | `@Data`, `@Builder` boilerplate reduction |
| Jackson | 2.17+ | JSON / XML / YAML serialisation |
| JLine3 | 3.26.3 | Progress bar, REPL readline editing |
| Lanterna | 3.1.2 | Full-screen TUI |
| OpenPDF | 1.3.30 | PDF report generation |
| SNMP4J | 3.7.7 | SNMPv2c scanning |
| snmp4j | 3.7.7 | SNMP scanning |
| dnsjava | 3.5.0 | DNS subdomain brute-force |
| IPAddress | 5.4.0 | IPv6 CIDR enumeration |
| SQLite JDBC | 3.45.3 | Scan history + CVE cache |
| SLF4J + Logback | 2.0 / 1.5 | Structured logging |
| JUnit 5 | 5.10+ | Unit testing |
| Mockito | 5.x | Mocking |
| Testcontainers | 1.19+ | Integration tests |
