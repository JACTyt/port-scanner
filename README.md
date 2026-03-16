# Java Port Scanner

A fast, multithreaded TCP/UDP port scanner written in Java 21. Built for network reconnaissance, security auditing, and infrastructure mapping. Features service detection, banner grabbing, TLS inspection, CVE lookup, subnet scanning, report export in multiple formats, and a plugin system.

> **Ethical notice:** Only scan systems you own or have explicit written authorization to scan. Port scanning without authorization may violate computer misuse laws in your jurisdiction. The tool enforces a mandatory confirmation prompt before scanning any non-localhost host.

---

## Features

| Category | Feature |
|----------|---------|
| **Scanning** | TCP connect scan, UDP scan, CIDR/subnet scan, auto-discover local subnets |
| **Performance** | Java 21 virtual threads, up to 1000 concurrent connections, nmap-style timing profiles (T0–T5) |
| **Detection** | Service identification (220+ ports), banner grabbing, protocol-specific probes (HTTP, SSH, FTP, SMTP, MySQL, PostgreSQL, Redis, Memcached) |
| **Enrichment** | TLS/SSL certificate inspection, HTTP header analysis, CVE lookup (NVD API), IP geolocation, AbuseIPDB reputation, GreyNoise threat intel, ASN lookup |
| **Network** | IPv6 support, SOCKS5 proxy routing, traceroute, DNS subdomain brute-force, host discovery (ping sweep) |
| **Output** | JSON, CSV, TXT, HTML, XML, Nmap-XML, diff mode (compare two scans), ANSI color terminal output |
| **Usability** | Full-screen TUI, YAML config file, top-ports list (nmap frequency order), plugin/script system |

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
```

The output JAR is at `target/port-scanner-1.0-shaded.jar`.

### Windows (no Maven on PATH)

Use `run.bat` from the project root — it automatically builds the project and runs the scanner:

```powershell
.\run.bat                                        # scan localhost 1-1024 (default)
.\run.bat --host 192.168.1.1 --ports 1-65535
```

The batch file uses IntelliJ's bundled Maven. If Maven is on your PATH, use `mvn package -DskipTests` directly.

---

## Docker

The scanner is available as a Docker image — no Java installation required on the host.

### Build the image locally

```bash
docker build -t port-scanner .
```

### Run

```bash
# Scan localhost inside the container
docker run -it --rm --network=host port-scanner --host localhost --ports 1-1024

# Save the report to a local reports/ directory
docker run -it --rm --network=host \
  -v ./reports:/reports \
  port-scanner --host localhost --ports 1-1024 -o /reports/scan.html
```

Or use the convenience wrappers (they create a `reports/` directory automatically):

```bash
# Linux / macOS
chmod +x docker-run.sh
./docker-run.sh --host localhost --ports 1-1024

# Windows PowerShell
.\docker-run.ps1 --host localhost --ports 1-1024
```

### Pull a release image from GHCR

```bash
docker pull ghcr.io/<owner>/port-scanner:latest
docker run -it --rm --network=host ghcr.io/<owner>/port-scanner:latest --host localhost
```

### Network and privilege caveats

| Concern | Details |
|---------|---------|
| **LAN access** | `--network=host` is Linux-only. On Windows/Mac, Docker runs inside a VM so the container sees the VM's network, not your host LAN. Run natively with `run.bat` to scan your local network on Windows. |
| **UDP scanning** | Requires `--cap-add=NET_RAW` (included in the wrapper scripts). |
| **Interactive prompt** | Always use `-it` — the ethical confirmation prompt reads from stdin. |
| **Output files** | Mount a volume with `-v ./reports:/reports` and write to `/reports/` or files are lost when the container exits. |

---

## Quick Start

```bash
# Scan localhost ports 1–1024
java -jar target/port-scanner-1.0-shaded.jar --host localhost

# Scan a specific host with banner grabbing
java -jar target/port-scanner-1.0-shaded.jar --host example.com --ports 1-1024 --banner

# Scan common ports (nmap top-100 by frequency)
java -jar target/port-scanner-1.0-shaded.jar --host 192.168.1.1 --top-ports 100

# Scan a subnet
java -jar target/port-scanner-1.0-shaded.jar --subnet 192.168.1.0/24 --ports 22,80,443

# Auto-discover and scan all local subnets
java -jar target/port-scanner-1.0-shaded.jar --auto-discover --ports 22,80,443,3389
```

---

## All CLI Options

### Target (required — pick one)

| Option | Description |
|--------|-------------|
| `-h`, `--host <host>` | Target hostname or IP address |
| `-s`, `--subnet <cidr>` | CIDR subnet to scan, e.g. `192.168.1.0/24` |
| `--auto-discover` | Scan all local network interfaces automatically |

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
| `--rate <pps>` | `0` | Max packets per second (0 = unlimited). Enables randomised port order when set. |
| `--skip-discovery` | false | Skip ICMP reachability check before scanning (useful when target blocks ping) |
| `--use-nio` | false | Use NIO non-blocking scanner (legacy; equivalent performance to default with virtual threads) |

### Service Detection

| Option | Description |
|--------|-------------|
| `--banner` | Grab the first line from each open port's input stream |
| `--probes` | Use protocol-specific probes for richer banners (requires `--banner`). Supports HTTP, SSH, FTP, SMTP, MySQL, PostgreSQL, Redis, Memcached. |
| `--tls` | Inspect TLS/SSL certificates on open ports (subject, issuer, expiry, SANs) |
| `--http` | Analyse HTTP response headers on web ports (server, status, security headers) |
| `--cve` | Look up CVEs for detected services via NVD API (requires `--banner`, adds latency) |

### Enrichment

| Option | Description |
|--------|-------------|
| `--geolocate` | Geolocate the target IP via IPinfo.io (free tier; token optional via `IPINFO_TOKEN`) |
| `--abuse-check` | Check IP reputation via AbuseIPDB (requires `ABUSEIPDB_KEY` env var or config) |
| `--greynoise` | Check IP via GreyNoise Community API (requires `GREYNOISE_KEY` env var or config) |

### Network

| Option | Description |
|--------|-------------|
| `--ipv6` | Prefer IPv6 when resolving hostnames that have both A and AAAA records |
| `--proxy <spec>` | Route TCP scans via SOCKS5 proxy, e.g. `socks5://127.0.0.1:1080`. Not supported for UDP. |
| `--traceroute` | Run a traceroute to the target after scanning |
| `--traceroute-max-hops <n>` | Max hops for traceroute (default: 30) |
| `--dns-brute-enable` | DNS subdomain brute-force using the bundled top-1000 wordlist |
| `--dns-brute <wordlist>` | DNS subdomain brute-force using a custom wordlist file |

### Output

| Option | Default | Description |
|--------|---------|-------------|
| `-o`, `--output <file>` | stdout | Output file. Format is auto-detected from extension: `.json`, `.csv`, `.txt`, `.html`, `.xml`, `.nmap` |
| `--format <fmt>` | — | Override output format: `json`, `csv`, `txt`, `html`, `xml`, `nmap-xml` |
| `--diff <file>` | — | Compare current scan against a previous JSON report; prints added/removed/changed ports |
| `--show-all` | false | Include closed and filtered ports in output (not recommended for large ranges) |
| `--no-color` | false | Disable ANSI colour output |
| `-v`, `--verbose` | false | Enable debug logging |

### Display

| Option | Description |
|--------|-------------|
| `--tui` | Enable full-screen interactive TUI with live progress, open-ports table, and log panel. Falls back to a progress bar if the terminal doesn't support it. ⚠️ See [Known Issues](BUGS.md). |

### Plugins / Scripts

| Option | Description |
|--------|-------------|
| `--scripts <names>` | Comma-separated plugin names to run after scanning, or `all`. Built-in plugins: `http-title`, `ssl-cert`, `ssh-version` |

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
java -jar target/port-scanner-1.0-shaded.jar --host 192.168.1.1 -T4
java -jar target/port-scanner-1.0-shaded.jar --host 10.0.0.1 --timing INSANE
```

---

## Output Formats

| Extension / Format | Description |
|--------------------|-------------|
| `.json` / `json` | Full structured report with all fields (Jackson) |
| `.csv` / `csv` | Flat spreadsheet — one row per port |
| `.txt` / `txt` | Human-readable table (same as terminal output) |
| `.html` / `html` | Self-contained HTML report with styled table |
| `.xml` / `xml` | Generic XML report |
| `.nmap` / `nmap-xml` | Nmap-compatible XML — importable into tools that consume nmap output |

```bash
# Save as HTML
java -jar target/port-scanner-1.0-shaded.jar --host 192.168.1.1 -o report.html

# Save as JSON, then diff against it later
java -jar target/port-scanner-1.0-shaded.jar --host 192.168.1.1 -o scan1.json
java -jar target/port-scanner-1.0-shaded.jar --host 192.168.1.1 -o scan2.json --diff scan1.json
```

---

## Configuration File

Persistent defaults can be set in `~/.portscanner/config.yaml`:

```yaml
timeout: 500
threads: 150
ports: "1-1024"
outputDir: "/home/user/scans"
banner: true
showAll: false
abuseIpDbKey: "your_key_here"
greynoiseKey: "your_key_here"
ipinfoToken: "your_token_here"
```

CLI flags always override config file values.

---

## Environment Variables

API keys can also be set as environment variables (takes priority over config file):

| Variable | Feature |
|----------|---------|
| `ABUSEIPDB_KEY` | `--abuse-check` |
| `GREYNOISE_KEY` | `--greynoise` |
| `IPINFO_TOKEN` | `--geolocate` (optional — free tier works without it) |
| `NVD_API_KEY` | `--cve` (strongly recommended to avoid rate limiting) |

---

## Example Commands

```bash
# Full scan with all enrichment on a web server
java -jar port-scanner-1.0-shaded.jar \
  --host example.com --ports 1-10000 \
  --banner --probes --tls --http --geolocate \
  -T4 -o report.html

# Quick scan of the 100 most common ports
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 --top-ports 100 -T4

# Subnet scan for SSH and web ports
java -jar port-scanner-1.0-shaded.jar \
  --subnet 192.168.1.0/24 --ports 22,80,443,8080 --banner

# UDP scan for common services
java -jar port-scanner-1.0-shaded.jar \
  --host 192.168.1.1 --protocol udp --ports 53,67,68,123,161

# Scan through a SOCKS5 proxy with TLS inspection
java -jar port-scanner-1.0-shaded.jar \
  --host 10.0.0.1 --ports 443,8443 \
  --tls --proxy socks5://127.0.0.1:1080

# DNS subdomain brute-force
java -jar port-scanner-1.0-shaded.jar \
  --host example.com --ports 80,443 --dns-brute-enable

# Run with plugins
java -jar port-scanner-1.0-shaded.jar \
  --host 192.168.1.1 --ports 80,443,22 --scripts http-title,ssl-cert,ssh-version

# Slow evasive scan (IDS-aware)
java -jar port-scanner-1.0-shaded.jar \
  --host 10.0.0.1 --ports 22,80,443 -T1

# Diff two scans to detect changes
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 -o before.json
java -jar port-scanner-1.0-shaded.jar --host 192.168.1.1 -o after.json --diff before.json
```

---

## Architecture

```
com.portscanner/
├── Main.java                        Entry point
├── cli/
│   ├── ScanCommand.java             Picocli @Command — all CLI logic
│   ├── ProgressReporter.java        JLine3 progress bar
│   └── TuiProgressDisplay.java      Lanterna full-screen TUI
├── scanner/
│   ├── PortScanner.java             TCP connect scan (virtual threads)
│   ├── NioPortScanner.java          NIO non-blocking scanner
│   ├── UdpScanner.java              UDP scanner
│   ├── CidrScanner.java             Subnet/CIDR scanner
│   ├── BannerGrabber.java           Raw banner reading
│   ├── HostDiscovery.java           Ping sweep / reachability
│   ├── TlsInspector.java            TLS certificate parser
│   ├── HttpInspector.java           HTTP header analyser
│   ├── Traceroute.java              tracert/traceroute wrapper
│   ├── DnsBruteForcer.java          Subdomain enumeration
│   ├── TopPorts.java                nmap-frequency top-1000 port list
│   ├── RateLimiter.java             Token-bucket rate limiting
│   └── probe/                       Protocol-specific banner probes
│       ├── HttpProbe, SshProbe, FtpProbe, SmtpProbe
│       └── MysqlProbe, PostgresProbe, RedisProbe, MemcachedProbe
├── model/
│   ├── ScanResult.java              Per-port result (status, banner, TLS, CVEs…)
│   ├── ScanReport.java              Full scan report
│   ├── SubnetReport.java            Aggregated subnet scan
│   └── (GeoLocation, TlsInfo, HttpInfo, ThreatInfo, AsnInfo, …)
├── service/
│   ├── ServiceMapper.java           Port→service name (220+ entries)
│   ├── CveLookup.java               NVD API client
│   ├── AbuseIpDbClient.java         AbuseIPDB client
│   ├── GreyNoiseClient.java         GreyNoise client
│   ├── IpInfoClient.java            IPinfo geolocation
│   └── AsnLookup.java               ASN lookup
├── report/
│   ├── JsonExporter, CsvExporter, TextExporter
│   ├── HtmlExporter, XmlExporter, NmapXmlExporter
│   └── ReportDiffer.java            Scan diff engine
├── config/
│   ├── ScannerConfig.java           Config model (~/.portscanner/config.yaml)
│   ├── ConfigLoader.java            YAML loader
│   └── TimingProfile.java           T0–T5 enum
└── plugin/
    ├── ScanPlugin.java              Plugin interface
    ├── PluginRegistry.java          Plugin loader
    └── builtin/
        ├── HttpTitlePlugin          Fetches HTML <title> from web ports
        ├── SslCertPlugin            Detailed certificate info
        └── SshVersionPlugin         SSH version string extraction
```

---

## Known Issues

See [BUGS.md](BUGS.md) for the full list. Key issues:

- **`--tui`** does not work on Windows (Lanterna terminal initialisation failure)
- **UDP scanning** requires elevated privileges for accurate results on Windows
- **`--traceroute`** may return no results if Windows Firewall blocks ICMP
- **`--cve`** / `--abuse-check` / `--greynoise`** require API keys for reliable results

---

## Tech Stack

| Library | Version | Purpose |
|---------|---------|---------|
| Java | 21 | Virtual threads, records |
| Picocli | 4.7.6 | CLI argument parsing |
| Lombok | 1.18.x | `@Data`, `@Builder` boilerplate reduction |
| Jackson | 2.17+ | JSON serialization |
| Lanterna | 3.1.2 | Full-screen TUI |
| SLF4J + Logback | — | Logging |
| JUnit 5 | 5.10+ | Unit testing |
| Mockito | 5.x | Mocking |
