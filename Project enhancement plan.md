# Java Port Scanner — Enhancement Plan v4

> **Status:** All v1, v2, and v3 enhancements are fully implemented (see git log).
> This document is a fresh iteration. Everything listed here is **not yet implemented**.

---

## Already Implemented — Do Not Re-Implement

TCP/UDP scanning · Virtual threads (Java 21) · CIDR/subnet scanning · Auto-discover ·
Host discovery · Timing profiles T0–T5 · Top-ports list · Rate limiting · Banner grabbing ·
Protocol-specific probes (HTTP, SSH, FTP, SMTP, MySQL, PostgreSQL, Redis, Memcached) ·
TLS inspection · HTTP header analysis · CVE lookup (NVD API + local SQLite) · AbuseIPDB ·
GreyNoise · IPinfo geolocation · ASN lookup · Reverse DNS · SOCKS5 proxy · Traceroute ·
DNS subdomain brute-force · IPv6 scanning · Plugin system (http-title, ssl-cert, ssh-version) ·
JLine3 progress bar · Lanterna TUI · ANSI color output · SLF4J/Logback logging ·
YAML config file · Nmap-XML output · HTML/XML/CSV/JSON/TXT exporters · Diff mode ·
Testcontainers integration tests · GitHub Actions CI · GraalVM native profile in pom.xml

---

## Task Summary

| Task | Name | Priority | Effort |
|------|------|----------|--------|
| [BUG-04](#bug-04-tui-broken-on-windows) | Fix TUI on Windows | P0 | 4h |
| [TASK-01](#task-01-dockerfile--docker-distribution) | Dockerfile + Docker distribution | P1 | 4h |
| [TASK-02](#task-02-graalvm-native-image-completion) | GraalVM native image completion | P1 | 1 day |
| [TASK-03](#task-03-multi-host-file-scanning) | Multi-host file scanning `--hosts-file` | P1 | 1 day |
| [TASK-04](#task-04-scan-history-database) | Scan history database | P1 | 1 day |
| [TASK-05](#task-05-scan-profiles--templates) | Scan profiles / templates `--profile` | P1 | 4h |
| [TASK-06](#task-06-service-version-extraction) | Service version extraction from banners | P1 | 4h |
| [TASK-07](#task-07-github-actions-release-pipeline) | GitHub Actions release pipeline | P2 | 4h |
| [TASK-08](#task-08-rest-api-mode) | REST API mode `--serve` | P2 | 2 days |
| [TASK-09](#task-09-scheduled--watch-mode) | Scheduled / watch mode `--watch` | P2 | 1 day |
| [TASK-10](#task-10-os--ttl-fingerprinting) | OS / TTL fingerprinting | P2 | 1 day |
| [TASK-11](#task-11-webhooknotification-on-scan-complete) | Webhook / notification on scan complete | P2 | 4h |
| [TASK-12](#task-12-markdown--pdf-output) | Markdown + PDF output | P2 | 4h |
| [TASK-13](#task-13-network-topology-visualization) | Network topology visualization | P3 | 2 days |
| [TASK-14](#task-14-external-plugin-loading) | External plugin loading from directory | P3 | 1 day |
| [TASK-15](#task-15-snmp-scanning) | SNMP scanning `--protocol snmp` | P3 | 2 days |
| [TASK-16](#task-16-windows-native-installer) | Windows native installer (jpackage) | P3 | 4h |
| [TASK-17](#task-17-interactive-repl-mode) | Interactive REPL mode | P4 | 2 days |
| [TASK-18](#task-18-metasploit-compatible-output) | Metasploit-compatible output | P4 | 1 day |

---

## Bug Fixes

---

### BUG-04: TUI Broken on Windows

**Priority:** P0 | **Effort:** 4h

**Problem:** Lanterna fails to initialize in Windows CMD / PowerShell / Windows Terminal when
launched via `java.exe`. The `WindowsTerminal` backend (JNA) does not initialize correctly inside
a shaded JAR, and the Swing fallback is blocked (`setAutoOpenTerminalEmulatorWindow(false)`).
Attempted fixes — stream-based constructor + `java.awt.headless=true` — have not resolved it.

**Root cause:** Lanterna 3.1.2's `DefaultTerminalFactory.createTerminal()` on Windows falls through
to a code path that requires either the JNA Windows Console API (broken in fat JARs) or
`javaw.exe` (no stdout). Neither is suitable for a CLI tool.

**Fix options (choose one):**

**Option A — Replace Lanterna with pure ANSI escape codes** *(recommended)*
- Remove Lanterna dependency entirely
- Implement a lightweight `AnsiTui` class using raw VT100 escape sequences written to `System.out`
- Windows Terminal and modern CMD both support VT100 since Windows 10 v1511
- Activate VT processing on Windows via `kernel32.dll` JNA call: `SetConsoleMode(handle, ENABLE_VIRTUAL_TERMINAL_PROCESSING)`
- No external dependency, works everywhere

**Option B — Replace Lanterna with `jexer` or `charva`**
- Both are Lanterna alternatives with better Windows support
- `jexer` supports xterm/VT100 and has a Swing fallback that works with `java.exe`

**Option C — Switch to `javaw.exe` + Swing window for TUI only**
- `run.bat` re-launches with `javaw.exe` only when `--tui` is passed
- Swing window for TUI, console for everything else
- Hacky and confusing UX

**What to change:**
- `TuiProgressDisplay.java` — replace Lanterna screen/GUI with chosen approach
- `pom.xml` — replace `lanterna` + `jna` + `jna-platform` with new dep (or none for Option A)
- `BUGS.md` — remove entry when resolved

**Verify:** `.\run.bat` on Windows Terminal should display a full-screen TUI without any fallback warning.

---

## P1 — High Priority

---

### TASK-01: Dockerfile + Docker Distribution

**Priority:** P1 | **Effort:** 4h | **New deps:** None

**Why we can dockerize this:**
The fat JAR (`port-scanner-1.0-shaded.jar`) is entirely self-contained — all dependencies are
bundled. A Docker image is just a JRE base + the JAR. The result is a ~200MB image (or ~80MB
with Alpine JRE) that requires zero Java installation on the host.

**Why it wasn't done yet:** No one asked — and there are a few non-obvious runtime concerns
that need to be handled correctly (see below).

**Runtime concerns and solutions:**

| Concern | Explanation | Solution |
|---------|-------------|---------|
| **Network perspective** | A container scans its own network namespace by default, not the host network. Scanning `192.168.1.x` from inside a container won't reach the LAN. | `docker run --network=host` (Linux only). On Windows/Mac, Docker runs inside a Linux VM so `--network=host` gives the VM's network, not the Windows host's LAN. |
| **UDP scanning** | Raw ICMP reception (used to detect closed UDP ports) requires elevated privileges. | `docker run --cap-add=NET_RAW` |
| **Interactive prompts** | The ethical confirmation prompt reads from stdin. A plain `docker run` without `-it` will fail. | Always run with `docker run -it`. Document this clearly. |
| **TUI** | Lanterna needs a real TTY. | `docker run -it` allocates a pseudo-TTY. TUI works if BUG-04 is fixed. |
| **Output files** | Reports written to the filesystem are lost when the container exits. | Mount a volume: `docker run -v ./reports:/reports`. Default `--output` to `/reports/` inside the container. |

**What to create:**

1. `Dockerfile` — multi-stage build:
```dockerfile
# Stage 1: build
FROM maven:3.9-eclipse-temurin-21-alpine AS builder
WORKDIR /build
COPY pom.xml .
RUN mvn dependency:go-offline -q
COPY src ./src
RUN mvn package -DskipTests -q

# Stage 2: runtime
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
RUN mkdir /reports
COPY --from=builder /build/target/port-scanner-1.0-shaded.jar port-scanner.jar
ENTRYPOINT ["java", "-jar", "/app/port-scanner.jar"]
```

2. `.dockerignore` — exclude `target/`, `.git/`, `*.md`

3. `docker-run.sh` (Linux/Mac) and `docker-run.ps1` (Windows) — convenience wrappers:
```bash
docker run -it --rm --network=host \
  --cap-add=NET_RAW \
  -v "$(pwd)/reports:/reports" \
  port-scanner "$@"
```

4. Document in README: build image, usage examples, network mode caveats.

**Verify:**
```bash
docker build -t port-scanner .
docker run -it --rm --network=host port-scanner --host localhost --ports 1-1024
docker run -it --rm --network=host -v ./reports:/reports port-scanner \
  --host localhost --ports 1-1024 -o /reports/scan.html
```

---

### TASK-02: GraalVM Native Image Completion

**Priority:** P1 | **Effort:** 1 day | **New deps:** None (profile already in `pom.xml`)

**Problem:** The `native` Maven profile exists in `pom.xml` but has never been built and
verified. Without proper reflection configuration, the native image build will fail or produce
a broken binary (Jackson, Picocli, SLF4J, and Logback all use reflection heavily).

**Value:** A native binary starts in ~10ms (vs JVM ~500ms), is a single file (~60–80MB),
and requires no Java installation — ideal for distribution and Docker minimal images (FROM scratch).

**What to do:**

1. Generate reflection config by running with the GraalVM tracing agent:
```bash
java -agentlib:native-image-agent=config-output-dir=src/main/resources/META-INF/native-image \
  -jar target/port-scanner-1.0-shaded.jar --host localhost --ports 80,443
```
This auto-generates `reflect-config.json`, `resource-config.json`, `proxy-config.json`.

2. Add `src/main/resources/META-INF/native-image/native-image.properties`:
```
Args = --no-fallback \
       -H:+ReportExceptionStackTraces \
       --initialize-at-build-time=org.slf4j \
       --initialize-at-run-time=io.netty
```

3. Add `resource-config.json` to include `services.json` and Logback config.

4. Handle Lanterna/JNA in native image — either exclude TUI from native build or add JNI config.

5. Build and verify:
```bash
mvn -Pnative package
./target/port-scanner --host localhost --ports 1-1024
```

6. Document the GraalVM setup in `GRAALVM.md` (file already exists).

7. Add native image build to GitHub Actions matrix (Linux + Windows via GraalVM CE).

**Verify:** Binary runs on a machine with no Java installed. Startup under 50ms.

---

### TASK-03: Multi-Host File Scanning

**Priority:** P1 | **Effort:** 1 day | **New deps:** None

**Value:** Right now scanning 50 hosts requires running the tool 50 times. A `--hosts-file`
flag reads targets from a file and scans them in parallel, producing a combined report.

**CLI addition:**
```
--hosts-file <path>   Read hosts (one per line) or CIDR ranges and scan all in parallel.
                      Comments (#) and blank lines ignored.
                      Mutually exclusive with --host, --subnet, --auto-discover.
--host-parallelism    Max concurrent host scans when using --hosts-file. Default: 4.
```

**Target file format:**
```
# Web servers
192.168.1.10
192.168.1.11
webserver.internal
10.0.0.0/24        # CIDR ranges also supported
```

**What to create:**
- `scanner/MultiHostScanner.java` — reads file, fans out to `PortScanner`/`CidrScanner` per host
  using a fixed-size executor capped at `--host-parallelism`
- Aggregated `MultiHostReport` (list of `ScanReport`) serialized to JSON/HTML
- Progress: per-host status line (host X/N: scanning...)
- `ScanCommand.java` — add `--hosts-file` and `--host-parallelism` options; validate mutual exclusivity

**Verify:** Provide a file with 5 entries (localhost + 4 non-routable). All 5 appear in output JSON.

---

### TASK-04: Scan History Database

**Priority:** P1 | **Effort:** 1 day | **New deps:** None (sqlite-jdbc already in pom.xml)

**Value:** SQLite is already a dependency (used for local CVE DB). Reusing it for scan history
is near-free. This enables tracking when ports open/close over time and alerting on changes.

**Database location:** `~/.portscanner/history.db`

**Schema:**
```sql
CREATE TABLE scans (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  host      TEXT NOT NULL,
  scanned_at TEXT NOT NULL,        -- ISO-8601
  duration_ms INTEGER,
  report_json TEXT NOT NULL        -- full ScanReport serialized
);

CREATE TABLE open_ports (
  scan_id   INTEGER REFERENCES scans(id),
  port      INTEGER,
  service   TEXT,
  banner    TEXT,
  PRIMARY KEY (scan_id, port)
);
```

**New CLI flag:**
```
--save-history        Persist this scan to ~/.portscanner/history.db
--history <host>      Show scan history for a host (last N scans, port change timeline)
--history-diff        Auto-diff against most recent scan for same host in history DB
```

**New subcommand:** `portscanner history --host 192.168.1.1 --last 10`
- Shows table: scan date, duration, open ports count, new/closed ports vs prior scan

**What to create:**
- `db/ScanHistoryDao.java` — insert scan, query by host, diff two scans
- `db/HistorySchema.java` — DDL init on first run
- Update `ScanCommand.java` — if `--save-history`: persist after scan completes
- `cli/HistoryCommand.java` — picocli subcommand for viewing history

**Verify:** Run two scans with `--save-history`. Run `history --host localhost`. Second entry shows diff.

---

### TASK-05: Scan Profiles / Templates

**Priority:** P1 | **Effort:** 4h | **New deps:** None

**Value:** Common scan patterns (web audit, database audit, quick recon) are always typed out
manually. Named profiles bundle flags into a single shorthand.

**CLI addition:**
```
--profile <name>    Load a named scan profile. Built-in: web, db, quick, full, stealth.
                    Custom profiles defined in ~/.portscanner/profiles.yaml.
```

**Built-in profiles:**

| Profile | Equivalent flags |
|---------|-----------------|
| `quick` | `--top-ports 100 -T4` |
| `web` | `--ports 80,443,8080,8443,3000,5000 --banner --http --tls` |
| `db` | `--ports 1433,3306,5432,6379,27017,9042 --banner --probes` |
| `full` | `--ports 1-65535 -T3 --banner --tls --http --geolocate` |
| `stealth` | `--top-ports 100 -T1 --rate 10` |

**Custom profile format** (`~/.portscanner/profiles.yaml`):
```yaml
profiles:
  myprofile:
    ports: "80,443,8080"
    banner: true
    tls: true
    timing: T4
```

**What to change:**
- `config/ScanProfile.java` — model class
- `config/ProfileLoader.java` — load built-ins + merge from YAML
- `ScanCommand.java` — `--profile` option applied before other flags (flags on CLI override profile)

**Verify:** `--profile web --host localhost` scans the expected ports with banner+TLS enabled.

---

### TASK-06: Service Version Extraction from Banners

**Priority:** P1 | **Effort:** 4h | **New deps:** None

**Value:** Currently `--banner` grabs the raw first line. `--probes` gets richer data.
But neither extracts a clean version string like `Apache/2.4.51` or `OpenSSH_8.9`. Version
info is critical for CVE correlation and makes output significantly more useful.

**What to do:**
1. Create `service/VersionExtractor.java` with a map of regex patterns:
```java
Map.of(
  "SSH",   Pattern.compile("SSH-[\\d.]+-([\\w._-]+)"),
  "HTTP",  Pattern.compile("Server: ([^\\r\\n]+)"),
  "FTP",   Pattern.compile("\\d{3}[- ]([\\w._-]+ [\\w._-]+)"),
  "SMTP",  Pattern.compile("220[- ](.+)"),
  "MySQL", Pattern.compile("\\d+\\.\\d+\\.\\d+[-\\w]*")
  // etc.
)
```
2. Add `version` field to `ScanResult.java`
3. After banner grab: run `VersionExtractor.extract(serviceName, banner)` and store result
4. Display in text output as extra column: `Apache 2.4.51`
5. Use extracted version to improve CVE lookup precision (version-aware NVD query)

**Verify:** Scan a local Apache/nginx server with `--banner`. `version` field shows `Apache/2.x.x`.

---

## P2 — Medium Priority

---

### TASK-07: GitHub Actions Release Pipeline

**Priority:** P2 | **Effort:** 4h | **New deps:** None

**Value:** CI already runs tests. A release pipeline would automatically publish artifacts
when a git tag is pushed, making distribution trivial.

**What to create:** `.github/workflows/release.yml`

Triggered on: `push` to tags matching `v*`

Steps:
1. Build fat JAR (`mvn package -DskipTests`)
2. Build native image on Linux runner (GraalVM CE Action)
3. Build native image on Windows runner (cross-compile or native runner)
4. Build Docker image + push to GitHub Container Registry (`ghcr.io`)
5. Create GitHub Release with artifacts:
   - `port-scanner-linux` (native binary)
   - `port-scanner-windows.exe` (native binary)
   - `port-scanner-1.0-shaded.jar` (universal JAR)
   - `port-scanner-1.0.tar.gz` (JAR + run scripts)

Users would then install with:
```bash
# Linux/Mac
curl -L https://github.com/<user>/port-scanner/releases/latest/download/port-scanner-linux -o port-scanner
chmod +x port-scanner
./port-scanner --host localhost

# Docker
docker pull ghcr.io/<user>/port-scanner:latest
```

---

### TASK-08: REST API Mode

**Priority:** P2 | **Effort:** 2 days | **New deps:** Javalin ~3MB or Sun HttpServer (no dep)

**Value:** Transforms the scanner into a microservice. Useful for CI/CD pipelines, automation,
and building dashboards on top. Combined with Docker: `docker run -p 8080:8080 port-scanner --serve`.

**CLI addition:**
```
--serve             Start an HTTP API server instead of running a one-off scan
--serve-port <n>    Port to listen on. Default: 8080
--serve-auth <key>  Require X-API-Key header on all requests
```

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scan` | Start a scan, returns scan ID |
| `GET` | `/scan/{id}` | Get scan status + results |
| `GET` | `/scan/{id}/stream` | SSE stream of live progress |
| `GET` | `/scans` | List recent scans |
| `DELETE` | `/scan/{id}` | Cancel a running scan |

**Request body for `POST /scan`:**
```json
{
  "host": "192.168.1.1",
  "ports": "1-1024",
  "timing": "T4",
  "banner": true,
  "tls": true
}
```

**Implementation options:**
- **Option A (no new dep):** Use `com.sun.net.httpserver.HttpServer` (built into JDK). Minimal but sufficient for basic REST.
- **Option B:** Add Javalin (~3MB) for cleaner routing, SSE, and JSON handling.

**What to create:**
- `api/ScanApiServer.java` — HTTP server, route definitions
- `api/ScanJobManager.java` — concurrent scan execution, job state map
- `api/dto/ScanRequest.java`, `ScanResponse.java`
- Update `ScanCommand.java` — `--serve` flag launches server instead of scanning

---

### TASK-09: Scheduled / Watch Mode

**Priority:** P2 | **Effort:** 1 day | **New deps:** None

**Value:** Continuously monitors a host for port changes. Useful for detecting unexpected
services opening or firewall rule changes.

**CLI addition:**
```
--watch             Re-scan every N minutes, report diffs only
--watch-interval    Interval in minutes between scans. Default: 60
--watch-alert       Print an alert (and optionally POST webhook) when a port opens or closes
```

**Behaviour:**
- First scan: full output
- Subsequent scans: only print diff (new ports, closed ports, changed banners)
- Runs until Ctrl+C
- If `--output` specified: appends a timestamped scan to a JSON array in the file
- If `--save-history` also set: each re-scan is persisted to history DB

**What to create:**
- `scanner/WatchMode.java` — scheduler loop using `ScheduledExecutorService`
- Reuses `ReportDiffer` for change detection
- Ctrl+C handler: `Runtime.getRuntime().addShutdownHook(...)` prints summary stats

---

### TASK-10: OS / TTL Fingerprinting

**Priority:** P2 | **Effort:** 1 day | **New deps:** None

**Value:** Guessing the target OS adds context to security reports. TTL from ICMP responses is
a cheap heuristic; TCP window size is more reliable.

**Approach:**
- **TTL heuristic** (via `InetAddress.isReachable()` or `ping` process): TTL 64 → Linux/Mac, TTL 128 → Windows, TTL 255 → network device
- **TCP stack fingerprinting** (basic): initial TCP window size, TCP options order — match against a small signature table
- **Banner-based**: SSH banner `Ubuntu`, IIS in HTTP `Server:` header, SMB OS field

**What to create:**
- `scanner/OsFingerprinter.java` — `OsGuess fingerprint(InetAddress, List<ScanResult>)`
- `model/OsGuess.java` — `@Data`: `String os`, `String confidence` (low/medium/high), `String method`
- Add `osGuess` to `ScanReport`, display in text output header and HTML report

**CLI flag:** `--os` (disabled by default, adds latency)

---

### TASK-11: Webhook / Notification on Scan Complete

**Priority:** P2 | **Effort:** 4h | **New deps:** None (use JDK `HttpClient`)

**Value:** Integrate the scanner into automated pipelines. POST results to Slack, Discord,
a monitoring system, or any custom endpoint when a scan completes.

**CLI addition:**
```
--webhook <url>           POST scan summary JSON to this URL on completion
--webhook-on-open-only    Only POST if at least one new open port was found (useful with --watch)
```

**POST body:** abbreviated `ScanReport` JSON (host, timestamp, open port count, open ports list).

**Config file support:**
```yaml
webhook: "https://hooks.slack.com/services/..."
webhookOnOpenOnly: true
```

**Slack/Discord payload format:** If URL contains `slack.com` or `discord.com`, format as a
Slack-compatible attachment block with port table.

**What to create:**
- `service/WebhookClient.java` — `send(ScanReport, String url)` using `java.net.http.HttpClient`
- Slack/Discord payload builder
- Hook into `ScanCommand.java` after scan completes

---

### TASK-12: Markdown + PDF Output

**Priority:** P2 | **Effort:** 4h | **New deps:** OpenPDF ~2MB (for PDF only) |

**Value:** Markdown is useful for pasting into GitHub issues, wikis, and documentation.
PDF is expected in professional security audit deliverables.

**Markdown exporter:**
- No new dependency needed — just string formatting
- Extension: `.md` → `MarkdownExporter`
- Format: H1 title, metadata table, H2 open ports with fenced table, H3 per-port detail

**PDF exporter:**
- Use OpenPDF (fork of iText 4, Apache-licensed)
- Extension: `.pdf` → `PdfExporter`
- Embed the HTML report into PDF using a simple table layout (no browser rendering needed)
- Or: convert the existing `HtmlExporter` output via Flying Saucer (xhtmlrenderer)

**What to create:**
- `report/MarkdownExporter.java` — implements `ReportExporter`
- `report/PdfExporter.java` — implements `ReportExporter`
- Register both in `ExporterFactory.java`
- Add `pdf` to `--format` options

---

## P3 — Nice to Have

---

### TASK-13: Network Topology Visualization

**Priority:** P3 | **Effort:** 2 days | **New deps:** None (output is plain text in DOT syntax)

**Value:** After a subnet scan or multi-host scan, visualize the discovered hosts, their open
ports, and network relationships as a graph.

**Output formats:**
- **Graphviz DOT** (`.dot`) — pipe to `dot -Tpng` to render; free, widely available
- **Mermaid** (embedded in Markdown/HTML) — renders in GitHub, GitLab, Notion, Obsidian

**What the graph shows:**
- Scanner node → target hosts (edges labelled with open port counts)
- Host nodes coloured by OS guess (red = Windows, green = Linux, grey = unknown)
- Port nodes on each host (80/HTTP, 443/HTTPS, etc.)
- Router hops from traceroute (if `--traceroute` was run)

**CLI flag:**
```
--topology-output <file>   Write Graphviz DOT or Mermaid diagram (detected by extension: .dot, .mmd)
```

**What to create:**
- `report/DotExporter.java` — implements `ReportExporter`; works on `MultiHostReport` or `SubnetReport`
- `report/MermaidExporter.java`
- Embed Mermaid diagram into HTML report automatically when scanning subnets

---

### TASK-14: External Plugin Loading from Directory

**Priority:** P3 | **Effort:** 1 day | **New deps:** None

**Value:** The current plugin system only supports built-in plugins compiled into the JAR.
External plugins would let users write their own detection logic without recompiling.

**Design:**
- Load JARs from `~/.portscanner/plugins/` at startup
- Each plugin JAR must contain a class implementing `ScanPlugin` + a
  `META-INF/services/com.portscanner.plugin.ScanPlugin` ServiceLoader file
- `PluginRegistry` uses `URLClassLoader` to load external JARs and discovers plugins via `ServiceLoader`

**What to change:**
- `plugin/PluginRegistry.java` — scan `~/.portscanner/plugins/*.jar`, load via `URLClassLoader`
- Document plugin API: interface, lifecycle, `PluginContext` fields available

**Example plugin use case:** A user writes `nfs-check.jar` that probes port 2049 for NFS exports.
They drop it in `~/.portscanner/plugins/` and run `--scripts nfs-check`.

---

### TASK-15: SNMP Scanning

**Priority:** P3 | **Effort:** 2 days | **New deps:** SNMP4J ~1MB

**Value:** SNMP is ubiquitous in network equipment (routers, switches, printers, UPS devices).
Scanning for open SNMP agents and walking common OIDs reveals system info, interface details,
and misconfigurations (community string `public` is still common).

**CLI additions:**
```
--protocol snmp         Include SNMP in scan (adds UDP port 161)
--snmp-community <str>  Community string to try. Default: public, private (both tried)
--snmp-walk             Walk sysDescr, sysName, ifTable OIDs on responsive hosts
```

**What to create:**
- `scanner/SnmpScanner.java` — sends SNMP GET to sysDescr OID (1.3.6.1.2.1.1.1.0)
- `model/SnmpInfo.java` — sysDescr, sysName, sysLocation, sysContact, interfaceCount
- Add `snmpInfo` to `ScanResult`, display in text/HTML output
- Dep: `org.snmp4j:snmp4j:3.7.x`

---

### TASK-16: Windows Native Installer (jpackage)

**Priority:** P3 | **Effort:** 4h | **New deps:** None (jpackage ships with JDK 14+)

**Value:** `jpackage` (included in JDK) produces a `.msi` or `.exe` Windows installer that
bundles a trimmed JRE alongside the app. Users double-click to install — no Java required.
The resulting install is ~60MB vs the 200MB+ Docker image.

**What to do:**
1. Create `jlink` config to produce a trimmed JRE (only modules used by the app)
2. Run `jpackage` to produce `.msi`:
```bash
jpackage \
  --type msi \
  --name "Port Scanner" \
  --app-version 1.0 \
  --input target/ \
  --main-jar port-scanner-1.0-shaded.jar \
  --main-class com.portscanner.Main \
  --win-console \
  --win-shortcut
```
3. Add `jpackage` step to GitHub Actions release workflow (TASK-07)
4. Output: `Port-Scanner-1.0.msi` attached to GitHub Release

**Note:** `--win-console` is critical — without it, the app is treated as a GUI app (like `javaw`) and has no console I/O.

---

## P4 — Stretch Goals

---

### TASK-17: Interactive REPL Mode

**Priority:** P4 | **Effort:** 2 days | **New deps:** JLine3 (already in pom.xml)

**Value:** Instead of re-running the JAR for every scan, a REPL lets you run multiple scans
interactively with history, tab-completion, and persistent context.

**CLI flag:** `portscanner shell` (new subcommand)

**REPL commands:**
```
scan 192.168.1.1 --ports 1-1024 --banner
history 192.168.1.1
diff scan1.json scan2.json
set timeout 500
set threads 200
profiles
help
exit
```

**JLine3** is already a dependency (used for the progress bar). Reuse it for readline-style
input with history file at `~/.portscanner/repl_history`.

**What to create:**
- `cli/ReplCommand.java` — picocli subcommand, starts the REPL loop
- `cli/ReplParser.java` — tokenises REPL input, dispatches to existing `ScanCommand` logic
- Tab-completion for hostnames from history DB, option names, profile names

---

### TASK-18: Metasploit-Compatible Output

**Priority:** P4 | **Effort:** 1 day | **New deps:** None

**Value:** Security professionals using Metasploit Framework can import nmap XML directly
(`db_import`). Our existing nmap-XML exporter produces compatible output in theory, but
it needs to be verified against real Metasploit import and any gaps closed.

**What to do:**
1. Test `db_import` with current `NmapXmlExporter` output against Metasploit 6.x
2. Fix any missing required fields (`<host state="up">`, `<address>` format, `<port protocol>`)
3. Add Metasploit workspace export format (`.msf` resource script):
```
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.1
set PORTS 80,443,22
run
```
4. Extension: `.rc` → `MetasploitRcExporter`

---

## Implementation Notes

### Dependency Policy
- Only add a new dependency if the value clearly justifies the JAR size increase
- Prefer JDK built-ins (`java.net.http`, `com.sun.net.httpserver`) over small utility libraries
- Any new dep must have an Apache 2.0 or MIT license

### Testing Requirements
- Every new scanner class needs a unit test with a `ServerSocket`-based fixture
- Every new exporter needs a round-trip test: build a `ScanReport` → export → parse → assert fields
- Integration tests (Testcontainers) for any feature that talks to a real service (SNMP, REST API)

### Priority Guidance
- **P0/P1**: Fix the TUI, add Docker, complete native image — these directly improve usability and distribution
- **P2**: REST API + watch mode — these unlock automation use cases
- **P3+**: Nice additions but not blockers
