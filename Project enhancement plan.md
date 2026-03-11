# Java Port Scanner — Enhancement Plan

> **Version 2.0** — Post-implementation roadmap
> Baseline: multithreaded TCP connect scanner with Picocli, Lombok, Jackson, JUnit 5

---

## Overview

The core scanner is feature-complete. This document outlines practical enhancements organized by category, each with implementation notes and effort estimates.

---

## 1. Scanning Capabilities

### 1.1 UDP Port Scanning
UDP is stateless — there is no three-way handshake to confirm an open port. The heuristic is: send a payload, wait; if an ICMP "port unreachable" comes back, the port is closed; silence means open|filtered.

**Implementation:**
- Use `DatagramSocket` to send a zero-byte UDP packet per port
- Listen for `PortUnreachableException` (maps to ICMP type 3, code 3) → `CLOSED`
- `SocketTimeoutException` → `OPEN|FILTERED` (same ambiguity as nmap)
- Add `--protocol udp|tcp|both` option to `ScanCommand`

**Effort:** Medium — UDP semantics are genuinely harder; requires root on Linux to receive ICMP reliably.

---

### 1.2 CIDR / Subnet Scanning
Scan an entire subnet in one invocation instead of running the tool per host.

**Implementation:**
- Add `--subnet 192.168.1.0/24` option (mutually exclusive with `--host`)
- Parse CIDR using bitwise arithmetic: `networkAddr | (i & ~mask)` for each host index
- Outer loop over hosts, inner loop existing port scan logic
- Produce one `ScanReport` per live host; wrap in a `SubnetReport` aggregate

**Effort:** Medium — mostly orchestration; no new socket primitives needed.

---

### 1.3 Host Discovery (Ping Sweep)
Before scanning ports on a subnet, filter out hosts that do not respond to a reachability check to avoid wasting time on dead IPs.

**Implementation:**
- `InetAddress.isReachable(timeout)` — uses ICMP echo on Unix, TCP echo on Windows
- Run host discovery in parallel using existing `ExecutorService` pattern
- Only submit port scan tasks for reachable hosts
- Add `--skip-discovery` flag to bypass for hosts that block ICMP

**Effort:** Low — `isReachable` is already in the JDK; the challenge is that it requires root for ICMP on Linux.

---

### 1.4 Protocol-Specific Probes
Plain TCP connect confirms a port is open but does not confirm the service. Sending a protocol-specific probe can confirm the service and elicit a richer banner.

**Implementation:**
- Define a `Probe` interface: `byte[] getPayload()` + `boolean matches(String response)`
- Concrete probes: `HttpProbe` (sends `GET / HTTP/1.0\r\n\r\n`), `SmtpProbe` (reads greeting then sends `EHLO scanner`), `FtpProbe`, `SshProbe` (SSH sends banner unprompted)
- `BannerGrabber` selects the right probe based on `ServiceMapper` result
- Add `--probes` flag to enable; keep passive banner grab as default

**Effort:** Medium — each protocol needs its own probe; maintainability concern as the list grows.

---

### 1.5 Scan Rate Limiting (Stealth Mode)
Flood-style scanning is trivially detected by IDS/IPS. A rate limiter introduces deliberate inter-packet delays.

**Implementation:**
- Add `--rate <packets-per-second>` option
- Use a `ScheduledExecutorService` or a hand-rolled token bucket with `Thread.sleep` to pace submissions
- Combine with randomized port ordering (`Collections.shuffle` on port list) to break sequential-scan signatures

**Effort:** Low — rate limiting is a one-class addition; randomized ordering is a single shuffle call.

---

## 2. Output & Reporting

### 2.1 HTML Report Exporter
Generate a self-contained HTML file with a styled table — useful for sharing with non-technical stakeholders.

**Implementation:**
- Add `HtmlExporter implements ReportExporter`
- Use a simple string template or `Mustache.java` (lightweight, no Spring required) for the HTML skeleton
- Embed inline CSS; no external CDN dependency so the file works offline
- Format selection: `.html` extension triggers `HtmlExporter`

**Effort:** Low — purely string generation; no new dependencies if using a template string.

---

### 2.2 XML Report Exporter
Some enterprise tools and CI pipelines consume XML.

**Implementation:**
- Add `XmlExporter implements ReportExporter`
- Jackson already supports XML via `jackson-dataformat-xml` (add one dependency)
- Annotate `ScanReport` / `ScanResult` with `@JacksonXmlRootElement` where needed
- Format selection: `.xml` extension

**Effort:** Low — Jackson handles the heavy lifting.

---

### 2.3 Live Console Output (Progress & Color)
Currently the progress line is a raw `printf`. Picocli ships with full ANSI color support; use it.

**Implementation:**
- Replace `System.out.printf` with Picocli's `CommandLine.Help.Ansi.AUTO.string()`
- Color-code port states in real-time output: `@|green OPEN|@`, `@|red CLOSED|@`, `@|yellow FILTERED|@`
- Add a summary stats line printed after scan completion
- Respect `--no-color` / `NO_COLOR` env var (Picocli handles this automatically with `ANSI.AUTO`)

**Effort:** Low — Picocli ANSI support is already on the classpath.

---

### 2.4 Diff Mode — Compare Two Scan Reports
Run the scanner twice and surface what changed: new open ports, newly closed ports.

**Implementation:**
- Add `--diff <previous-report.json>` option
- Load the previous `ScanReport` via Jackson, compare `openPorts` sets
- Output: `NEW: 8443 (HTTPS-Alt)`, `CLOSED: 23 (Telnet)`, `UNCHANGED: 22, 80, 443`
- Useful for monitoring firewall rule changes over time

**Effort:** Medium — Jackson deserialization of previous report is straightforward; diff logic is simple set operations.

---

## 3. Service Intelligence

### 3.1 Expanded Services Database
The current `services.json` covers ~60 ports. IANA assigns over 6,000 registered ports.

**Implementation:**
- Download the official IANA service-names-port-numbers CSV and write a one-time parser to generate an expanded `services.json`
- Keep the file in `src/main/resources`; the JSON parser is already wired
- Add a `--services-file <path>` option to allow users to supply custom mappings at runtime

**Effort:** Low — data sourcing is the main task; code change is minimal.

---

### 3.2 CVE Lookup Integration
After identifying a service and version from a banner (e.g., `OpenSSH 7.4`), query a vulnerability database for known CVEs.

**Implementation:**
- Parse service version from banner using regex (e.g., `OpenSSH_([\d.]+)`)
- Query the NVD REST API v2.0: `GET https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OpenSSH+7.4`
- Add `--cve` flag to enable; results added to `ScanResult.cves: List<String>`
- Rate-limit NVD calls (NVD enforces 5 req/30s without an API key)
- Cache results in a local `~/.portscanner/cve-cache.json` to avoid repeat lookups

**Effort:** High — network calls, API key management, response parsing, rate limiting, caching.

---

### 3.3 OS Fingerprinting (Heuristic)
Infer the target OS from observable TCP/IP stack behavior without SYN scans or raw sockets.

**Observable signals (no root required):**
- TTL from `InetAddress.isReachable` responses: TTL ~64 → Linux/macOS, TTL ~128 → Windows, TTL ~255 → Cisco IOS
- Open port pattern heuristics: 135/139/445 open → Windows; 22 open + 111 open → Linux
- Response timing variance

**Implementation:**
- `OsGuesser` class with a weighted scoring map
- Add `--os-detect` flag; result added to `ScanReport.osGuess: String`

**Effort:** Medium — heuristics are imprecise by nature; needs calibration against real targets.

---

## 4. Architecture & Performance

### 4.1 Async I/O with Java NIO (Non-blocking Sockets)
The current thread-per-port model works but is limited to ~200 concurrent connections due to OS file descriptor constraints. NIO `SocketChannel` with a `Selector` can handle thousands of connections in a single thread.

**Implementation:**
- Replace `Socket` with `SocketChannel.open()` in non-blocking mode
- Register channels with a `Selector`; poll with `selector.select(timeout)`
- `SelectionKey.OP_CONNECT` fires when the connection attempt completes
- Dramatically increases throughput for large port ranges (1–65535)

**Effort:** High — NIO code is significantly more complex than blocking sockets; requires careful timeout handling.

---

### 4.2 GraalVM Native Image
Package the scanner as a self-contained native binary with no JVM dependency. Startup time drops from ~300ms to ~5ms.

**Implementation:**
- Picocli has built-in GraalVM native image support via `picocli-codegen`
- Add `native-maven-plugin` to `pom.xml`
- Add GraalVM metadata for Jackson reflection (`reflect-config.json`)
- Build: `mvn -Pnative package` → produces a native `port-scanner` binary

**Effort:** Medium — Picocli/Jackson both support GraalVM; the main work is reflection metadata for Jackson.

---

### 4.3 Configuration File Support
Allow users to persist default options (preferred timeout, thread count, output directory) in `~/.portscanner/config.yaml` instead of typing them every invocation.

**Implementation:**
- Add `jackson-dataformat-yaml` dependency
- Load config at startup, use as defaults; CLI options still override
- Picocli's `@PropertiesDefaultProvider` can wire this with minimal code

**Effort:** Low — mostly configuration wiring; no new scanning logic.

---

### 4.4 Plugin / Extension System
Allow custom `ReportExporter` or `Probe` implementations to be loaded at runtime from external JARs.

**Implementation:**
- Use Java's `ServiceLoader` mechanism: exporters declare `META-INF/services/com.portscanner.report.ReportExporter`
- Scanner discovers and registers them at startup
- Document the SPI contract so third parties can ship their own exporters

**Effort:** Medium — `ServiceLoader` is well-understood but requires discipline in API stability.

---

## 5. Developer Experience

### 5.1 Structured Logging (SLF4J + Logback)
Replace `System.out.println` debug output with proper leveled logging.

**Implementation:**
- Add `slf4j-api` + `logback-classic`
- Replace ad-hoc prints with `log.debug()` / `log.info()` / `log.warn()`
- Add `--verbose` / `-v` flag mapped to `ch.qos.logback.classic.Level.DEBUG`
- Ship a `logback.xml` in resources with sensible defaults

**Effort:** Low — mechanical replacement; no design changes.

---

### 5.2 Integration Test Suite
Current tests use unit-level `ServerSocket` stubs. Add a proper integration test layer.

**Implementation:**
- Use `Testcontainers` to spin up Docker containers (e.g., an SSH container) and scan them
- Assert real banner responses, not mocked ones
- Run integration tests in a separate Maven lifecycle phase (`verify`) to keep `test` fast

**Effort:** Medium — Testcontainers setup is straightforward; requires Docker on the CI host.

---

### 5.3 GitHub Actions CI Pipeline
Automate build, test, and native binary artifact publishing.

**Workflow jobs:**
1. `build` — `mvn verify` on Ubuntu + Windows runners
2. `native` — build GraalVM native binary on each OS, upload as release artifact
3. `security` — run `mvn dependency-check:check` (OWASP) on each PR

**Effort:** Low — standard Maven + GitHub Actions; GraalVM job needs `graalvm/setup-graalvm` action.

---

## Priority Matrix

| Enhancement | Value | Effort | Priority |
|---|---|---|---|
| ANSI color output | High | Low | Do first |
| HTML report exporter | Medium | Low | Do first |
| Expanded services DB | High | Low | Do first |
| Rate limiting / stealth mode | High | Low | Do first |
| Configuration file | Medium | Low | Do first |
| Subnet / CIDR scanning | High | Medium | Next |
| Host discovery (ping sweep) | High | Medium | Next |
| Diff mode | Medium | Medium | Next |
| GraalVM native image | Medium | Medium | Next |
| Protocol-specific probes | High | Medium | Next |
| UDP scanning | Medium | Medium | Later |
| OS fingerprinting | Medium | Medium | Later |
| Integration tests | High | Medium | Later |
| CI pipeline | High | Low | Later |
| CVE lookup | High | High | Later |
| NIO async scanning | Medium | High | Later |
| Plugin system | Low | Medium | Future |

---

*Only scan systems you own or have explicit written permission to scan.*
