# Port Scanner Enhancement Summary

**Date:** 2026-03-11
**Research basis:** Training knowledge (cutoff August 2025). URLs provided for manual verification.
**Source files:** 6 detailed findings documents in this folder.

---

## Quick-Reference Priority Matrix

| Priority | Enhancement | Effort | New Deps | Speedup / Value |
|----------|-------------|--------|----------|-----------------|
| 🔴 P1 | Virtual threads (Java 21) | Low | None | ~8–10x scan speed |
| 🔴 P1 | CompletableFuture + orTimeout() | Low | None | Better timeout handling |
| 🔴 P1 | ANSI progress bar (no deps) | Low | None | UX polish |
| 🔴 P1 | Timing profiles T0–T5 | Low | None | IDS evasion, nmap parity |
| 🔴 P1 | Top ports list (--top-ports N) | Low | None | Faster common-case scans |
| 🟡 P2 | TLS inspection (SSLSocket) | Medium | None | Cert expiry, weak ciphers |
| 🟡 P2 | HTTP header analysis | Medium | None | Framework/server detection |
| 🟡 P2 | AbuseIPDB integration | Low | None | IP reputation enrichment |
| 🟡 P2 | IPinfo.io geolocation | Low | None | ASN, country, ISP enrichment |
| 🟡 P2 | Reverse DNS enrichment | Low | None | Hostname in reports |
| 🟡 P2 | ASN lookup (Team Cymru DNS) | Low | None | No-dep ASN lookup |
| 🟡 P2 | nmap XML output format | Medium | None | Tool interoperability |
| 🟡 P2 | GreyNoise Community API | Low | None | Malicious scanner detection |
| 🟠 P3 | JLine3 sticky status line | Medium | jline3 (~2MB) | Professional TUI |
| 🟠 P3 | Plugin/script system | High | None | Extensibility |
| 🟠 P3 | Local NVD SQLite (offline CVE) | Medium | sqlite-jdbc | Replace NVD API calls |
| 🟠 P3 | Probe-based version detection | High | None | nmap -sV equivalent |
| 🟠 P3 | Traceroute (ProcessBuilder) | Medium | None | Network topology |
| ⚪ P4 | Lanterna full TUI | High | lanterna (~400KB) | Full-screen dashboard |
| ⚪ P4 | IPv6 scanning + CIDR | Medium | ipaddress (5.4.0) | IPv6 support |
| ⚪ P4 | DNS subdomain brute-force | Medium | dnsjava (3.6.1) | Recon feature |
| ⚪ P4 | Javalin web dashboard | High | javalin (~10MB) | Browser-based live view |
| ⚪ P4 | OS fingerprinting (TTL/ping) | Medium | None | Imprecise without raw sockets |

---

## 1. Performance — Modern Java

> **Source:** `findings_modern_java.md`

### 1.1 Virtual Threads — Highest-Impact Change (Java 21)

Replace the current `Executors.newFixedThreadPool(poolSize)` in `PortScanner.java` with virtual threads:

```java
// Current (200-thread cap, queuing bottleneck)
ExecutorService executor = Executors.newFixedThreadPool(Math.min(threadCount, 200));

// Virtual threads — unlimited, JVM-scheduled, no platform thread per port
ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
Semaphore concurrencyLimit = new Semaphore(1000); // control open fd count
```

**Expected speedup (modeled benchmarks):**

| Scenario | Current (100 threads) | Virtual threads (Semaphore 1000) |
|----------|----------------------|----------------------------------|
| 1,024 ports, 200ms timeout | ~2 seconds | ~0.25 seconds (~8x) |
| 65,535 ports, 200ms timeout | ~66 seconds | ~6–7 seconds (~10x) |

Memory: 1,000 virtual threads use ~200 MB less heap than 1,000 platform threads.

**pom.xml change:** Bump `<source>17</source>` → `<source>21</source>`.
The `--use-nio` flag becomes redundant — virtual threads match NIO throughput with simpler code.

### 1.2 CompletableFuture with orTimeout() — Java 17, No Preview

Replace the raw `Future.get(timeout, unit)` loop in `PortScanner.java`:

```java
// Replace:
ScanResult result = future.get(timeoutMs + 500L, TimeUnit.MILLISECONDS);

// With:
List<CompletableFuture<ScanResult>> futures = portList.stream()
    .map(port -> CompletableFuture.supplyAsync(() -> scanPort(host, port), executor)
        .orTimeout(timeoutMs + 500L, TimeUnit.MILLISECONDS)
        .exceptionally(e -> ScanResult.builder().port(port).status(PortStatus.FILTERED).build()))
    .toList();
CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
```

Also parallelise the sequential CVE lookups in `ScanCommand.java:263–273` using `CompletableFuture.runAsync()`.

### 1.3 Record Classes for Models (Java 16+, GA)

`ScanResult` can become a record — enforced immutability, no Lombok needed, thread-safe across virtual threads:

```java
public record ScanResult(int port, PortStatus status, String serviceName,
                         String banner, long responseTimeMs, List<String> cves) {}
```

Jackson 2.17+ supports records natively.

---

## 2. Advanced Scanning Techniques

> **Source:** `findings_advanced_scanning.md`

### 2.1 TLS Inspection — High Value, No New Dependencies

For any open port, attempt a TLS handshake using `javax.net.ssl.SSLSocket`:

```java
SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
try (SSLSocket sslSocket = (SSLSocket) factory.createSocket()) {
    sslSocket.connect(new InetSocketAddress(host, port), timeoutMs);
    sslSocket.startHandshake();
    SSLSession session = sslSocket.getSession();
    // session.getProtocol() → "TLSv1.3"
    // session.getPeerCertificates() → X509Certificate[]
}
```

**What to detect:**
- Certificate subject, issuer, SANs, expiry (flag certs expiring within 30 days)
- Deprecated protocols: TLSv1.0, TLSv1.1, SSLv3
- Weak ciphers: RC4, NULL, EXPORT, DES
- STARTTLS upgrade for SMTP (port 25), IMAP (143), FTP (21)

**New CLI flag:** `--tls`
**New models:** `TlsInfo` (@Data @Builder), added as `tlsInfo` field on `ScanResult`
**New class:** `TlsInspector` in `scanner/`

### 2.2 HTTP Header Analysis — High Value, No New Dependencies

The existing `HttpProbe` only sends the request; `BannerGrabber` reads only the status line. A new `HttpInspector` reads all headers:

```java
out.print("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n");
// Parse Server, X-Powered-By, X-Generator, CF-Ray, X-Varnish, etc.
```

**What to detect:**
- Server software: Apache, nginx, IIS, Jetty, Kestrel, Gunicorn (with version)
- Frameworks: PHP, ASP.NET, Express, Next.js, Ruby on Rails
- CDN: Cloudflare, CloudFront, Varnish, Fastly
- CMS: WordPress, Drupal, Joomla
- Missing security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- HTTP→HTTPS redirect (301/302 + Location header)

**New CLI flag:** `--http`
**New models:** `HttpInfo` (@Data @Builder), added to `ScanResult`
**New class:** `HttpInspector` in `scanner/`

### 2.3 Protocol-Specific Probes for Databases

Extend `ProbeRegistry` with binary protocol probes:

| Port | Service | Detection Method |
|------|---------|-----------------|
| 6379 | Redis | Send `*1\r\n$4\r\nPING\r\n`, expect `+PONG` |
| 11211 | Memcached | Send `version\r\n`, expect `VERSION x.y.z` |
| 3306 | MySQL | Read 5-byte handshake header on connect |
| 5432 | PostgreSQL | Send 8-byte startup msg, read auth response type |

`BannerGrabber` needs a raw byte read mode alongside the current `readLine()` path.

**New flag:** `--version-detect` / `-V`

### 2.4 OS Fingerprinting (Low Priority)

Without raw sockets, only TTL-based inference via `ProcessBuilder("ping", "-c", "1", host)` is feasible. Parse `ttl=64` → Linux/macOS, `ttl=128` → Windows, `ttl=255` → Cisco/BSD. Accuracy is limited by hop count. Full fingerprinting requires Pcap4J (root required).

---

## 3. Scanner Features from nmap / masscan / rustscan

> **Source:** `findings_scanner_features.md`

### 3.1 Timing Profiles (--timing / -T) — P1

Add a `TimingProfile` enum (PARANOID/SNEAKY/POLITE/NORMAL/AGGRESSIVE/INSANE) backed by a `ScanTimingConfig` record. Maps to: connect timeout, inter-probe delay, max retries, parallelism limits — matching nmap T0–T5 semantics.

```java
@Option(names = {"-T", "--timing"}, defaultValue = "NORMAL",
        description = "Timing profile: PARANOID, SNEAKY, POLITE, NORMAL, AGGRESSIVE, INSANE")
private TimingProfile timingProfile;
```

### 3.2 Top Ports List (--top-ports N) — P1

Add `TopPorts.java` with `TOP_100` and `TOP_1000` arrays ordered by nmap-services open-frequency. Overrides `--ports` when set:

```java
@Option(names = "--top-ports", description = "Scan N most commonly open ports (100, 1000, etc.)")
private int topPorts;
```

Top 10 by frequency: `80, 23, 443, 21, 22, 25, 3389, 110, 445, 139`

### 3.3 nmap XML Output Format — P2

The existing `XmlExporter` produces Jackson-generated XML. Replacing it with `XMLStreamWriter`-based output in nmap's `xmloutputversion="1.05"` format enables compatibility with Metasploit, Faraday, Dradis, and nmap-parse-output tools.

New class: `NmapXmlExporter implements ReportExporter` — triggered by `--output scan.nmap` or a new `--format nmap-xml` option.

### 3.4 Plugin/Script System (nmap NSE analog) — P3

Define a `ScanPlugin` interface with `rule(ScanResult, ScanReport)` and `execute(...)` methods. Load plugins via `ServiceLoader`. Built-in first plugins: HTTP banner, TLS cert, SSH version, HTTP title.

### 3.5 SOCKS5 Proxy Support — P3 (trivial to add)

```java
Proxy socksProxy = new Proxy(Proxy.Type.SOCKS, new InetSocketAddress(proxyHost, proxyPort));
Socket s = new Socket(socksProxy);
```

Add `--proxy socks5://host:port` CLI option.

---

## 4. Threat Intelligence Integrations

> **Source:** `findings_threat_intel.md`

### Recommended Set (free tiers, minimal API key dependency)

| API | Data | Free Tier | CLI Flag |
|-----|------|-----------|----------|
| **AbuseIPDB** | Abuse confidence score (0–100), reporter count | 1,000/day | `--abuse-check` |
| **GreyNoise Community** | malicious/benign/unknown classification | 50/day | `--greynoise` |
| **IPinfo.io** | Country, city, ASN, ISP | 50,000/month | `--geolocate` |
| Local NVD SQLite | CVE lookup (offline, replaces existing NVD API calls) | Unlimited | `--local-cve-db` |

All use Java 11's `HttpClient` — no new Maven dependencies.

### Priority API Details

**AbuseIPDB** — Auth: `Key:` header. Endpoint: `GET /api/v2/check?ipAddress={ip}&maxAgeInDays=90`
Returns `abuseConfidenceScore` (>25 = suspect), `totalReports`, `isp`.

**GreyNoise** — Auth: `key:` header. Endpoint: `GET /v3/community/{ip}`
Returns `classification: "malicious"/"benign"/"unknown"` and `noise` (is background scanner).

**IPinfo.io** — Auth: `?token=`. Endpoint: `GET /ipinfo.io/{ip}/json`
Returns `org` (`"AS15169 Google LLC"`), `country`, `city`, `timezone`.

**Team Cymru ASN (DNS, no key)** — Reverse IP query via `javax.naming.DirContext`:
`8.8.8.8` → query `8.8.8.8.origin.asn.cymru.com` TXT → `"15169 | 8.8.8.0/24 | US | arin"`

### Local NVD SQLite — Replace Existing CveLookup

Seed from NVD 2.0 API (free API key gives 50 req/30s). Store in SQLite via `org.xerial:sqlite-jdbc:3.45.3.0`. Schema: `cves(cve_id, description, cvss_v3, severity, cpe_list)`. Sync daily via `lastModStartDate` parameter. ~150–200 MB on disk.

**Bonus free sources:**
- **ExploitDB** — offline Git repo (`files_exploits.csv`) maps CVE IDs to exploit EDB-IDs. No API key.
- **RIPE Stat** — free BGP prefix/ASN data: `https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}`

---

## 5. TUI & Output Enhancements

> **Source:** `findings_tui_output.md`

### Phase 1 — ANSI Progress Bar (Zero New Dependencies)

Add a `ScheduledExecutorService` ticker at 100ms using `System.err.print("\r...")` with carriage-return updates. Use Picocli's `spec.commandLine().getErr()` to keep stdout clean for piping:

```
[=============>          ] 342/1024 (33%) | 17 OPEN | 428 p/s | ETA: 1m 38s  /
```

**Effort:** ~4–6 hours. No new Maven dependencies.

### Phase 2 — JLine3 Sticky Status Line

Add `jline:jline:3.26.3` (~1.5 MB). Use `Status.getStatus(terminal)` to keep one persistent line at the bottom of the terminal while results scroll above. Add keyboard listener for `P`ause / `Q`uit / `+/-` threads.

**Effort:** ~1–2 days.

### Phase 3 — Lanterna Full TUI (--tui flag)

Add `lanterna:3.1.2` (~400 KB). Full-screen mode: host info panel, animated progress bar, live-updating port results table, stats panel (rate/ETA/open count by service). Fall back to Phase 1 output if `--tui` absent.

**Effort:** ~2–3 days.

### Phase 4 — Javalin Web Dashboard (--web PORT)

Add `javalin:6.3.0` (~10 MB, separate Maven profile). `GET /results` returns current `ScanReport` JSON. `GET /stream` pushes SSE events for each new open port. Bundle minimal `index.html` in resources. Opens browser via `Desktop.browse()`.

**Effort:** ~2–3 days. Recommend optional Maven profile due to JAR size.

---

## 6. Network Topology & Discovery

> **Source:** `findings_network_topology.md`

### High Priority (No Privileges, No New Deps)

**Reverse DNS enrichment** — `InetAddress.getByName(ip).getCanonicalHostName()` on each open-port result. Add `hostname` field to `ScanResult`. Run in parallel via existing thread pool.

**ASN lookup via Team Cymru DNS** — uses `javax.naming.directory.DirContext` (JDK built-in). Reverse IP octets, query `{reversed}.origin.asn.cymru.com` TXT. Returns ASN, BGP prefix, country, registry. No rate limits published.

**Network interface auto-detection** — `NetworkInterface.getNetworkInterfaces()` + `InterfaceAddress.getNetworkPrefixLength()`. New `--auto-discover` flag enumerates local subnets and passes them to `CidrScanner`.

### Medium Priority (ProcessBuilder, No Privileges)

**Traceroute** — `ProcessBuilder("tracert/-h 30")` on Windows, `ProcessBuilder("traceroute/-m 30")` on Linux/macOS. Parse hop lines (hop#, RTT, IP). Add `List<TracerouteHop>` to `ScanReport`. Flag: `--traceroute`.

**Better host discovery** — Three-tier: `isReachable()` → TCP probe to common ports (ConnectException = alive) → `ProcessBuilder ping`. Improves reliability vs. ICMP-blocking firewalls.

### Lower Priority (New Dependencies or Privileges)

**IPv6 scanning** — TCP connect works today. Gap: IPv6 CIDR enumeration needs `com.github.seancfoley:ipaddress:5.4.0`. NDP cache reading via `ip -6 neigh show` (ProcessBuilder). Flag: `--ipv6`.

**DNS subdomain brute-force** — `dnsjava:3.6.1` for async DNS resolution. Flag: `--dns-brute <wordlist>`.

**ARP scan** — Requires Pcap4J + root. For local subnet discovery without privileges, read ARP cache from `/proc/net/arp` or `arp -a` via ProcessBuilder.

---

## 7. New CLI Flags Summary

| Flag | Feature Area | New Deps | Notes |
|------|-------------|----------|-------|
| `--tls` | Advanced scanning | None | TLS handshake, cert inspection |
| `--http` | Advanced scanning | None | Full HTTP header analysis |
| `--version-detect` / `-V` | Advanced scanning | None | Protocol probes for version extraction |
| `-T` / `--timing` | Scanner features | None | T0–T5 timing profiles |
| `--top-ports N` | Scanner features | None | Scan N most commonly open ports |
| `--source-port N` | Scanner features | None | Bind local port (firewall bypass) |
| `--source-ip IP` | Scanner features | None | Bind local NIC IP |
| `--proxy socks5://...` | Scanner features | None | Route via SOCKS5 |
| `--scripts` | Plugin system | None | Run named plugins |
| `--abuse-check` | Threat intel | None | AbuseIPDB IP score |
| `--greynoise` | Threat intel | None | GreyNoise classification |
| `--geolocate` | Network topology | None | IPinfo.io geolocation + ASN |
| `--traceroute` | Network topology | None | ProcessBuilder traceroute |
| `--dns-brute <wordlist>` | Network topology | dnsjava | Subdomain brute-force |
| `--ipv6` | Network topology | ipaddress lib | Prefer IPv6, IPv6 CIDR |
| `--auto-discover` | Network topology | None | Auto-detect local subnets |
| `--tui` | Output | lanterna | Lanterna full-screen TUI |
| `--web [PORT]` | Output | javalin | Embedded web dashboard |

---

## 8. New Classes to Create

| Class | Package | Effort | Priority |
|-------|---------|--------|----------|
| `TlsInspector` | `scanner/` | Medium | P2 |
| `HttpInspector` | `scanner/` | Medium | P2 |
| `VersionExtractor` | `service/` | Low | P2 |
| `TlsInfo` | `model/` | Low | P2 |
| `HttpInfo` | `model/` | Low | P2 |
| `GeoLocation` | `model/` | Low | P2 |
| `AsnInfo` | `model/` | Low | P2 |
| `TopPorts` | `scanner/` | Low | P1 |
| `ScanTimingConfig` | `config/` | Low | P1 |
| `NmapXmlExporter` | `report/` | Medium | P2 |
| `AbuseIpDbClient` | `service/` | Low | P2 |
| `GreyNoiseClient` | `service/` | Low | P2 |
| `IpInfoClient` | `service/` | Low | P2 |
| `LocalCveDatabase` | `service/` | Medium | P3 |
| `ScanPlugin` (interface) | `plugin/` | High | P3 |
| `RedisProbe` | `scanner/probe/` | Low | P2 |
| `MemcachedProbe` | `scanner/probe/` | Low | P2 |
| `MysqlProbe` | `scanner/probe/` | Low | P2 |
| `Traceroute` | `scanner/` | Medium | P3 |
| `DnsEnumerator` | `scanner/` | Medium | P4 |

---

## 9. Existing Code to Modify

| File | Change | Priority |
|------|--------|----------|
| `PortScanner.java` | Virtual threads + Semaphore; CompletableFuture | P1 |
| `PortScanner.java` | Add retry logic for FILTERED ports | P2 |
| `BannerGrabber.java` | Add raw byte read mode for binary protocols | P2 |
| `ScanCommand.java` | Add new CLI flags; fix `--show-all` bug (currently unused) | P1 |
| `ProbeRegistry.java` | Register Redis, Memcached, MySQL probes | P2 |
| `Probe` interface | Add `readRawBytes()` and `parseVersion(byte[])` defaults | P2 |
| `ScanResult` | Add `tlsInfo`, `httpInfo`, `hostname`, `serviceVersion` fields | P2 |
| `ScanReport` | Add `geoLocation`, `asnInfo`, `tlsPortCount` fields | P2 |
| `TextExporter` / `HtmlExporter` | Render new model fields | P2 |
| `pom.xml` | Bump Java target to 21 | P1 |
| `pom.xml` | Add sqlite-jdbc, dnsjava (optional profile) | P3 |

---

## 10. Known Java Limitations (Do Not Implement)

These features are commonly requested but **cannot be implemented in pure Java without native code**:

| Feature | Reason | Alternative |
|---------|--------|-------------|
| SYN scan | Requires raw sockets (root + JNI) | TCP connect scan is already in use |
| FIN/XMAS/NULL scan | Requires raw sockets; unreliable on Windows anyway | Document limitation in `--help` |
| IP spoofing / decoy scan | OS enforces source IP | Distributed scanning across multiple hosts |
| ICMP traceroute/UDP traceroute | No ICMP Time Exceeded delivery to Java socket | ProcessBuilder traceroute workaround |
| ARP scanning (active) | Layer 2 — requires libpcap/raw socket | ARP cache reading via ProcessBuilder |
| Packet capture | Requires libpcap/Npcap + privileges | Pcap4J (optional, privileged mode) |

---

## Research Files Index

| File | Topic | Lines |
|------|-------|-------|
| `findings_advanced_scanning.md` | TLS, HTTP, OS fingerprinting, SYN alternatives, probes | ~950 |
| `findings_modern_java.md` | Virtual threads, StructuredTaskScope, records, benchmarks | ~716 |
| `findings_threat_intel.md` | Shodan, GreyNoise, AbuseIPDB, NVD offline, geolocation | ~833 |
| `findings_tui_output.md` | Lanterna, JLine3, ANSI, progress bar, web dashboard | ~699 |
| `findings_scanner_features.md` | nmap timing, NSE, masscan, rustscan, nmap XML, probes | ~846 |
| `findings_network_topology.md` | Traceroute, ARP, ICMP, DNS, IPv6, interfaces | ~871 |
