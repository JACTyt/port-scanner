# Java Port Scanner — Enhancement Plan v3

> **Status:** All original v1 and v2 enhancements are fully implemented (see git log).
> This document covers the next iteration of improvements, written as concrete, actionable tasks.
> Each task describes exactly what to change, create, and verify.

---

## Already Implemented (Do Not Re-implement)

UDP scanning · CIDR/subnet scanning · Host discovery · Protocol-specific probes · Rate limiting ·
HTML/XML/CSV/JSON/TXT exporters · Diff mode · ANSI color output · SLF4J logging · YAML config ·
CVE lookup (NVD API) · NIO non-blocking scanner · Banner grabbing · Service mapper (220+ ports)

---

## Task Summary Table

| Task | Name | Priority | Effort | New Deps |
|------|------|----------|--------|----------|
| [BUG-01](#bug-01-show-all-flag-never-applied-in-output) | Fix `--show-all` flag | P0 | 30 min | None |
| [BUG-02](#bug-02-no-ethical-prompt-for---subnet-mode) | Ethical prompt for `--subnet` | P0 | 30 min | None |
| [BUG-03](#bug-03-future-timeout-too-short-under-rate-limiting) | Future timeout under rate limiting | P0 | 30 min | None |
| [TASK-01](#task-01-virtual-threads-java-21) | Virtual Threads (Java 21) | P1 | 2h | None |
| [TASK-02](#task-02-timing-profiles--t0t5) | Timing Profiles `-T0`–`-T5` | P1 | 3h | None |
| [TASK-03](#task-03-top-ports-list---top-ports-n) | Top Ports List `--top-ports N` | P1 | 2h | None |
| [TASK-04](#task-04-ansi-progress-bar) | ANSI Progress Bar | P1 | 4h | None |
| [TASK-05](#task-05-completablefuture-refactor) | CompletableFuture Refactor | P1 | 3h | None |
| [TASK-06](#task-06-tls-certificate-inspection---tls) | TLS Certificate Inspection `--tls` | P2 | 1 day | None |
| [TASK-07](#task-07-http-header-analysis---http) | HTTP Header Analysis `--http` | P2 | 1 day | None |
| [TASK-08](#task-08-binary-protocol-probes) | Binary Protocol Probes | P2 | 4h | None |
| [TASK-09](#task-09-reverse-dns--asn-enrichment) | Reverse DNS + ASN Enrichment | P2 | 4h | None |
| [TASK-10](#task-10-nmap-xml-output-format) | nmap XML Output Format | P2 | 1 day | None |
| [TASK-11](#task-11-abuseipdb-integration---abuse-check) | AbuseIPDB Integration `--abuse-check` | P2 | 4h | None |
| [TASK-12](#task-12-greynoise-community-api---greynoise) | GreyNoise Community API `--greynoise` | P2 | 3h | None |
| [TASK-13](#task-13-ipinfo-geolocation---geolocate) | IPinfo.io Geolocation `--geolocate` | P2 | 3h | None |
| [TASK-14](#task-14-traceroute---traceroute) | Traceroute `--traceroute` | P3 | 1 day | None |
| [TASK-15](#task-15-socks5-proxy-support---proxy) | SOCKS5 Proxy `--proxy` | P3 | 2h | None |
| [TASK-16](#task-16-auto-discover-local-subnets---auto-discover) | Auto-Discover Local Subnets | P3 | 3h | None |
| [TASK-17](#task-17-local-nvd-sqlite-database) | Local NVD SQLite Database | P3 | 2 days | sqlite-jdbc |
| [TASK-18](#task-18-jline3-interactive-progress) | JLine3 Interactive Progress | P3 | 1-2 days | jline3 |
| [TASK-19](#task-19-plugin-script-system---scripts) | Plugin/Script System `--scripts` | P3 | 2 days | None |
| [TASK-20](#task-20-lanterna-full-screen-tui---tui) | Lanterna Full-Screen TUI `--tui` | P4 | 2-3 days | lanterna |
| [TASK-21](#task-21-ipv6-scanning) | IPv6 Scanning | P4 | 2 days | ipaddress |
| [TASK-22](#task-22-dns-subdomain-brute-force---dns-brute) | DNS Subdomain Brute-Force | P4 | 1 day | dnsjava |
| [TASK-23](#task-23-github-actions-ci-pipeline) | GitHub Actions CI Pipeline | P3 | 4h | None |
| [TASK-24](#task-24-integration-tests-testcontainers) | Integration Tests (Testcontainers) | P3 | 1-2 days | testcontainers |

---

## Bug Fixes (Fix Before Any New Features)

---

### BUG-01: `--show-all` Flag Never Applied in Output

**Priority:** P0 | **Effort:** 30 min | **Deps:** None

**Problem:** `showAll` is loaded from config correctly (`ScanCommand.java:122`) but `printSummary()` only prints `report.getOpenPorts()`. Closed and filtered ports are never shown regardless of the flag.

**Files to modify:**
- `src/main/java/com/portscanner/cli/ScanCommand.java`

**Steps:**
1. Change `printSummary(ScanReport report)` signature to `printSummary(ScanReport report, boolean showAll)`.
2. In `printSummary()`, when `showAll` is true, also iterate `report.getFilteredPorts()` (and closed ports if stored), printing them with `@|red CLOSED|@` or `@|yellow FILTERED|@` color coding.
3. Update the call site at `ScanCommand.java:276` to pass `showAll`.
4. Add a note in the `--show-all` option description: `"Not recommended for large ranges (adds thousands of lines)"`.

**Done when:**
- Running with `--show-all` prints CLOSED and FILTERED ports in the table.
- Running without `--show-all` is identical to current behavior.
- `ScanCommand` unit test asserts that `printSummary` is called with the correct `showAll` value.

---

### BUG-02: No Ethical Prompt for `--subnet` Mode

**Priority:** P0 | **Effort:** 30 min | **Deps:** None

**Problem:** The ethical confirmation prompt (`ScanCommand.java:196–207`) only fires for `--host` mode. `--subnet` mode skips it entirely, allowing scanning of non-local CIDR ranges without acknowledgment.

**Files to modify:**
- `src/main/java/com/portscanner/cli/ScanCommand.java`

**Steps:**
1. Before the `CidrScanner` is created in the subnet block (`ScanCommand.java:170`), resolve the first host IP of the CIDR using `InetAddress.getByName()`.
2. Check `isLoopbackAddress() || isSiteLocalAddress()` on that IP.
3. If the subnet is not local (e.g., `8.8.8.0/24`), display the same confirmation prompt as host mode.
4. Also check if the subnet itself indicates a private range directly: `10.x.x.x/8`, `172.16–31.x.x/12`, `192.168.x.x/16` — these can skip the prompt.

**Done when:**
- `--subnet 8.8.8.0/24` shows the ethical confirmation prompt.
- `--subnet 192.168.1.0/24` does not show the prompt.
- `--subnet 127.0.0.0/8` does not show the prompt.

---

### BUG-03: Future Timeout Too Short Under Rate Limiting

**Priority:** P0 | **Effort:** 30 min | **Deps:** None

**Problem:** `PortScanner` collects results with `future.get(timeoutMs + 500, MILLISECONDS)`. When `--rate` is set, port tasks are submitted gradually, so later ports in the queue may not have even started by the time `future.get()` is called. This causes premature `TimeoutException` for ports that were queued behind rate-limited tasks.

**Files to modify:**
- `src/main/java/com/portscanner/scanner/PortScanner.java`

**Steps:**
1. In the result-collection loop, when a rate limit (`rate > 0`) is active, calculate the maximum possible queueing delay: `maxQueueDelayMs = (portCount / rate) * 1000L`.
2. Add this to the `future.get()` timeout: `future.get(timeoutMs + 500 + maxQueueDelayMs, MILLISECONDS)`.
3. Cap `maxQueueDelayMs` at a reasonable ceiling (e.g., 60,000 ms) to prevent infinite waits on huge scans.

**Done when:**
- A scan with `--rate 10 --ports 1-100` no longer produces spurious FILTERED results for ports that weren't actually slow.
- Existing `RateLimiterTest` still passes.

---

## Phase 1 — Quick Wins (No New Dependencies, ~2 days total)

---

### TASK-01: Virtual Threads (Java 21)

**Priority:** P1 | **Effort:** 2 hours | **Deps:** None

**Goal:** Replace the fixed thread pool with Java 21 virtual threads, removing the 200-thread cap and achieving ~8–10x scan throughput for large port ranges.

**Files to modify:**
- `pom.xml` — bump Java source/target from `17` to `21`
- `src/main/java/com/portscanner/scanner/PortScanner.java` — replace executor
- `src/main/java/com/portscanner/scanner/UdpScanner.java` — same change
- `src/main/java/com/portscanner/scanner/CidrScanner.java` — same change
- `src/main/java/com/portscanner/cli/ScanCommand.java` — threads cap validation

**Steps:**
1. In `pom.xml`, change both `<source>17</source>` and `<target>17</target>` to `21`.
2. In `PortScanner.java`, replace:
   ```java
   ExecutorService executor = Executors.newFixedThreadPool(Math.min(threadCount, 200));
   ```
   with:
   ```java
   ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
   Semaphore concurrencyLimit = new Semaphore(Math.min(threadCount, 1000));
   ```
3. Wrap each task submission with `concurrencyLimit.acquire()` before and `concurrencyLimit.release()` in a `finally` block inside the `Callable`.
4. Apply the same pattern to `UdpScanner.java` and `CidrScanner.java`.
5. In `ScanCommand.java`, change the threads cap from `Math.min(threads, 200)` to `Math.min(threads, 1000)` and update the `--threads` option description and help text accordingly.
6. Add a note in `--help` that `--use-nio` is now equivalent in performance to the default scanner — mark it as legacy.

**Done when:**
- All 77 existing tests pass with Java 21 target.
- Scanning ports 1–1024 against localhost completes in under 0.5 seconds with default settings.
- `--threads 1000` works without JVM crash.

---

### TASK-02: Timing Profiles `-T0`–`-T5`

**Priority:** P1 | **Effort:** 3 hours | **Deps:** None

**Goal:** Add nmap-style timing profiles that bundle timeout, delay, and parallelism settings into a single named flag — enabling IDS evasion (T0/T1) and maximum speed (T5).

**Files to create:**
- `src/main/java/com/portscanner/config/TimingProfile.java` — enum
- `src/main/java/com/portscanner/config/ScanTimingConfig.java` — record

**Files to modify:**
- `src/main/java/com/portscanner/cli/ScanCommand.java` — add `-T` option
- `src/main/java/com/portscanner/scanner/PortScanner.java` — accept `ScanTimingConfig`

**Steps:**
1. Create `TimingProfile` enum with values: `PARANOID`, `SNEAKY`, `POLITE`, `NORMAL`, `AGGRESSIVE`, `INSANE`.
2. Create `ScanTimingConfig` record:
   ```java
   public record ScanTimingConfig(
       long connectTimeoutMs,
       int  maxRetries,
       long scanDelayMs,
       int  maxParallelism
   ) {}
   ```
3. Add a static factory `ScanTimingConfig.forProfile(TimingProfile p)` returning:

   | Profile | connectTimeoutMs | maxRetries | scanDelayMs | maxParallelism |
   |---------|-----------------|------------|-------------|----------------|
   | PARANOID | 300,000 | 10 | 300,000 | 1 |
   | SNEAKY | 15,000 | 10 | 15,000 | 1 |
   | POLITE | 10,000 | 10 | 400 | 1 |
   | NORMAL | 1,000 | 6 | 0 | 100 |
   | AGGRESSIVE | 1,250 | 6 | 0 | 200 |
   | INSANE | 300 | 2 | 0 | 500 |

4. In `ScanCommand`, add:
   ```java
   @Option(names = {"-T", "--timing"}, defaultValue = "NORMAL",
           description = "Timing profile: PARANOID(T0), SNEAKY(T1), POLITE(T2), NORMAL(T3), AGGRESSIVE(T4), INSANE(T5)")
   private TimingProfile timingProfile;
   ```
5. After loading user config, apply the timing profile **only for settings the user has not explicitly overridden**. Explicitly passed `--timeout` and `--threads` always win over the profile.
6. Thread pool size comes from `timingConfig.maxParallelism()` unless `--threads` was explicitly set.

**Done when:**
- `--timing PARANOID` scans ports one-by-one with 5-minute timeout (verifiable with logs).
- `-T 5` is accepted as shorthand for `INSANE` (map T0–T5 integer aliases).
- `-T INSANE` on ports 1–100 against localhost completes in under 0.1 seconds.

---

### TASK-03: Top Ports List `--top-ports N`

**Priority:** P1 | **Effort:** 2 hours | **Deps:** None

**Goal:** Allow `--top-ports 100` to scan the 100 most commonly open ports in frequency order, matching the most common use case without specifying a range.

**Files to create:**
- `src/main/java/com/portscanner/scanner/TopPorts.java`

**Files to modify:**
- `src/main/java/com/portscanner/cli/ScanCommand.java` — add `--top-ports` option

**Steps:**
1. Create `TopPorts.java` with a `private static final int[] TOP_1000` array containing the 1,000 most scanned ports ordered by open frequency from nmap-services data. The first 20 entries are: `80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900`.
2. Add a public method `public static int[] get(int n)` that returns `Arrays.copyOfRange(TOP_1000, 0, Math.min(n, 1000))`.
3. In `ScanCommand.java`, add:
   ```java
   @Option(names = "--top-ports",
           description = "Scan N most commonly open ports (overrides --ports). Max 1000.")
   private Integer topPorts;
   ```
4. In `call()`, after parsing `--ports`, if `topPorts != null`, override `ports` with `TopPorts.get(topPorts)`.
5. Make `--top-ports` and `--ports` mutually exclusive: if both are set, print an error and return exit code 2.
6. Add `TopPortsTest` with: `get(10)` returns exactly 10 entries; port 80 is always first; `get(0)` returns empty array; `get(1001)` caps at 1000.

**Done when:**
- `--top-ports 100` scans exactly 100 ports and port 80 is the first one attempted.
- `--top-ports 100 --ports 1-1024` prints an error.
- `TopPortsTest` passes.

---

### TASK-04: ANSI Progress Bar

**Priority:** P1 | **Effort:** 4 hours | **Deps:** None

**Goal:** Show a live progress bar on stderr during scanning so the user can see real-time throughput, open port count, and estimated completion time.

**Files to create:**
- `src/main/java/com/portscanner/cli/ProgressReporter.java`

**Files to modify:**
- `src/main/java/com/portscanner/scanner/PortScanner.java` — accept and call reporter
- `src/main/java/com/portscanner/cli/ScanCommand.java` — create and pass reporter

**Steps:**
1. Create `ProgressReporter` with:
   - Constructor: `ProgressReporter(int totalPorts, boolean enabled)`
   - Fields: `AtomicInteger scanned`, `AtomicInteger openCount`
   - `void portScanned(PortStatus status)` — increments counters (called by `PortScanner` after each port)
   - `void start()` — starts a `ScheduledExecutorService` that fires every 100ms
   - `void stop()` — cancels the scheduler, prints a final newline
2. The 100ms tick prints to `System.err` using carriage return (not newline) to overwrite in-place:
   ```
   [============>       ] 512/1024 (50%) | 12 OPEN | 341 p/s | ETA: 1s
   ```
   - Progress bar: 20-char wide, filled with `=`, head `>`, empty ` `
   - Scan rate: ports-per-second calculated from elapsed time since `start()`
   - ETA: `(totalPorts - scanned) / currentRate` seconds
3. Disable automatically when `System.console() == null` (piped output, CI environment).
4. Also disable when `--no-color` flag is set.
5. `PortScanner.scan()` accepts an optional `ProgressReporter` parameter (null = no progress). Call `reporter.portScanned(result.getStatus())` after each port result is collected.
6. In `ScanCommand`, create `new ProgressReporter(ports.length, System.console() != null && !noColor)`, call `start()` before `scanner.scan()`, `stop()` after.

**Done when:**
- Progress bar is visible during a scan of ports 1–1024.
- Output is clean when piped: `java -jar ... | cat` shows no `\r` characters.
- No progress bar when `--no-color` is set.
- All existing tests still pass (reporter with `enabled=false` is a no-op).

---

### TASK-05: CompletableFuture Refactor

**Priority:** P1 | **Effort:** 3 hours | **Deps:** TASK-01 (virtual threads, same PR is fine)

**Goal:** Replace raw `Future.get()` iteration in `PortScanner.java` with `CompletableFuture` + `orTimeout()` for cleaner timeout handling and to enable parallel CVE lookups.

**Files to modify:**
- `src/main/java/com/portscanner/scanner/PortScanner.java` — replace result-collection loop
- `src/main/java/com/portscanner/cli/ScanCommand.java` — parallelize CVE lookups

**Steps:**
1. In `PortScanner.scan()`, replace the `Future<ScanResult>` list + sequential `.get()` loop with:
   ```java
   List<CompletableFuture<ScanResult>> futures = portArray.stream()
       .map(port -> CompletableFuture
           .supplyAsync(() -> scanPort(host, resolvedAddress, port), executor)
           .orTimeout(timeoutMs + 500L, TimeUnit.MILLISECONDS)
           .exceptionally(ex -> ScanResult.builder()
               .port(port).status(PortStatus.FILTERED)
               .responseTimeMs(timeoutMs).build()))
       .toList();
   CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
   List<ScanResult> results = futures.stream().map(CompletableFuture::join).toList();
   ```
2. In `ScanCommand.java`, the CVE lookup loop (lines 266–272) is currently sequential. Parallelize it:
   ```java
   List<CompletableFuture<Void>> cveFutures = report.getOpenPorts().stream()
       .map(result -> CompletableFuture.runAsync(() -> {
           String keyword = cveLookup.extractKeyword(result.getServiceName(), result.getBanner());
           if (!keyword.isBlank()) {
               List<String> cves = cveLookup.lookup(keyword);
               if (!cves.isEmpty()) result.setCves(cves);
           }
       }))
       .toList();
   CompletableFuture.allOf(cveFutures.toArray(new CompletableFuture[0])).join();
   ```
3. Note: NVD API has a rate limit of 5 req/30s without an API key. Add a `Semaphore(5)` guard inside the CVE parallel block to stay within limits.

**Done when:**
- All 77 tests pass.
- `--cve` on a host with 20+ open ports completes faster than sequential.
- No `CancellationException` or `ExecutionException` leaks to the user.

---

## Phase 2 — Scanning Enhancements (No New Dependencies, ~1 week)

---

### TASK-06: TLS Certificate Inspection `--tls`

**Priority:** P2 | **Effort:** 1 day | **Deps:** None (uses `javax.net.ssl` from JDK)

**Goal:** For any open port, attempt a TLS handshake and extract certificate details, protocol version, and cipher suite — flagging expired certs and deprecated protocols.

**Files to create:**
- `src/main/java/com/portscanner/model/TlsInfo.java` — Lombok `@Data @Builder`
- `src/main/java/com/portscanner/scanner/TlsInspector.java`

**Files to modify:**
- `src/main/java/com/portscanner/model/ScanResult.java` — add `TlsInfo tlsInfo` field
- `src/main/java/com/portscanner/cli/ScanCommand.java` — add `--tls` flag, wire inspector
- `src/main/java/com/portscanner/report/TextExporter.java` — render TLS info
- `src/main/java/com/portscanner/report/HtmlExporter.java` — render TLS info

**Steps:**
1. Create `TlsInfo` model:
   ```java
   @Data @Builder public class TlsInfo {
       private String protocol;           // e.g. "TLSv1.3"
       private String cipherSuite;        // e.g. "TLS_AES_256_GCM_SHA384"
       private String certSubject;        // CN=example.com
       private String certIssuer;         // CN=Let's Encrypt R3
       private LocalDate certExpiry;
       private List<String> subjectAltNames;
       private boolean isExpired;
       private boolean expiresSoon;       // within 30 days
       private boolean isSelfSigned;      // issuer == subject
       private boolean hasWeakCipher;     // RC4, NULL, EXPORT, DES, 3DES
       private boolean hasDeprecatedProtocol; // TLSv1.0, TLSv1.1, SSLv3
   }
   ```
2. Create `TlsInspector.inspect(String host, int port, int timeoutMs): Optional<TlsInfo>`:
   ```java
   SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
   try (SSLSocket sslSocket = (SSLSocket) factory.createSocket()) {
       sslSocket.connect(new InetSocketAddress(host, port), timeoutMs);
       sslSocket.startHandshake();
       SSLSession session = sslSocket.getSession();
       // session.getProtocol(), session.getCipherSuite()
       // session.getPeerCertificates()[0] → X509Certificate
   }
   ```
3. From `X509Certificate`: `getNotAfter()` → expiry, `getSubjectX500Principal().getName()` → subject, `getIssuerX500Principal().getName()` → issuer. Check SAN extension OID `2.5.29.17`.
4. Detect `isSelfSigned` by comparing subject and issuer.
5. Detect `hasWeakCipher` by checking if cipher suite contains: `RC4`, `_NULL_`, `EXPORT`, `_DES_`, `3DES`.
6. Detect `hasDeprecatedProtocol` when protocol is `TLSv1`, `TLSv1.1`, or `SSLv3`.
7. In `ScanCommand`, add `@Option(names = "--tls")` and after scanning, run `TlsInspector` in parallel on all open ports.
8. In `TextExporter`, when `tlsInfo != null`, print a sub-row: `  └─ TLS: TLSv1.3 | Expires: 2026-12-01 | CN=example.com`.
9. Flag expired certs in red, deprecation warnings in yellow.

**Done when:**
- `--tls` on a public HTTPS server (e.g., port 443) prints cert subject, expiry, and TLS version.
- A self-signed cert is flagged as `SELF-SIGNED`.
- Ports that don't support TLS silently produce no TLS output (not an error).
- Add `TlsInspectorTest`: create a local `SSLServerSocket` with a test keystore, verify `inspect()` returns correct `TlsInfo`.

---

### TASK-07: HTTP Header Analysis `--http`

**Priority:** P2 | **Effort:** 1 day | **Deps:** None

**Goal:** For ports identified as HTTP/HTTPS, send a full GET request, parse all response headers, detect server software and frameworks, and audit for missing security headers.

**Files to create:**
- `src/main/java/com/portscanner/model/HttpInfo.java` — Lombok `@Data @Builder`
- `src/main/java/com/portscanner/scanner/HttpInspector.java`

**Files to modify:**
- `src/main/java/com/portscanner/model/ScanResult.java` — add `HttpInfo httpInfo`
- `src/main/java/com/portscanner/cli/ScanCommand.java` — add `--http` flag
- `src/main/java/com/portscanner/report/TextExporter.java` — render HttpInfo
- `src/main/java/com/portscanner/report/HtmlExporter.java` — render HttpInfo

**Steps:**
1. Create `HttpInfo` model:
   ```java
   @Data @Builder public class HttpInfo {
       private int statusCode;
       private String serverHeader;           // e.g. "nginx/1.24.0"
       private String poweredBy;              // X-Powered-By value
       private String detectedTechnology;     // "WordPress", "Drupal", "Express", etc.
       private String redirectsTo;            // Location header if 301/302
       private Map<String, Boolean> securityHeaders; // header name → present?
   }
   ```
   Security headers to audit: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.

2. Create `HttpInspector.inspect(String host, int port, boolean useTls, int timeoutMs): Optional<HttpInfo>`:
   - Open a plain `Socket` (or `SSLSocket` if `useTls`), send:
     ```
     GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n
     ```
   - Read response line by line until blank line (end of headers); do not read body.
   - Parse status line: `HTTP/1.1 200 OK` → `statusCode = 200`.
   - Parse headers into a `Map<String, String>` (lowercase keys).

3. Technology detection logic:
   - `server` header → extract software name and version.
   - `x-powered-by: PHP/7.4` → `detectedTechnology = "PHP 7.4"`.
   - `x-powered-by: ASP.NET` → `detectedTechnology = "ASP.NET"`.
   - `x-generator: WordPress` → `detectedTechnology = "WordPress"`.
   - `cf-ray` header present → append `"(Cloudflare CDN)"` to technology.
   - `x-varnish` header present → append `"(Varnish cache)"`.
   - `x-served-by` header present → note CDN (Fastly).

4. In `ScanCommand`, add `@Option(names = "--http")` and run `HttpInspector` after scanning on ports whose `serviceName` contains `http`, `web`, or port numbers `80, 443, 8080, 8443, 8888`.

5. In `TextExporter`, print HTTP findings as sub-rows under the port line:
   ```
   80       HTTP             12ms         HTTP/1.1 200
     └─ Server: Apache/2.4.57 | Missing: HSTS, CSP, X-Frame-Options
   ```

**Done when:**
- `--http` on port 80/443 of a web server shows software name.
- Missing security headers are listed.
- A redirect target is shown when status is 301/302.
- `HttpInspectorTest` with `ServerSocket` returning crafted HTTP headers.

---

### TASK-08: Binary Protocol Probes

**Priority:** P2 | **Effort:** 4 hours | **Deps:** None

**Goal:** Extend `ProbeRegistry` with binary protocol probes for Redis, Memcached, MySQL, and PostgreSQL to enable version detection without relying on a text banner.

**Files to create:**
- `src/main/java/com/portscanner/scanner/probe/RedisProbe.java`
- `src/main/java/com/portscanner/scanner/probe/MemcachedProbe.java`
- `src/main/java/com/portscanner/scanner/probe/MysqlProbe.java`
- `src/main/java/com/portscanner/scanner/probe/PostgresProbe.java`

**Files to modify:**
- `src/main/java/com/portscanner/scanner/probe/ProbeRegistry.java` — register new probes
- `src/main/java/com/portscanner/scanner/BannerGrabber.java` — add raw byte read mode

**Steps:**
1. In `BannerGrabber`, add a `readRawBytes(InputStream in, int maxBytes, int timeoutMs): byte[]` method alongside the existing `readLine()` path. This reads up to `maxBytes` raw bytes within `timeoutMs`.
2. Implement `RedisProbe`:
   - Send: `*1\r\n$4\r\nPING\r\n` (RESP protocol inline PING)
   - Match: response starts with `+PONG`
   - Version extraction: send `INFO server` and parse `redis_version:x.y.z`
3. Implement `MemcachedProbe`:
   - Send: `version\r\n`
   - Match: response matches `VERSION \d+\.\d+`
   - Version: extract from the VERSION line
4. Implement `MysqlProbe`:
   - On connect, MySQL server sends an initial handshake packet with no client prompt needed.
   - Read first 5 bytes: bytes 0–3 = packet length (little-endian int24), byte 4 = sequence number.
   - Read `packetLength` more bytes. The first byte of the payload is the protocol version (should be `0x0a` = MySQL 5.x+).
   - Version string starts at byte 1 of the payload and is null-terminated ASCII.
   - Extract version string up to the first `\0`.
5. Implement `PostgresProbe`:
   - Send an 8-byte SSLRequest message: `\x00\x00\x00\x08\x04\xD2\x16\x2F`
   - If response is `S`, server supports SSL.
   - If response is `N`, send startup message: `\x00\x00\x00\x08\x00\x03\x00\x00` (minimal startup).
   - Read response: `R` byte = auth request (confirms PostgreSQL), `E` byte = error. Either confirms Postgres.
   - Parse server version from the `server_version` parameter in the startup response.
6. Register all four probes in `ProbeRegistry` with their canonical ports (6379, 11211, 3306, 5432).

**Done when:**
- Scanning a local Redis instance with `--banner --probes` returns `Redis` as service name with version.
- Scanning a local MySQL returns `MySQL x.y.z` in the banner field.
- `BannerGrabberTest` has a new test: ServerSocket echoing `+PONG` is detected as Redis.

---

### TASK-09: Reverse DNS + ASN Enrichment

**Priority:** P2 | **Effort:** 4 hours | **Deps:** None (uses `javax.naming` from JDK)

**Goal:** Enrich scan results with PTR (reverse DNS) hostnames and ASN metadata automatically — showing `dns.google` next to `8.8.8.8` and `AS15169 Google LLC` in the report header.

**Files to create:**
- `src/main/java/com/portscanner/service/AsnLookup.java`
- `src/main/java/com/portscanner/model/AsnInfo.java` — Lombok `@Data @Builder`

**Files to modify:**
- `src/main/java/com/portscanner/model/ScanResult.java` — add `String hostname`
- `src/main/java/com/portscanner/model/ScanReport.java` — add `AsnInfo asnInfo`
- `src/main/java/com/portscanner/cli/ScanCommand.java` — run enrichment after scan
- `src/main/java/com/portscanner/report/TextExporter.java` — show hostname + ASN

**Steps:**
1. Create `AsnInfo` model:
   ```java
   @Data @Builder public class AsnInfo {
       private String asn;       // "AS15169"
       private String prefix;    // "8.8.8.0/24"
       private String country;   // "US"
       private String registry;  // "arin"
       private String name;      // "Google LLC" (from Team Cymru)
   }
   ```
2. Create `AsnLookup.lookup(String ip): Optional<AsnInfo>`:
   - Reverse the IP octets: `8.8.8.8` → `8.8.8.8` (already reversed: `8.8.8.8` → query `8.8.8.8.origin.asn.cymru.com`).
   - Actually reverse octets: `8.8.8.8` → `8.8.8.8` reversed is `8.8.8.8`. For `1.2.3.4` it is `4.3.2.1.origin.asn.cymru.com`.
   - Use `javax.naming.directory.InitialDirContext` with `Hashtable<String, String>` env to query `TXT` records:
     ```java
     Hashtable<String,String> env = new Hashtable<>();
     env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
     DirContext ctx = new InitialDirContext(env);
     Attributes attrs = ctx.getAttributes(reversedIp + ".origin.asn.cymru.com", new String[]{"TXT"});
     ```
   - Parse TXT value: `"15169 | 8.8.8.0/24 | US | arin | "` → split on `|`.
   - Second query to `AS15169.asn.cymru.com TXT` returns the org name.
3. Reverse DNS hostname: `InetAddress.getByName(ip).getCanonicalHostName()` — already in JDK, no extra code needed. Run this only if it returns something other than the IP itself.
4. In `ScanCommand`, after scanning completes, run reverse DNS in parallel using a `CompletableFuture` per open-port result. Set `result.setHostname(hostname)` for each.
5. Run ASN lookup once per `ScanReport` (one IP, one lookup). Add result to `report`.
6. In `TextExporter`, show hostname in parentheses after IP in the header: `Scanning 8.8.8.8 (dns.google)`.
7. Show ASN block at the end: `ASN: AS15169 Google LLC | 8.8.8.0/24 | US`.

**Done when:**
- Scanning `8.8.8.8` shows `dns.google` as hostname (requires DNS).
- ASN lookup returns `AS15169`.
- Both are gracefully absent (not an error) when DNS is unavailable.
- `AsnLookupTest` mocks `DirContext` and verifies parsing of a hardcoded TXT value.

---

### TASK-10: nmap XML Output Format

**Priority:** P2 | **Effort:** 1 day | **Deps:** None (uses `javax.xml.stream` from JDK)

**Goal:** Generate nmap-compatible XML output (`xmloutputversion="1.05"`) so scan results can be imported into Metasploit, Faraday, Dradis, and parsed by `nmap-parse-output` tools.

**Files to create:**
- `src/main/java/com/portscanner/report/NmapXmlExporter.java`

**Files to modify:**
- `src/main/java/com/portscanner/report/ExporterFactory.java` — register `.nmap` extension + `--format nmap-xml`
- `src/main/java/com/portscanner/cli/ScanCommand.java` — add `--format` option

**Steps:**
1. Create `NmapXmlExporter implements ReportExporter` using `javax.xml.stream.XMLStreamWriter`:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE nmaprun>
   <nmaprun scanner="portscanner" version="2.0" xmloutputversion="1.05"
            start="{epochSeconds}" startstr="{humanDate}">
     <host starttime="{epoch}" endtime="{epoch}">
       <status state="up" reason="conn-refused"/>
       <address addr="{ip}" addrtype="ipv4"/>
       <hostnames>
         <hostname name="{hostname}" type="PTR"/>
       </hostnames>
       <ports>
         <port protocol="tcp" portid="{port}">
           <state state="open" reason="syn-ack"/>
           <service name="{serviceName}" product="{banner}"/>
         </port>
       </ports>
     </host>
     <runstats>
       <finished time="{epoch}" elapsed="{durationSecs}"/>
       <hosts up="1" down="0" total="1"/>
     </runstats>
   </nmaprun>
   ```
2. Add `--format` option to `ScanCommand`:
   ```java
   @Option(names = "--format",
           description = "Output format override: json, csv, txt, html, xml, nmap-xml")
   private String format;
   ```
3. In `ExporterFactory`, prefer `--format` over file extension when both are given. Map `nmap-xml` or `.nmap` extension to `NmapXmlExporter`.
4. The existing `XmlExporter` (Jackson-based generic XML) stays — it's for `--format xml`. `NmapXmlExporter` is specifically for `--format nmap-xml`.

**Done when:**
- `--output scan.nmap` produces valid nmap XML.
- `--format nmap-xml --output results.xml` also works.
- The output parses without error in a basic XML parser.
- `NmapXmlExporterTest` verifies required XML elements are present.

---

## Phase 3 — Threat Intelligence (No New Dependencies, ~3-4 days)

---

### TASK-11: AbuseIPDB Integration `--abuse-check`

**Priority:** P2 | **Effort:** 4 hours | **Deps:** None (uses Java 11 `HttpClient`)

**Goal:** Query AbuseIPDB for the target IP's abuse confidence score and display a threat warning when the score exceeds a threshold.

**Files to create:**
- `src/main/java/com/portscanner/service/AbuseIpDbClient.java`
- `src/main/java/com/portscanner/model/ThreatInfo.java` — Lombok `@Data @Builder`

**Files to modify:**
- `src/main/java/com/portscanner/config/ScannerConfig.java` — add `String abuseIpDbKey`
- `src/main/java/com/portscanner/model/ScanReport.java` — add `ThreatInfo threatInfo`
- `src/main/java/com/portscanner/cli/ScanCommand.java` — add `--abuse-check` flag
- `src/main/java/com/portscanner/report/TextExporter.java` — render threat warning

**Steps:**
1. Create `ThreatInfo`:
   ```java
   @Data @Builder public class ThreatInfo {
       private int abuseConfidenceScore; // 0-100
       private int abuseReportCount;
       private String isp;
       private String greynoiseClassification; // "malicious"/"benign"/"unknown"
       private boolean greynoiseIsScanner;
   }
   ```
2. Create `AbuseIpDbClient.check(String ip, String apiKey): Optional<ThreatInfo>`:
   - `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90`
   - Header: `Key: {apiKey}`, `Accept: application/json`
   - Use `java.net.http.HttpClient` (Java 11+).
   - Parse response JSON with Jackson (already a dependency).
   - Extract: `data.abuseConfidenceScore`, `data.totalReports`, `data.isp`.
3. API key resolution order:
   1. Env var `ABUSEIPDB_KEY`
   2. `config.yaml` field `abuseIpDbKey`
   3. If neither found and `--abuse-check` is set: print `"Warning: ABUSEIPDB_KEY not set"` and skip.
4. In `ScanCommand`, add `@Option(names = "--abuse-check")`. Run after scanning, set result on report.
5. In `TextExporter`, if `threatInfo.abuseConfidenceScore > 25`, print a red warning banner:
   ```
   ⚠  THREAT: AbuseIPDB score 87/100 (142 reports) — HIGH RISK
   ```

**Done when:**
- With a valid API key in `ABUSEIPDB_KEY`, `--abuse-check` on a known-clean IP (e.g., `8.8.8.8`) returns score 0.
- Without an API key, `--abuse-check` prints a warning but does not crash.
- `AbuseIpDbClientTest` mocks the HTTP response and verifies parsing.

---

### TASK-12: GreyNoise Community API `--greynoise`

**Priority:** P2 | **Effort:** 3 hours | **Deps:** None

**Goal:** Query GreyNoise to classify the target IP as `malicious`, `benign`, or `unknown`, and flag if it is a known internet-wide scanner.

**Files to create:**
- `src/main/java/com/portscanner/service/GreyNoiseClient.java`

**Files to modify:**
- `src/main/java/com/portscanner/config/ScannerConfig.java` — add `String greynoiseKey`
- `src/main/java/com/portscanner/cli/ScanCommand.java` — add `--greynoise` flag
- `src/main/java/com/portscanner/report/TextExporter.java` — render GreyNoise result

**Steps:**
1. Create `GreyNoiseClient.check(String ip, String apiKey): Optional<ThreatInfo>` (updates the same `ThreatInfo` model from TASK-11, or merges into existing one):
   - `GET https://api.greynoise.io/v3/community/{ip}`
   - Header: `key: {apiKey}`
   - Parse: `classification` (`"malicious"/"benign"/"unknown"`), `noise` (boolean — is a background scanner), `name` (actor name if known).
2. API key resolution: env var `GREYNOISE_KEY` → `config.yaml` `greynoiseKey`.
3. Merge result into `ScanReport.threatInfo` (create new `ThreatInfo` if `--greynoise` is used without `--abuse-check`).
4. In `TextExporter`, show: `GreyNoise: MALICIOUS (Scanner: Shodan)` or `GreyNoise: BENIGN`.

**Done when:**
- `--greynoise` on a known benign IP returns `"benign"`.
- `--greynoise --abuse-check` together fill both fields of `ThreatInfo` in one report.
- `GreyNoiseClientTest` mocks HTTP response.

---

### TASK-13: IPinfo.io Geolocation `--geolocate`

**Priority:** P2 | **Effort:** 3 hours | **Deps:** None

**Goal:** Show country, city, ISP, and ASN for the target IP in the scan header using the IPinfo.io free API.

**Files to create:**
- `src/main/java/com/portscanner/service/IpInfoClient.java`
- `src/main/java/com/portscanner/model/GeoLocation.java` — Lombok `@Data @Builder`

**Files to modify:**
- `src/main/java/com/portscanner/config/ScannerConfig.java` — add `String ipinfoToken`
- `src/main/java/com/portscanner/model/ScanReport.java` — add `GeoLocation geoLocation`
- `src/main/java/com/portscanner/cli/ScanCommand.java` — add `--geolocate` flag
- `src/main/java/com/portscanner/report/TextExporter.java` — render geo block in header

**Steps:**
1. Create `GeoLocation`:
   ```java
   @Data @Builder public class GeoLocation {
       private String ip, hostname, city, region, country, org, timezone;
   }
   ```
   `org` contains ASN + name: `"AS15169 Google LLC"`.
2. Create `IpInfoClient.lookup(String ip, String token): Optional<GeoLocation>`:
   - `GET https://ipinfo.io/{ip}/json?token={token}` (token optional — free tier without token is 50k/month)
   - Parse JSON with Jackson.
3. API key: env `IPINFO_TOKEN` → `config.yaml` `ipinfoToken` → empty string (works without key, rate limited).
4. In `ScanCommand`, run lookup before printing the scan header. Print geo block immediately after the header line:
   ```
   Location: Portland, Oregon, US | ISP: AS15169 Google LLC | TZ: America/Los_Angeles
   ```

**Done when:**
- `--geolocate` on a public IP shows country and ISP.
- Works without a token (limited rate).
- `IpInfoClientTest` mocks response.

---

## Phase 4 — Network Topology (No New Dependencies, ~1 week)

---

### TASK-14: Traceroute `--traceroute`

**Priority:** P3 | **Effort:** 1 day | **Deps:** None (uses `ProcessBuilder`)

**Goal:** Run system traceroute after scanning and append the routing path to the report, showing hop-by-hop RTT and IPs.

**Files to create:**
- `src/main/java/com/portscanner/scanner/Traceroute.java`
- `src/main/java/com/portscanner/model/TracerouteHop.java` — record

**Files to modify:**
- `src/main/java/com/portscanner/model/ScanReport.java` — add `List<TracerouteHop> tracerouteHops`
- `src/main/java/com/portscanner/cli/ScanCommand.java` — add `--traceroute` flag
- `src/main/java/com/portscanner/report/TextExporter.java` — render hop table

**Steps:**
1. Create `TracerouteHop` record:
   ```java
   public record TracerouteHop(int hopNumber, String ip, String hostname, double rttMs) {}
   ```
2. Create `Traceroute.run(String host, int maxHops): List<TracerouteHop>`:
   - Detect OS: `System.getProperty("os.name").toLowerCase()`.
   - Windows: `new ProcessBuilder("tracert", "-h", String.valueOf(maxHops), "-w", "1000", host)`
   - Linux/macOS: `new ProcessBuilder("traceroute", "-m", String.valueOf(maxHops), "-w", "1", host)`
   - Set `redirectErrorStream(true)`.
   - Parse output with OS-specific regex:
     - Windows line: `  1    <1 ms    <1 ms    <1 ms  192.168.1.1`
     - Linux line: ` 1  192.168.1.1 (192.168.1.1)  0.543 ms`
   - Handle `* * *` lines (timeout) as `TracerouteHop(n, "*", "*", -1)`.
3. Default `maxHops = 30`. Expose as `--traceroute-max-hops N` option.
4. In `ScanCommand`, run `Traceroute` after the port scan completes. Add to report.
5. In `TextExporter`, render:
   ```
   TRACEROUTE (30 hops max):
    1    0.5ms   192.168.1.1 (router.local)
    2    8.2ms   10.0.0.1
    3    *       (timeout)
   ```

**Done when:**
- `--traceroute` on a reachable host shows routing path.
- `* * *` hops don't crash the parser.
- Works on both Windows (tracert) and Linux (traceroute).
- `TracerouteTest` parses a hardcoded tracert/traceroute output string.

---

### TASK-15: SOCKS5 Proxy Support `--proxy`

**Priority:** P3 | **Effort:** 2 hours | **Deps:** None (uses `java.net.Proxy`)

**Goal:** Route all scanner TCP connections through a SOCKS5 proxy for anonymized scanning or pivoting through a jump host.

**Files to modify:**
- `src/main/java/com/portscanner/scanner/PortScanner.java` — pass Proxy to socket creation
- `src/main/java/com/portscanner/scanner/BannerGrabber.java` — pass Proxy
- `src/main/java/com/portscanner/scanner/TlsInspector.java` (TASK-06) — pass Proxy
- `src/main/java/com/portscanner/scanner/HttpInspector.java` (TASK-07) — pass Proxy
- `src/main/java/com/portscanner/cli/ScanCommand.java` — add `--proxy` option

**Steps:**
1. In `ScanCommand`, add:
   ```java
   @Option(names = "--proxy", description = "Route scans via SOCKS5 proxy, e.g. socks5://127.0.0.1:1080")
   private String proxyUrl;
   ```
2. Parse `proxyUrl`: strip `socks5://`, split on `:`, create:
   ```java
   Proxy proxy = new Proxy(Proxy.Type.SOCKS, new InetSocketAddress(proxyHost, proxyPort));
   ```
3. Pass `Proxy` (nullable) down to `PortScanner` constructor. In `PortScanner`, change:
   ```java
   // Before:
   Socket socket = new Socket();
   // After:
   Socket socket = proxy != null ? new Socket(proxy) : new Socket();
   ```
4. Apply the same change to `BannerGrabber`, `TlsInspector`, and `HttpInspector`.
5. `UdpScanner` cannot use SOCKS5 (UDP-over-SOCKS requires SOCKS5 UDP ASSOCIATE, not standard). Log a warning if `--proxy` + `--protocol udp` are combined.

**Done when:**
- `--proxy socks5://127.0.0.1:1080` routes TCP connections through a local SSH tunnel (`ssh -D 1080`).
- Without `--proxy`, behavior is identical to current.
- A warning is printed if `--proxy` is used with UDP.

---

### TASK-16: Auto-Discover Local Subnets `--auto-discover`

**Priority:** P3 | **Effort:** 3 hours | **Deps:** None (uses `java.net.NetworkInterface`)

**Goal:** Automatically detect all non-loopback network interfaces and their subnets, then scan them — replacing the need to manually specify `--subnet 192.168.1.0/24`.

**Files to create:**
- `src/main/java/com/portscanner/scanner/NetworkInterfaceScanner.java`

**Files to modify:**
- `src/main/java/com/portscanner/cli/ScanCommand.java` — add `--auto-discover` flag

**Steps:**
1. Create `NetworkInterfaceScanner.discoverLocalSubnets(): List<String>`:
   ```java
   NetworkInterface.getNetworkInterfaces().asIterator().forEachRemaining(iface -> {
       if (!iface.isLoopback() && iface.isUp()) {
           for (InterfaceAddress addr : iface.getInterfaceAddresses()) {
               if (addr.getAddress() instanceof Inet4Address) {
                   int prefix = addr.getNetworkPrefixLength();
                   String subnet = computeNetworkAddress(addr.getAddress(), prefix) + "/" + prefix;
                   subnets.add(subnet);
               }
           }
       }
   });
   ```
2. `computeNetworkAddress(InetAddress addr, int prefix)`: bitwise AND the address with the mask derived from prefix length.
3. In `ScanCommand`, add `@Option(names = "--auto-discover")`. When set:
   - Mutual exclusion: cannot use `--host` or `--subnet` with `--auto-discover`.
   - Call `NetworkInterfaceScanner.discoverLocalSubnets()`.
   - Print: `Discovered subnets: 192.168.1.0/24, 10.0.0.0/24`.
   - For each subnet, run `CidrScanner` and collect results.
4. Print a combined summary with results from all subnets.

**Done when:**
- `--auto-discover` on a machine with a single LAN interface discovers and scans the local subnet.
- Works on Windows and Linux.
- `NetworkInterfaceScannerTest` mocks `NetworkInterface` and verifies subnet calculation.

---

## Phase 5 — Advanced Output (~1 week)

---

### TASK-17: Local NVD SQLite Database

**Priority:** P3 | **Effort:** 2 days | **Deps:** `org.xerial:sqlite-jdbc:3.45.3.0`

**Goal:** Replace live NVD API calls with a locally cached SQLite database, enabling offline CVE lookup and eliminating rate-limit delays.

**Files to create:**
- `src/main/java/com/portscanner/service/LocalCveDatabase.java`

**Files to modify:**
- `pom.xml` — add `sqlite-jdbc` dependency
- `src/main/java/com/portscanner/service/CveLookup.java` — fall back to local DB
- `src/main/java/com/portscanner/cli/ScanCommand.java` — add `update-db` subcommand

**Steps:**
1. Add to `pom.xml`:
   ```xml
   <dependency>
       <groupId>org.xerial</groupId>
       <artifactId>sqlite-jdbc</artifactId>
       <version>3.45.3.0</version>
   </dependency>
   ```
2. Create `LocalCveDatabase`:
   - DB path: `~/.portscanner/cve-db.sqlite` (create directory if absent).
   - Schema:
     ```sql
     CREATE TABLE cves (
         cve_id TEXT PRIMARY KEY,
         description TEXT,
         cvss_v3 REAL,
         severity TEXT,
         cpe_list TEXT,
         last_modified TEXT
     );
     CREATE INDEX cves_cpe_idx ON cves(cpe_list);
     ```
   - `query(String keyword): List<String>` — `SELECT cve_id FROM cves WHERE cpe_list LIKE '%' || ? || '%' ORDER BY cvss_v3 DESC LIMIT 10`.
   - `sync(String lastModDate)` — calls NVD 2.0 API in pages of 2,000, inserts/updates rows. Uses `lastModStartDate` parameter to fetch only new/modified CVEs since last sync.
   - `getLastSyncDate(): Optional<String>` — reads from a `meta` table (`key='last_sync'`).
3. Add an `update-db` subcommand to `ScanCommand` (Picocli `@Command` can have subcommands):
   ```java
   @Command(name = "update-db", description = "Download/update local CVE database from NVD")
   static class UpdateDbCommand implements Callable<Integer> { ... }
   ```
4. Modify `CveLookup.lookup()`: check if local DB exists first; if yes, query it; fall back to live NVD API call.
5. Print progress during sync: `Syncing CVEs: 12,400 / 250,000...`.

**Done when:**
- `portscanner update-db` downloads CVEs into `~/.portscanner/cve-db.sqlite`.
- `--cve` on a host with OpenSSH open returns CVEs from the local database without any HTTP calls.
- Second run of `--cve` is instant (cached).

---

### TASK-18: JLine3 Interactive Progress

**Priority:** P3 | **Effort:** 1-2 days | **Deps:** `org.jline:jline:3.26.3` (~1.5 MB)

**Goal:** Replace the `\r` carriage-return progress bar (TASK-04) with a persistent JLine3 status line at the bottom of the terminal while scan results scroll above, and add keyboard shortcuts.

**Files to modify:**
- `pom.xml` — add `jline` dependency
- `src/main/java/com/portscanner/cli/ProgressReporter.java` — upgrade to JLine3
- `src/main/java/com/portscanner/cli/ScanCommand.java` — initialize JLine terminal

**Steps:**
1. Add to `pom.xml`:
   ```xml
   <dependency>
       <groupId>org.jline</groupId>
       <artifactId>jline</artifactId>
       <version>3.26.3</version>
   </dependency>
   ```
2. In `ScanCommand`, before scanning:
   ```java
   Terminal terminal = TerminalBuilder.builder().system(true).build();
   ```
   Fall back gracefully if terminal creation fails (not a TTY → use Phase 1 progress bar from TASK-04).
3. Use `Status.getStatus(terminal)` to attach a sticky status line at the bottom. Update it from the `ProgressReporter` tick.
4. Add a non-blocking key reader: `NonBlockingReader reader = terminal.reader()`. On each tick, check for:
   - `P` or `p` → pause/resume (set `AtomicBoolean paused` in `PortScanner`)
   - `Q` or `q` → graceful shutdown (interrupt the executor)
   - `+` → increase thread count by 10
   - `-` → decrease thread count by 10 (floor: 1)
5. `PortScanner` needs a `pause()` / `resume()` method: `paused.set(true)` causes each `scanPort()` call to spin-wait until `paused.set(false)`.

**Done when:**
- Status line stays at the bottom while open ports print above.
- `P` key pauses the scan (port scanning stops, then resumes on next `P`).
- `Q` key exits cleanly (current in-flight ports finish, no more are started).
- Falls back to TASK-04 progress bar when JLine terminal is unavailable.

---

### TASK-19: Plugin/Script System `--scripts`

**Priority:** P3 | **Effort:** 2 days | **Deps:** None (uses Java `ServiceLoader`)

**Goal:** Define a plugin interface so built-in and third-party plugins can enrich scan results — similar to nmap NSE scripts.

**Files to create:**
- `src/main/java/com/portscanner/plugin/ScanPlugin.java` — interface
- `src/main/java/com/portscanner/plugin/PluginContext.java` — data carrier
- `src/main/java/com/portscanner/plugin/PluginRegistry.java` — loader
- `src/main/java/com/portscanner/plugin/builtin/HttpTitlePlugin.java`
- `src/main/java/com/portscanner/plugin/builtin/SslCertPlugin.java`
- `src/main/java/com/portscanner/plugin/builtin/SshVersionPlugin.java`
- `src/main/resources/META-INF/services/com.portscanner.plugin.ScanPlugin` — ServiceLoader descriptor

**Files to modify:**
- `src/main/java/com/portscanner/cli/ScanCommand.java` — add `--scripts` option

**Steps:**
1. Define the interface:
   ```java
   public interface ScanPlugin {
       String name();                                  // e.g. "http-title"
       boolean appliesTo(ScanResult result);           // filter: only HTTP ports
       void execute(ScanResult result, PluginContext ctx);
   }
   ```
2. Create `PluginContext` — carries `host`, `timeout`, `ScannerConfig`, and a `PrintStream` for plugin output.
3. Create `PluginRegistry`:
   - `load()`: `ServiceLoader.load(ScanPlugin.class)` discovers all implementations on classpath.
   - `getByName(String name)`: filter by `plugin.name().equalsIgnoreCase(name)`.
   - `getAll()`: returns all loaded plugins.
4. Implement `HttpTitlePlugin`:
   - `appliesTo()`: returns true when `result.getServiceName()` contains `http`.
   - `execute()`: open socket, send `GET / HTTP/1.1\r\nHost: ...\r\n\r\n`, read body until `</title>`, extract title text, set `result.setBanner("Title: " + title)`.
5. Implement `SslCertPlugin`:
   - `appliesTo()`: returns true when port is 443, 8443, or any port with `https` service name.
   - `execute()`: reuse `TlsInspector.inspect()` from TASK-06, set `result.setTlsInfo(tlsInfo)`.
6. Implement `SshVersionPlugin`:
   - `appliesTo()`: returns true when service name contains `ssh`.
   - `execute()`: read the SSH banner (already available from `BannerGrabber`), parse `SSH-2.0-OpenSSH_8.9` format, set version string.
7. In `ScanCommand`, add:
   ```java
   @Option(names = "--scripts",
           description = "Comma-separated plugin names to run, or 'all'. E.g. --scripts http-title,ssl-cert")
   private String scripts;
   ```
   After scanning, load `PluginRegistry`, filter requested plugins, run `execute()` on matching results.
8. Register built-ins in `META-INF/services/com.portscanner.plugin.ScanPlugin`.

**Done when:**
- `--scripts all` runs all three built-in plugins.
- `--scripts http-title` only runs `HttpTitlePlugin` on HTTP ports.
- A third-party JAR with a `ScanPlugin` implementation placed on the classpath is auto-discovered.
- `PluginRegistryTest` verifies ServiceLoader finds built-in plugins.

---

## Phase 6 — Future Major Features

---

### TASK-20: Lanterna Full-Screen TUI `--tui`

**Priority:** P4 | **Effort:** 2-3 days | **Deps:** `com.googlecode.lanterna:lanterna:3.1.2` (~400 KB)

**Goal:** Full-screen terminal UI with panels for scan progress, live open-port results table, service stats, and a log console.

**High-level layout:**
```
┌──────────────────────────────────────────────────────────┐
│  Port Scanner 2.0 — Scanning 192.168.1.1 (1-1024)       │
├──────────────────┬───────────────────────────────────────┤
│  Progress        │  Open Ports                           │
│  [=====>   ] 50% │  PORT    SERVICE      BANNER          │
│  512/1024 ports  │  22      SSH          OpenSSH 8.9     │
│  24 OPEN         │  80      HTTP         Apache/2.4      │
│  341 p/s         │  443     HTTPS        nginx/1.24      │
│  ETA: 1.5s       │                                       │
├──────────────────┴───────────────────────────────────────┤
│  Log: [21:30:12] Port 80 OPEN — Apache/2.4.57            │
└──────────────────────────────────────────────────────────┘
```

**Key implementation points:**
- `WindowBasedTextGUI` with two panels in a `LinearLayout`.
- `AnimatedLabel` for the progress bar.
- `Table<String>` for live open-port results, updated via `gui.getGUIThread().invokeLater()`.
- Fall back to Phase 1 progress bar (`TASK-04`) when `--tui` is absent.
- Exit on `Escape` or `Q`.

---

### TASK-21: IPv6 Scanning

**Priority:** P4 | **Effort:** 2 days | **Deps:** `com.github.seancfoley:ipaddress:5.4.0`

**Goal:** Support `--host 2001:db8::1` and `--subnet 2001:db8::/32` for IPv6 targets.

**Key implementation points:**
- TCP connect scan already works with IPv6 via `InetAddress.getByName()` — the scanner is already IPv6-capable for single hosts.
- Gap: CIDR enumeration. `CidrScanner` uses bitwise int arithmetic that only works for IPv4. Replace with `ipaddress` library's `IPAddressSeqRange` to enumerate IPv6 CIDR blocks.
- NDP neighbor cache reading (replaces ARP): `ip -6 neigh show` via `ProcessBuilder` on Linux; `netsh interface ipv6 show neighbors` on Windows.
- Add `--ipv6` flag that prefers IPv6 addresses when resolving hostnames with both A and AAAA records.

---

### TASK-22: DNS Subdomain Brute-Force `--dns-brute`

**Priority:** P4 | **Effort:** 1 day | **Deps:** `dnsjava:org.dnsjava:dnsjava:3.6.1`

**Goal:** Enumerate subdomains of a target domain using a wordlist.

**Key implementation points:**
- Accept `--dns-brute /path/to/wordlist.txt` and a domain via `--host example.com`.
- For each word in the wordlist, resolve `{word}.example.com` using dnsjava's async `Resolver`.
- Run resolutions in parallel (virtual threads from TASK-01 work here too).
- Collect results: for each word that resolves, print the subdomain and IP.
- Bundle a small default wordlist (`top-1000-subdomains.txt`) in `src/main/resources`.

---

### TASK-23: GitHub Actions CI Pipeline

**Priority:** P3 | **Effort:** 4 hours | **Deps:** None

**Goal:** Automate build, test, and release on every push.

**Files to create:**
- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`

**Steps:**
1. `ci.yml` — triggered on `push` and `pull_request` to `main`:
   - Job `build`: runs `mvn verify` on `ubuntu-latest` and `windows-latest` with JDK 21.
   - Job `security`: runs `mvn org.owasp:dependency-check-maven:check` to flag vulnerable dependencies.
2. `release.yml` — triggered on tag push `v*`:
   - Build fat JAR: `mvn package -DskipTests`.
   - Upload `port-scanner-*.jar` as a GitHub Release asset.
3. Add `macos-latest` to the build matrix.

**Done when:**
- Every push to `main` shows a green check.
- A tag `v2.1.0` creates a GitHub Release with the fat JAR attached.

---

### TASK-24: Integration Tests (Testcontainers)

**Priority:** P3 | **Effort:** 1-2 days | **Deps:** `testcontainers-core`, `testcontainers-junit-jupiter`

**Goal:** Test the scanner against real services running in Docker containers to catch regressions that unit tests with `ServerSocket` stubs cannot detect.

**Files to create:**
- `src/test/java/com/portscanner/integration/SshScanIntegrationTest.java`
- `src/test/java/com/portscanner/integration/HttpScanIntegrationTest.java`
- `src/test/java/com/portscanner/integration/RedisScanIntegrationTest.java`

**Steps:**
1. Add Testcontainers to `pom.xml` in the `test` scope.
2. Bind integration tests to the `verify` lifecycle phase (`failsafe-plugin`), not `test` — so `mvn test` stays fast.
3. `SshScanIntegrationTest`: spin up `linuxserver/openssh-server` container. Assert that scanning its exposed port returns `OPEN` status and a banner containing `SSH-2.0-OpenSSH`.
4. `HttpScanIntegrationTest`: spin up `nginx:alpine`. Assert port 80 is `OPEN`, service name is `HTTP`, and `--http` detects `nginx` in the Server header.
5. `RedisScanIntegrationTest`: spin up `redis:7-alpine`. Assert port 6379 is `OPEN` and `--probes` returns a banner containing `Redis`.
6. Tag integration tests with `@Tag("integration")` and configure Surefire to exclude them; Failsafe to include them.

**Done when:**
- `mvn test` runs in under 30 seconds (no containers).
- `mvn verify` runs all integration tests and passes.
- CI pipeline (TASK-23) runs `mvn verify` to include integration tests.

---

## Known Java Limitations — Do Not Attempt

These features are frequently requested but are technically impossible in pure Java without native code or root privileges:

| Feature | Why It's Blocked | Acceptable Alternative |
|---------|-----------------|----------------------|
| SYN scan | Raw sockets require root + JNI (Pcap4J) | TCP connect scan (already in use) |
| FIN / XMAS / NULL scan | Raw sockets; unreliable on Windows | Document in `--help` |
| IP spoofing / decoy scan | OS kernel enforces source IP | Proxy chaining (`--proxy`) |
| ICMP-based traceroute | Java cannot receive ICMP Time Exceeded on user sockets | `ProcessBuilder traceroute` (TASK-14) |
| ARP scan (active) | Layer 2 — requires libpcap/Npcap | Read ARP cache via `ProcessBuilder arp -a` |
| Packet capture / sniffing | Requires elevated privileges + Pcap4J | Not within scope of this tool |
| TCP window size fingerprinting | JDK `Socket` does not expose received IP headers | ProcessBuilder ping TTL heuristic (low accuracy) |

---

*Only scan systems you own or have explicit written permission to scan.*
