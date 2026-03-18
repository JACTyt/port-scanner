# Java Port Scanner — Enhancement Plan v5

> **Status:** All v1–v4 enhancements are fully implemented (see git log).
> This document is a fresh iteration. Everything listed here is **not yet implemented**.

---

## Already Implemented — Do Not Re-Implement

TCP/UDP scanning · Virtual threads (Java 21) · CIDR/subnet scanning · Auto-discover ·
Host discovery · Timing profiles T0–T5 · Top-ports list · Rate limiting · Banner grabbing ·
Protocol-specific probes (HTTP, SSH, FTP, SMTP, MySQL, PostgreSQL, Redis, Memcached) ·
TLS inspection · HTTP header analysis · CVE lookup (NVD API + local SQLite) · AbuseIPDB ·
GreyNoise · IPinfo geolocation · ASN lookup · Reverse DNS · SOCKS5 proxy · Traceroute ·
DNS subdomain brute-force · IPv6 scanning · Plugin system (http-title, ssl-cert, ssh-version) ·
External plugin loading (URLClassLoader + ServiceLoader from ~/.portscanner/plugins/) ·
JLine3 progress bar · Lanterna TUI (with fallback) · ANSI color output · SLF4J/Logback logging ·
YAML config file · Scan profiles · Scan history database (SQLite) · Service version extraction ·
Multi-host file scanning (--hosts-file) · OS/TTL fingerprinting · SNMP scanning (SNMPv2c) ·
Watch/scheduled mode · REST API server (JDK HttpServer) · Webhook notifications (Slack/Discord/custom) ·
Nmap-XML output (Metasploit db_import compatible) · Metasploit .rc resource scripts ·
HTML/XML/CSV/JSON/TXT/Markdown/PDF exporters · Network topology (Graphviz DOT / Mermaid) ·
Diff mode · Interactive REPL shell (JLine3) · Testcontainers integration tests ·
GitHub Actions CI · GraalVM native profile in pom.xml · Docker + docker-run scripts ·
jpackage installers (Windows MSI, Linux .deb/.rpm)

---

## Task Summary

| Task | Name | Priority | Effort |
|------|------|----------|--------|
| [BUG-05](#bug-05-tui-broken-on-windows) | Fix TUI on Windows | P0 | 4h |
| [TASK-19](#task-19-sarif-export) | SARIF 2.1.0 export (GitHub Security tab) | P1 | 4h |
| [TASK-20](#task-20-junit-xml-export--ci-policy-gates) | JUnit XML export + CI policy gates `--fail-on-open` | P1 | 4h |
| [TASK-21](#task-21-shodan-internetdb-enrichment) | Shodan InternetDB enrichment (free, no key) | P1 | 4h |
| [TASK-22](#task-22-tls-deep-audit) | TLS deep audit (cipher enumeration, weak-cipher/vuln detection) | P2 | 2 days |
| [TASK-23](#task-23-ssh-algorithm-audit) | SSH algorithm audit (parse Key Exchange Init) | P2 | 1 day |
| [TASK-24](#task-24-http-security-header-scoring) | HTTP security header scoring (OWASP Observatory model) | P2 | 1 day |
| [TASK-25](#task-25-certificate-transparency-recon) | Certificate Transparency recon via crt.sh | P2 | 4h |
| [TASK-26](#task-26-unauthenticated-service-detection) | Unauthenticated service detection (Redis, FTP anon, Elasticsearch…) | P3 | 1 day |
| [TASK-27](#task-27-dns-security-checks) | DNS security checks (AXFR zone transfer, open resolver) | P3 | 1 day |
| [TASK-28](#task-28-two-phase-scan-pipeline) | Two-phase scan pipeline (`--quick` → `--deep`) | P3 | 1 day |
| [TASK-29](#task-29-cvss-score-enrichment) | CVSS score enrichment for matched CVEs | P3 | 4h |
| [TASK-30](#task-30-nuclei-yaml-template-loader) | Nuclei YAML template loader | P4 | 3 days |
| [TASK-31](#task-31-scan-agent--distributed-mode) | Scan agent / distributed scanning mode | P4 | 3 days |
| [TASK-32](#task-32-excelxlsx-export) | Excel/XLSX export | P4 | 4h |

---

## Bug Fixes

---

### BUG-05: TUI Broken on Windows

**Priority:** P0 | **Effort:** 4h

**Problem:** Lanterna fails to initialize in Windows CMD / PowerShell / Windows Terminal when
launched via `java.exe`. The `WindowsTerminal` backend (JNA) does not initialize correctly inside
a shaded JAR, and the Swing fallback is blocked. The scanner currently falls back to the JLine3
progress bar automatically, but `--tui` produces a warning instead of a working full-screen display.

**Root cause:** Lanterna 3.1.2's `DefaultTerminalFactory.createTerminal()` on Windows falls through
to a code path that requires either the JNA Windows Console API (broken in fat JARs) or
`javaw.exe` (no stdout). Neither is suitable for a CLI tool.

**Recommended fix — Replace Lanterna with pure ANSI escape codes:**
- Remove Lanterna dependency entirely
- Implement a lightweight `AnsiTui` class using raw VT100/VT220 escape sequences written to `System.out`
- Windows Terminal and modern CMD both support VT100 since Windows 10 v1511
- Activate VT processing on Windows via a `kernel32.dll` JNA call:
  `SetConsoleMode(handle, ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT)`
- Eliminates 3 dependencies (`lanterna`, `jna`, `jna-platform`) — saves ~5MB from the JAR
- No new dependencies required

**What to change:**
- `TuiProgressDisplay.java` — replace Lanterna `Screen`/`MultiWindowTextGUI` with VT100 escape sequences
- `pom.xml` — remove `lanterna`, `jna`, `jna-platform` dependencies
- `BUGS.md` — remove entry when resolved

**Verify:** `.\run.bat --host localhost --tui` on Windows Terminal shows a working full-screen layout without any fallback warning.

---

## P1 — High Priority

---

### TASK-19: SARIF 2.1.0 Export

**Priority:** P1 | **Effort:** 4h | **New deps:** None

**Value:** SARIF (Static Analysis Results Interchange Format, OASIS standard) is the universal
interchange format for security findings. GitHub's Security tab accepts SARIF files uploaded via
`github/codeql-action/upload-sarif`. DefectDojo, Azure DevOps, VS Code, and Snyk all consume it.
Adding SARIF output instantly makes the scanner compatible with the entire modern security toolchain.

**What SARIF enables:**
- Upload scan results to the GitHub Security > Code Scanning tab with zero extra tooling
- Import into DefectDojo, Faraday, and all OASIS-compliant vulnerability management platforms
- VS Code extensions display findings inline in the editor

**CLI addition:**
```
--format sarif         Export as SARIF 2.1.0 JSON
-o report.sarif        Extension also selects SARIF exporter
```

**SARIF structure to generate:**
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "port-scanner", "version": "1.0", "rules": [...] } },
    "results": [
      {
        "ruleId": "OPEN_PORT",
        "level": "warning",
        "message": { "text": "Port 22/SSH is open" },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": "tcp://192.168.1.1:22" }
          }
        }],
        "properties": { "service": "SSH", "banner": "OpenSSH 8.9", "cves": ["CVE-2023-38408"] }
      }
    ]
  }]
}
```

- Each open port → one `result` entry with `level` based on associated CVEs (error if CVSS ≥ 7.0, warning otherwise, note for informational)
- Each unique CVE → one `rule` entry in `driver.rules[]` with CVE description and CVSS as tags
- `artifactLocation.uri` uses `tcp://host:port` scheme (SARIF allows any URI)

**What to create:**
- `report/SarifExporter.java` — implements `ReportExporter`; serializes `ScanReport` → SARIF 2.1.0 JSON via Jackson
- `ExporterFactory.java` — add `.sarif` extension and `sarif` format string
- `ScanCommand.java` — document `--format sarif` in `--format` help text

**GitHub Actions integration example** (document in README):
```yaml
- name: Port scan
  run: java -jar port-scanner.jar --host $HOST --ports 1-1024 --cve -o results.sarif --format sarif

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

**Verify:** Upload generated `.sarif` to the SARIF validator at `https://sarifweb.azurewebsites.net/` — must pass validation. Import into a local DefectDojo instance.

---

### TASK-20: JUnit XML Export + CI Policy Gates

**Priority:** P1 | **Effort:** 4h | **New deps:** None

**Value:** JUnit XML is the universal test result format understood by every CI platform: Jenkins,
GitLab CI, CircleCI, Azure DevOps, GitHub Actions, TeamCity. Modeling open ports as "failed tests"
and policy violations as "test failures" gives immediate red/green gate status in any pipeline —
without SARIF support and without custom parsing.

**Two features in one task:**

**Feature A — JUnit XML exporter:**
Each open port is a `<testcase>`. If the port is in a blocklist or a CVE is attached, the test fails
(`<failure>` element). A port that is expected to be open (allowlist) passes.

```xml
<testsuite name="port-scanner" tests="3" failures="1" timestamp="2026-03-18T10:00:00">
  <testcase classname="192.168.1.1" name="port-22-SSH" time="0.012"/>
  <testcase classname="192.168.1.1" name="port-23-Telnet" time="0.005">
    <failure message="Port 23 (Telnet) is open — unencrypted protocol">
      Banner: +OK Telnet ready. CVEs: none.
    </failure>
  </testcase>
  <testcase classname="192.168.1.1" name="port-80-HTTP" time="0.010"/>
</testsuite>
```

**Feature B — Policy gates (`--fail-on-open`, `--policy-file`):**

```
--fail-on-open <port[,port…]>   Exit code 1 if any of these ports are found open.
                                 Useful in CI: fail the build if port 22 is open on a prod host.
--policy-file <path>            YAML policy rules evaluated post-scan. Overrides --fail-on-open.
```

**Policy file format** (`~/.portscanner/policy.yaml`):
```yaml
rules:
  - name: "No Telnet"
    port: 23
    state: OPEN
    action: FAIL          # FAIL | WARN | INFO
    message: "Telnet is unencrypted — disable it"

  - name: "No anonymous FTP"
    port: 21
    state: OPEN
    service: FTP
    action: WARN

  - name: "Must have HTTPS"
    port: 443
    state: OPEN
    action: PASS_IF_PRESENT   # FAIL if this port is NOT open
```

**Exit codes:**
- `0` — scan completed, no policy failures
- `1` — at least one `FAIL` rule triggered
- `2` — scan error (unreachable host, timeout, etc.)

**What to create:**
- `report/JUnitXmlExporter.java` — implements `ReportExporter`; generates JUnit XML
- `config/PolicyRule.java` + `config/PolicyLoader.java` — policy model + YAML loader
- `config/PolicyEvaluator.java` — evaluates rules against a `ScanReport`, returns violations
- `ScanCommand.java` — `--fail-on-open` and `--policy-file` options; evaluate policy before exit
- `ExporterFactory.java` — add `.xml-junit` / `junit` format

**Verify:** Run with `--fail-on-open 23` against a host with port 23 open — exit code must be 1.
Confirm JUnit XML is accepted by `actions/upload-artifact` + `dorny/test-reporter` GitHub Action.

---

### TASK-21: Shodan InternetDB Enrichment

**Priority:** P1 | **Effort:** 4h | **New deps:** None (JDK `HttpClient`)

**Value:** Shodan's `internetdb.shodan.io` API is free, requires no API key, and returns open ports,
hostnames, CVEs, and tags for any IP in under 100ms. It provides independent corroboration of scan
results and surfaces CVEs that the NVD API lookup might miss (Shodan matches banners against its own
CVE correlation engine). This is the single highest-value zero-cost enrichment to add.

**API:**
```
GET https://internetdb.shodan.io/{ip}
Response:
{
  "ip": "93.184.216.34",
  "ports": [80, 443],
  "cpes": ["cpe:/a:apache:http_server:2.4.51"],
  "hostnames": ["example.com"],
  "tags": ["self-signed"],
  "vulns": ["CVE-2021-41773", "CVE-2021-42013"]
}
```

**CLI addition:**
```
--shodan      Enrich results with Shodan InternetDB data (no API key required)
              Adds Shodan-seen ports, CPEs, and CVEs to the report
```

**Comparison output (high value):**
When `--shodan` is used, the report shows a comparison:
```
Shodan sees: 80, 443
This scan:   22, 80, 443, 8080
Delta:       Port 22 and 8080 not in Shodan index (recently opened or Shodan hasn't scanned yet)
```

**What to create:**
- `service/ShodanInternetDbClient.java` — `ShodanResult query(String ip)` via `java.net.http.HttpClient`
- `model/ShodanResult.java` — `@Data @Builder`: `List<Integer> ports`, `List<String> cpes`, `List<String> vulns`, `List<String> tags`
- Merge `vulns` into `ScanReport.cves` list; add `shodanPorts` field to `ScanReport` for the comparison
- Display in text output: "Shodan: X CVEs, last seen ports: ..." line in the header block
- `ScanCommand.java` — `--shodan` flag

**Shodan for full API key (optional follow-up):**
For users with a Shodan API key (`SHODAN_KEY` env var), also call:
- `GET /shodan/host/{ip}` — full banner data, all historical ports, ISP/org details

**Verify:** Run `--host 8.8.8.8 --shodan`. Must return Google's DNS service tags. Run against `--subnet` — one call per resolved IP.

---

## P2 — Medium Priority

---

### TASK-22: TLS Deep Audit

**Priority:** P2 | **Effort:** 2 days | **New deps:** Bouncy Castle ~4MB (for ClientHello crafting) or pure JSSE

**Value:** The existing `--tls` flag retrieves the server certificate and basic info. A deep TLS audit
goes much further: enumerating which protocol versions and cipher suites the server accepts, and
detecting known vulnerabilities. This is what `testssl.sh` and `sslyze` do and is one of the most
requested features in security tooling.

**What to detect:**

| Check | How | Severity |
|-------|-----|----------|
| SSLv2/SSLv3 enabled | Send SSLv2/v3 ClientHello, check if server responds | CRITICAL |
| TLS 1.0/1.1 enabled | Negotiate TLS 1.0/1.1, check if server accepts | HIGH |
| Weak ciphers (RC4, NULL, EXPORT, DES, 3DES) | Offer only that cipher in ClientHello | HIGH |
| Anonymous Diffie-Hellman (no authentication) | Offer ADH cipher suites | CRITICAL |
| BEAST (TLS 1.0 + CBC cipher) | Detect TLS 1.0 + CBC = BEAST possible | MEDIUM |
| POODLE (SSLv3 + CBC) | SSLv3 enabled + CBC cipher = POODLE | HIGH |
| HEARTBLEED (CVE-2014-0160) | Send malformed heartbeat extension, check for overread | CRITICAL |
| SWEET32 (3DES birthday attack) | 3DES cipher accepted | MEDIUM |
| CRIME/BREACH (compression) | Check if TLS compression enabled | MEDIUM |
| Weak certificate signature (SHA-1/MD5) | Already in TlsInfo — expose in audit report | MEDIUM |
| Certificate key size < 2048-bit RSA / < 256-bit ECC | Already parseable from cert | MEDIUM |
| Certificate expired or expiring within 30 days | Already in TlsInfo | HIGH |

**Cipher suite enumeration approach (JSSE without Bouncy Castle):**
```java
SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(null, TRUST_ALL, null);
SSLEngine engine = ctx.createSSLEngine(host, port);
String[] supported = engine.getSupportedCipherSuites();
// For each cipher, try to establish connection with only that cipher enabled
// If handshake succeeds → server accepts this cipher
```

**Heartbleed probe (requires raw bytes):**
Heartbleed is triggered by sending a TLS `heartbeat` extension request with `payload_length` > actual payload. Server responds with memory contents if vulnerable. This requires crafting a raw TLS record (24 bytes) — implementable via raw `Socket` without Bouncy Castle.

**CLI addition:**
```
--tls-deep     Full TLS audit: enumerate cipher suites and check known vulnerabilities.
               Implies --tls. Adds significant latency (one connection per cipher tested).
```

**What to create:**
- `scanner/TlsAuditor.java` — `TlsAuditResult audit(String host, int port, int timeoutMs)`
- `model/TlsAuditResult.java` — `List<String> acceptedCiphers`, `List<String> weakCiphers`, `List<TlsVulnerability> vulnerabilities`, `List<String> supportedProtocols`
- `model/TlsVulnerability.java` — `name`, `cve`, `severity`, `description`
- Add `tlsAudit` field to `ScanResult`; display in text/HTML output as a collapsible section
- Heartbleed probe as a separate `HeartbleedProbe` implementing `Probe` interface

**Verify:** Run against a test server with known weak config (e.g., `badssl.com` subdomains: `tls-v1-0.badssl.com`, `rc4.badssl.com`, `expired.badssl.com`).

---

### TASK-23: SSH Algorithm Audit

**Priority:** P2 | **Effort:** 1 day | **New deps:** None

**Value:** SSH servers advertise their supported key exchange, encryption, MAC, and host-key
algorithms in the `Key Exchange Init` (`SSH_MSG_KEXINIT`) message — sent in cleartext immediately
after the version banner. Parsing it reveals weak algorithms without establishing an authenticated
session. This is exactly what tools like `ssh-audit` do and is a common finding in security audits.

**Algorithms to flag as weak:**

| Category | Weak (flag these) | Strong (recommend these) |
|----------|-------------------|--------------------------|
| Key exchange | `diffie-hellman-group1-sha1` (Logjam), `diffie-hellman-group-exchange-sha1` | `curve25519-sha256`, `ecdh-sha2-nistp256` |
| Host key | `ssh-dss` (DSA 1024-bit), `ssh-rsa` with SHA-1 | `ssh-ed25519`, `rsa-sha2-256` |
| Encryption | `arcfour` (RC4), `3des-cbc`, `blowfish-cbc`, `aes128-cbc` | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com` |
| MAC | `hmac-md5`, `hmac-sha1`, `umac-64@openssh.com` | `hmac-sha2-256`, `umac-128-etm@openssh.com` |

**Implementation — no SSH library needed:**
The SSH protocol exchange is:
1. Client → Server: `SSH-2.0-OpenSSH_9.0\r\n` (version string)
2. Server → Client: version string
3. Server → Client: `SSH_MSG_KEXINIT` packet (binary, but immediately readable)

The `KEXINIT` packet structure is documented in RFC 4253 §7.1. Parsing it requires reading a binary length-prefixed stream from a plain `Socket`, no authentication or key exchange needed.

```
byte      SSH_MSG_KEXINIT (= 20)
byte[16]  cookie (random)
name-list kex_algorithms
name-list server_host_key_algorithms
name-list encryption_algorithms_client_to_server
name-list encryption_algorithms_server_to_client
name-list mac_algorithms_client_to_server
...
```

**CLI addition:**
```
--ssh-audit    Parse SSH Key Exchange Init and flag weak algorithms (requires --banner or port 22 open)
```

**What to create:**
- `scanner/SshAuditor.java` — `SshAuditResult audit(String host, int port, int timeoutMs)`; opens raw socket, sends version string, reads and parses `KEXINIT`
- `model/SshAuditResult.java` — `String serverVersion`, `List<String> kexAlgorithms`, `List<String> weakAlgorithms`, `List<String> recommendations`
- Add `sshAudit` field to `ScanResult`; surface in text/HTML output
- Invoke from `ScanCommand` when port 22 (or any detected SSH port) is open and `--ssh-audit` is set

**Reference:** `ssh-audit` by `jtesta` (Python, MIT license) contains a complete algorithm weakness database as a reference.

**Verify:** Run against a modern OpenSSH 9.x server. Should show clean results. Run against a legacy SSH server (e.g., OpenSSH 6.x) — should flag weak kex algorithms.

---

### TASK-24: HTTP Security Header Scoring

**Priority:** P2 | **Effort:** 1 day | **New deps:** None

**Value:** The Mozilla Observatory grades websites on their HTTP security headers. Security teams
routinely run Observatory scans on web applications. Integrating a similar check directly into the
port scanner — triggered automatically on any open HTTP/HTTPS port — provides instant security
posture feedback without requiring a separate tool.

**Headers to evaluate (OWASP Secure Headers Project):**

| Header | Max deduction if missing | Notes |
|--------|--------------------------|-------|
| `Strict-Transport-Security` (HSTS) | -20 | Only applicable to HTTPS |
| `Content-Security-Policy` (CSP) | -25 | Presence alone is insufficient — inspect directives |
| `X-Frame-Options` | -20 | Or CSP `frame-ancestors` directive |
| `X-Content-Type-Options: nosniff` | -10 | Simple on/off |
| `Referrer-Policy` | -10 | Many valid values |
| `Permissions-Policy` | -5 | (formerly Feature-Policy) |
| `Cross-Origin-Opener-Policy` (COOP) | -5 | |
| `Cross-Origin-Resource-Policy` (CORP) | -5 | |

**Information disclosure headers (flag as findings):**
- `Server: Apache/2.4.51` — discloses version (flag as INFO)
- `X-Powered-By: PHP/7.4.3` — discloses language + version (flag as LOW)
- `X-AspNet-Version` — discloses .NET version (flag as LOW)

**Scoring model:**
- Start at 100
- Deduct per missing or misconfigured header
- Grade: A+ (≥95), A (≥85), B (≥70), C (≥55), D (≥30), F (<30)

**What to create:**
- `scanner/HttpSecurityAuditor.java` — `HttpSecurityAuditResult audit(String host, int port, boolean tls)`; fetches `/` via `HttpURLConnection`, parses response headers
- `model/HttpSecurityAuditResult.java` — `int score`, `String grade`, `List<HeaderFinding> findings`
- `model/HeaderFinding.java` — `String header`, `String value`, `Severity severity`, `String recommendation`
- Add `httpSecurityAudit` field to `ScanResult`; surface in HTML report as a grade badge and in text output as a one-line summary
- Auto-invoke when `--http` flag is set and an HTTP/HTTPS port is open

**Verify:** Scan `example.com` — should get a grade F or D (no security headers). Scan a well-configured site like `mozilla.org` — should get A or A+.

---

### TASK-25: Certificate Transparency Recon

**Priority:** P2 | **Effort:** 4h | **New deps:** None (JDK `HttpClient`)

**Value:** Certificate Transparency logs record every TLS certificate ever issued for a domain.
Querying these logs via `crt.sh` reveals subdomains that:
- Are not in public DNS (internal hostnames that leaked via certificate)
- Were previously exposed before moving behind a CDN
- Belong to third-party services (SaaS, cloud providers) associated with the domain

This is a staple of passive reconnaissance and finds targets that DNS brute-force misses entirely.

**API:**
```
GET https://crt.sh/?q=%.example.com&output=json
Response: [{"issuer_ca_id":...,"name_value":"sub.example.com","not_before":"...","not_after":"..."}]
```

**CLI addition:**
```
--ct-recon <domain>    Query Certificate Transparency logs (crt.sh) for subdomains of <domain>.
                       Discovered hosts are added to the scan queue automatically.
                       Can be combined with --ports and all other scan flags.
```

**Workflow:**
1. Query `crt.sh` for `%.domain` and `domain`
2. Deduplicate hostnames from `name_value` field (strip wildcard `*.` prefixes)
3. Resolve each hostname via DNS (discard unresolvable)
4. Feed resolved IPs into the existing `MultiHostScanner` scan queue
5. Show a summary: "CT recon found 47 subdomains; 32 resolved; scanning..."

**What to create:**
- `service/CertTransparencyClient.java` — `List<String> findSubdomains(String domain)` via JDK `HttpClient`
- `model/CtLogEntry.java` — `nameValue`, `notBefore`, `notAfter`, `issuerCaId`
- Deduplication + wildcard stripping logic
- `ScanCommand.java` — `--ct-recon <domain>` flag; integrate with `MultiHostScanner`
- Display discovered subdomains before scan begins

**Config:**
```yaml
ctReconSources:
  - "https://crt.sh/?q=%25.{domain}&output=json"      # public crt.sh
```

**Verify:** Run `--ct-recon example.com`. Must return at least `www.example.com`. Verify deduplication handles wildcard entries correctly.

---

## P3 — Nice to Have

---

### TASK-26: Unauthenticated Service Detection

**Priority:** P3 | **Effort:** 1 day | **New deps:** None

**Value:** Open databases and services accepting connections without credentials are a critical
finding in any security audit. Many tools scan for these separately; integrating detection directly
into the port scanner avoids a second pass. Detection requires only trivial protocol probes — no
credentials or libraries needed.

**Services to detect and how:**

| Service | Port | Probe | Indicator of unauth access |
|---------|------|-------|---------------------------|
| Redis | 6379 | `PING\r\n` | Response `+PONG\r\n` |
| Memcached | 11211 | `stats\r\n` | Response starts with `STAT ` |
| MongoDB | 27017 | `isMaster` BSON command | BSON response without `errmsg: "not authorized"` |
| Elasticsearch | 9200 | `GET /` HTTP | JSON response with `cluster_name` |
| CouchDB | 5984 | `GET /` HTTP | JSON with `"couchdb":"Welcome"` |
| FTP | 21 | `USER anonymous\r\nPASS anon@\r\n` | Response `230 ` (login successful) |
| PostgreSQL | 5432 | Send `StartupMessage` with `user=postgres` | `AuthenticationOk` without password prompt |
| Kubernetes API | 6443/8080 | `GET /api` HTTP | JSON with `apiVersion` without 401 |
| Prometheus | 9090 | `GET /metrics` HTTP | Metrics output (text/plain) |
| Spring Actuator | 8080/8443 | `GET /actuator` HTTP | JSON `_links` response |

**CLI addition:**
```
--unauth-detect    After TCP scan, probe open service ports for unauthenticated access.
                   Auto-selects appropriate probe per detected service.
```

**What to create:**
- `scanner/UnauthDetector.java` — dispatches `UnauthProbe` per open port based on detected service
- `scanner/probe/UnauthProbe.java` (interface) — `UnauthResult probe(String host, int port, int timeoutMs)`
- Implementations: `RedisUnauthProbe`, `MemcachedUnauthProbe`, `MongoUnauthProbe`, `ElasticsearchUnauthProbe`, `FtpAnonProbe`, `PromUnauthProbe`, `ActuatorUnauthProbe`
- `model/UnauthResult.java` — `boolean isUnauthenticated`, `String evidence`, `Severity severity`
- Add `unauthResult` to `ScanResult`; display prominently (red) in all output formats
- Auto-invoke when `--unauth-detect` flag is set; no additional output when all probes return false

**Severity classification:**
- CRITICAL: Redis unauth, MongoDB unauth, Elasticsearch unauth (direct data access)
- HIGH: FTP anonymous, PostgreSQL no-password, Kubernetes API
- MEDIUM: Prometheus metrics, Spring Actuator

**Verify:** Spin up a `docker run -p 6379:6379 redis:alpine` (no auth), run `--unauth-detect` — must report Redis as unauthenticated.

---

### TASK-27: DNS Security Checks

**Priority:** P3 | **Effort:** 1 day | **New deps:** None (dnsjava already in pom.xml)

**Value:** DNS misconfigurations are among the most impactful findings in external recon. Zone
transfers expose the entire DNS zone; open resolvers are DDoS amplifiers. Both checks are trivial
to implement using dnsjava (already a dependency).

**Checks to implement:**

**1. DNS Zone Transfer (AXFR):**
- Send a DNS `AXFR` query (TCP) for the target domain to each of its authoritative nameservers
- If the server responds with zone records, it is misconfigured — discloses all hostnames, MX, TXT, SPF, internal IPs
- Discovered hostnames are fed into the scan queue (same as CT recon)
- Severity: HIGH

```java
Lookup lookup = new Lookup("example.com", Type.AXFR);
lookup.setResolver(new SimpleResolver(nsServer));
Record[] records = lookup.run();
```

**2. Open Resolver Detection:**
- Send a recursive DNS query for an external domain (e.g., `google.com`) to the target IP on port 53
- If the target responds with a valid answer, it is an open resolver — usable for DNS amplification DDoS
- Severity: MEDIUM

**3. DNSSEC Validation:**
- Query for `DS` and `DNSKEY` records for the domain
- Check if `AD` (Authenticated Data) flag is set in responses
- Absence of DNSSEC → susceptibility to cache poisoning (Kaminsky attack)
- Severity: LOW/INFO

**4. DNS over TCP Support:**
- Verify DNS responds on TCP port 53 (required by RFC 7766 but often blocked by firewalls)

**CLI addition:**
```
--dns-audit    Run DNS security checks on port-53 targets (zone transfer, open resolver, DNSSEC)
```

**What to create:**
- `scanner/DnsAuditor.java` — `DnsAuditResult audit(String host, String domain, int timeoutMs)`
- `model/DnsAuditResult.java` — `boolean zoneTransferAllowed`, `List<String> leakedRecords`, `boolean openResolver`, `boolean dnssecEnabled`, `boolean tcpEnabled`
- `ScanCommand.java` — `--dns-audit` flag; invoke when port 53 is open
- Integrate discovered records from AXFR into the scan queue (optional: `--dns-audit-scan` to trigger follow-up scan of leaked hosts)

**Verify:** Test against a known misconfigured nameserver (many public testing domains allow AXFR, e.g., `zonetransfer.me`). Zone transfer must return records. Open resolver test against `8.8.8.8` must return `true`.

---

### TASK-28: Two-Phase Scan Pipeline

**Priority:** P3 | **Effort:** 1 day | **New deps:** None

**Value:** When scanning all 65535 ports, the majority of ports are closed or filtered. Running
expensive operations (banner grabbing, TLS inspection, SNMP, OS fingerprinting) on all 65535
ports wastes time. RustScan's dominant workflow solves this: a fast phase discovers all open ports,
then a deep phase runs enrichment only on the open ports found. This can reduce total scan time
by 80–90% on typical hosts.

**Current workflow (slow for full port range):**
```
foreach port in 1..65535 → connect + banner grab + TLS + CVE lookup → result
```

**Proposed two-phase workflow:**
```
Phase 1 (--quick): foreach port in 1..65535 → TCP connect only → collect open ports
Phase 2 (--deep):  foreach open_port → banner + probes + TLS + CVE lookup + SNMP + OS
```

**CLI addition:**
```
--quick    Phase 1: fast TCP-connect-only scan of all 65535 ports. No banner grabbing.
           Output: list of open ports. Used as input for --deep.

--deep     Phase 2: run full enrichment on the previously discovered open ports only.
           Reads open ports from --diff file or from a prior --quick scan stored via --save-history.
```

**Combined usage (most common):**
```
--quick --deep   Run both phases automatically in sequence:
                 1. TCP connect scan all 65535 ports (fast, high threads, short timeout)
                 2. Deep enrichment on open ports only (slower, full feature set)
```

**Implementation:**
- `--quick` mode: sets `threads=min(1000, portCount)`, `timeout=100ms`, disables all probes, banner, TLS
- After phase 1: collect `List<Integer> openPorts`
- `--deep` mode: re-runs scan with `ports=openPorts.join(",")` and all requested enrichment flags
- Progress display: "Phase 1: 65535 ports → 8 open (2.3s). Phase 2: enriching 8 ports..."

**What to change:**
- `ScanCommand.java` — `--quick` and `--deep` flags; orchestrate two-phase logic
- `PortScanner.java` — accept a `List<Integer>` port list directly (not just a range string) for phase 2
- No new classes needed — reuses existing `PortScanner` with different configuration

**Verify:**
```bash
# Should complete in < 10s for all 65535 ports, then enrich only open ones
java -jar port-scanner.jar --host 192.168.1.1 --quick --deep --banner --tls
```

---

### TASK-29: CVSS Score Enrichment

**Priority:** P3 | **Effort:** 4h | **New deps:** None

**Value:** The existing `--cve` flag returns CVE IDs but no severity scores. Adding CVSS v3.1
scores transforms the CVE list from identifiers into actionable risk data — enabling filtering,
sorting by severity, and CI policy gates (e.g., fail if CVSS ≥ 9.0).

**Data sources:**

1. **NVD REST API v2** (already used): `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-38408`
   - Returns CVSS v2, v3.1, and v4.0 scores and vectors
   - Already called by `CveLookup.java` — extend to parse CVSS fields

2. **CIRCL CVE Search** (free, no API key): `GET https://cve.circl.lu/api/cve/{cve_id}`
   - Returns CVSS v2/v3, EPSS score (exploit prediction), references, and affected CPEs
   - Use as fallback when NVD rate-limits

3. **EPSS (Exploit Prediction Scoring System)** (free API): `GET https://api.first.org/data/v1/epss?cve={id}`
   - Returns 0–1 probability that the CVE will be exploited in the wild within 30 days
   - High EPSS + high CVSS = immediately actionable finding

**Model changes:**
```java
// Current:
List<String> cves;

// Proposed: replace with
List<CveEntry> cves;

@Data @Builder
public class CveEntry {
    String id;           // "CVE-2023-38408"
    double cvssV3;       // 9.8
    String cvssVector;   // "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    String severity;     // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    double epss;         // 0.012 (1.2% exploitation probability)
    String description;  // first 120 chars of NVD description
}
```

**CLI addition:**
```
--fail-on-cvss <score>    Exit code 1 if any open port has a CVE with CVSS ≥ this value.
                          Example: --fail-on-cvss 7.0 fails the build on HIGH/CRITICAL CVEs.
```

**Sort/filter in output:**
- Text output: sort CVEs by CVSS descending within each port entry
- Summary line: "⚠ 2 CRITICAL (CVSS ≥ 9.0), 4 HIGH (CVSS ≥ 7.0)"
- HTML report: color-code CVE badges (red = critical, orange = high, yellow = medium)

**What to change:**
- `model/CveEntry.java` — new model (replaces `String` in `cves` list)
- `service/CveLookup.java` — extend to fetch and parse CVSS fields from NVD v2 API
- `service/CirclCveClient.java` — fallback CVSS source + EPSS lookup
- `ScanResult.java` — change `List<String> cves` → `List<CveEntry> cves`
- Update all exporters to display CVSS scores
- `ScanCommand.java` — `--fail-on-cvss <score>` flag

**Verify:** Scan a host with a known CVE service. `ScanResult.cves[0].cvssV3` must be populated. `--fail-on-cvss 9.0` must exit with code 1 when a CVSS ≥ 9.0 CVE is found.

---

## P4 — Stretch Goals

---

### TASK-30: Nuclei YAML Template Loader

**Priority:** P4 | **Effort:** 3 days | **New deps:** SnakeYAML (already implied by Jackson YAML) |

**Value:** Nuclei (by ProjectDiscovery) is the industry standard for template-based vulnerability
detection. Its community template repository (`github.com/projectdiscovery/nuclei-templates`)
contains 9,000+ YAML templates covering CVEs, misconfigurations, default credentials, and
exposed panels. Loading a subset of these templates into the port scanner enables vulnerability
detection without writing any Java code.

**Nuclei template structure (simplified):**
```yaml
id: CVE-2021-41773
info:
  name: Apache HTTP Server 2.4.49 Path Traversal
  severity: critical
  cve-id: CVE-2021-41773

http:
  - method: GET
    path:
      - "{{BaseURL}}/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd"
    matchers:
      - type: regex
        regex:
          - "root:.*:0:0:"
        condition: and
```

**Scope — implement a subset of Nuclei template types:**

| Template type | Effort | Value |
|---------------|--------|-------|
| HTTP request + regex matcher | Low | Very high — covers most CVE templates |
| HTTP request + word matcher | Low | High |
| HTTP request + status matcher | Low | High |
| TCP raw probe + regex matcher | Medium | High — covers non-HTTP services |
| Network/service templates | Medium | Good for SSH, Redis, etc. |
| JavaScript-based templates | Very high | Skip for now |
| Workflow templates | High | Skip for now |

**What to create:**
- `nuclei/NucleiTemplate.java` — Jackson-deserialized YAML model for supported template fields
- `nuclei/NucleiTemplateLoader.java` — loads `*.yaml` from `~/.portscanner/nuclei-templates/`
- `nuclei/NucleiRunner.java` — `List<NucleiResult> run(NucleiTemplate, ScanResult)` — executes HTTP/TCP requests, evaluates matchers
- `nuclei/matcher/RegexMatcher.java`, `WordMatcher.java`, `StatusMatcher.java`
- `model/NucleiResult.java` — `templateId`, `name`, `severity`, `matched`, `matchedAt`, `extractedValues`
- `ScanCommand.java` — `--nuclei-templates <path>` flag; `--nuclei-tags <tags>` to filter by severity/type

**Template auto-update:**
```
java -jar port-scanner.jar update-nuclei    # Git clone/pull nuclei-templates to ~/.portscanner/nuclei-templates/
```

**Verify:** Run CVE-2021-41773 template against an Apache 2.4.49 container. Must detect and report the vulnerability. Run a safe template against a target — must not produce false positives.

---

### TASK-31: Scan Agent / Distributed Scanning Mode

**Priority:** P4 | **Effort:** 3 days | **New deps:** None (JDK HttpClient for agent↔coordinator comms)

**Value:** Scanning large enterprise networks (10.0.0.0/8 — 16M hosts) from a single machine is
impractical. A distributed mode deploys multiple scan agents inside different network segments
(behind firewalls, in cloud VPCs), each scanning its local segment and reporting results back to a
central coordinator. This mirrors the architecture used by Rapid7 Nexpose, Qualys, and Tenable SC.

**Architecture:**

```
Coordinator (--coordinator --port 9000)
    ↑ HTTP/JSON
    ├── Agent 1 (192.168.1.x/24) --agent --server http://coordinator:9000 --token <tok>
    ├── Agent 2 (10.0.0.x/24)   --agent --server http://coordinator:9000 --token <tok>
    └── Agent 3 (172.16.x.x/16) --agent --server http://coordinator:9000 --token <tok>
```

**Coordinator mode:**
- Accepts agent registration (`POST /agent/register`)
- Distributes work items: `{target: "192.168.1.0/24", ports: "1-1024", options: {...}}`
- Aggregates results as agents report back (`POST /agent/result`)
- Exposes combined results via existing REST API (`GET /scans`)

**Agent mode:**
- Polls coordinator for work (`GET /agent/work`)
- Executes scan using existing `PortScanner` / `CidrScanner`
- Reports results as `ScanReport` JSON (`POST /agent/result`)
- Heartbeat every 30s (`PUT /agent/heartbeat`)

**CLI additions:**
```
--coordinator          Start as coordinator node
--coordinator-port     Coordinator HTTP port. Default: 9000
--agent                Start as scan agent (polls coordinator for work)
--agent-server <url>   Coordinator URL
--agent-token <key>    Authentication token
--agent-label <name>   Human-readable label for this agent (e.g., "dmz-segment")
```

**What to create:**
- `api/CoordinatorServer.java` — extends `ScanApiServer` with agent management endpoints
- `api/ScanAgentClient.java` — polls coordinator, executes scans, reports results
- `api/dto/AgentRegistration.java`, `WorkItem.java`, `AgentResult.java`
- `ScanCommand.java` — `--coordinator` and `--agent` flags

**Security:** All agent↔coordinator communication authenticated via `Authorization: Bearer <token>` header. Results encrypted at rest if `--agent-encrypt` flag set (JDK AES-256-GCM).

**Verify:** Start coordinator. Start two agents. Submit a scan via the REST API targeting a /24 split across both agents. Combined results must appear in coordinator's `/scans` endpoint.

---

### TASK-32: Excel/XLSX Export

**Priority:** P4 | **Effort:** 4h | **New deps:** Apache POI ~8MB

**Value:** Security teams and management stakeholders universally consume reports in Excel.
While JSON/HTML/PDF are developer-friendly, Excel is the standard deliverable format in
enterprise security audits and compliance reporting.

**Workbook structure:**

| Sheet | Content |
|-------|---------|
| Summary | Host, IP, scan date, duration, total/open/filtered port counts, OS guess |
| Open Ports | One row per port: port, protocol, service, version, banner, CVEs, CVSS |
| TLS Findings | One row per port with TLS data: cert subject, expiry, cipher, vulnerabilities |
| CVEs | Flattened list: port, CVE ID, CVSS score, severity, description |
| SNMP | sysDescr, sysName, sysLocation, sysContact |
| Traceroute | Hop number, IP, hostname, RTT |

**Formatting:**
- Freeze top row, auto-filter on every sheet
- Conditional formatting: red fill for CRITICAL CVEs, orange for HIGH
- Hyperlinks: CVE IDs link to `https://nvd.nist.gov/vuln/detail/{cve}`
- Column widths auto-sized

**CLI addition:**
```
-o report.xlsx        Extension selects XLSX exporter
--format xlsx         Explicit format override
```

**What to create:**
- `report/XlsxExporter.java` — implements `ReportExporter`; uses Apache POI `XSSFWorkbook`
- `ExporterFactory.java` — add `.xlsx` extension and `xlsx` format string
- `pom.xml` — add `org.apache.poi:poi-ooxml:5.3.0`

**Verify:** Open generated `.xlsx` in Excel and LibreOffice Calc. Verify all sheets are present, auto-filter works, and CVE hyperlinks resolve correctly.

---

## Implementation Notes

### Dependency Policy
- Only add a new dependency if the value clearly justifies the JAR size increase
- Prefer JDK built-ins (`java.net.http`, `com.sun.net.httpserver`) over small utility libraries
- Any new dep must have an Apache 2.0 or MIT license
- Bouncy Castle (LGPL) is acceptable for TLS deep audit if no JSSE alternative exists

### Testing Requirements
- Every new scanner class needs a unit test with a `ServerSocket`-based fixture or Testcontainers
- Every new exporter needs a round-trip test: build a `ScanReport` → export → parse → assert fields
- SARIF output must be validated against the official SARIF JSON schema
- JUnit XML output must be accepted by `dorny/test-reporter` GitHub Action
- TLS audit tests: use `badssl.com` subdomains as live fixtures (or spin up a local openssl test server)

### Priority Guidance
- **P0**: Fix the Windows TUI — this is the most visible UX bug
- **P1**: SARIF + JUnit XML + Shodan — these three unlock CI/CD integration and cross-tool interoperability with minimal effort
- **P2**: TLS deep audit + SSH audit + HTTP header scoring — deepen detection quality for the protocols already supported
- **P3**: Build on P2 with unauthenticated service detection, DNS checks, and two-phase scanning
- **P4**: Nuclei and distributed mode are high-value but high-effort; tackle after P1–P3 are solid
