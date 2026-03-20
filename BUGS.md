# Known Issues & Non-Working Features

## 1. TUI Mode (`--tui`) — BROKEN on Windows

**Status:** Falls back to plain text output with warning:
> `TUI unavailable (To start java on Windows, use javaw! ...)`

**Root cause:** Lanterna's terminal backend fails to initialize in Windows CMD / PowerShell / Windows Terminal when launched via `java.exe`. It requires either:
- `javaw.exe` — which detaches from the console entirely (no stdout), or
- A compatible text-mode terminal backend (JNA-based `WindowsTerminal`) that fails in shaded JARs

**Workaround:** The plain text output works correctly. You still get full scan results — just no full-screen UI.

**Fix in progress:** `TuiProgressDisplay.java` has been updated to force headless mode + stream-based ANSI terminal. Needs a successful build + verification.

---

## 2. Traceroute (`--traceroute`) — MAY REQUIRE ELEVATION on Windows

**Status:** Calls `tracert.exe` via `ProcessBuilder`. Works if `tracert` is available on PATH (it is by default), but results may be empty or partial if Windows Firewall blocks ICMP.

**Workaround:**
- Run as Administrator if you get no hops
- Check Windows Firewall is not blocking ICMP outbound

---

## 3. UDP Scanning (`--protocol udp` or `--protocol both`) — UNRELIABLE on Windows

**Status:** UDP scanning relies on ICMP "port unreachable" responses to detect closed ports. Windows may require elevated privileges to receive raw ICMP responses, and results are often inaccurate without them.

**Workaround:**
- Run as Administrator for more accurate UDP results
- UDP scanning is inherently less reliable than TCP regardless of OS

**Note:** `--proxy` is silently ignored when UDP scanning (by design).

---

## 4. CVE Lookup (`--cve`) — REQUIRES INTERNET + NVD API KEY

**Status:** Makes live HTTP requests to the NVD (National Vulnerability Database) API. Without an API key, requests are heavily rate-limited (may time out or return no results).

**Workaround:**
- Set `NVD_API_KEY` environment variable, or add it to the config file
- Use `--cve` only on a small port range to avoid hitting rate limits

---

## 5. AbuseIPDB Check (`--abuse-check`) — REQUIRES API KEY

**Status:** Will silently skip enrichment if `ABUSEIPDB_KEY` is not set.

**Workaround:** Set the `ABUSEIPDB_KEY` environment variable:
```powershell
$env:ABUSEIPDB_KEY = "your_key_here"
```

---

## 6. GreyNoise Check (`--greynoise`) — REQUIRES API KEY

**Status:** Will silently skip enrichment if `GREYNOISE_KEY` is not set.

**Workaround:** Set the `GREYNOISE_KEY` environment variable:
```powershell
$env:GREYNOISE_KEY = "your_key_here"
```

---

## 7. Geolocate (`--geolocate`) — WORKS but rate-limited without token

**Status:** Uses IPinfo.io free tier. Works without a token but limited to 50,000 requests/month.

**Workaround:** Set `IPINFO_TOKEN` environment variable for higher limits.

---

## 8. `run.bat` Build Behavior

**Status:** `run.bat` always rebuilds the project before running. This takes ~5–10 seconds on every launch.

**Workaround:** Run the JAR directly to skip the build step:
```powershell
"C:\Users\legion\.jdks\temurin-21.0.9\bin\java" -jar "D:\Repos\Github\port-scanner\target\port-scanner-1.0-shaded.jar" --host localhost --ports 1-1024
```

---

## Task-30 / Task-31 Issues (identified by code review)

---

### BUG-09: CoordinatorServer 204 response is malformed — agent poll loop may hang

**Severity:** Critical
**File:** `src/main/java/com/portscanner/api/CoordinatorServer.java` — `handleWork()` / `send()` helper

**Problem:** The `send()` helper calls `ex.sendResponseHeaders(status, bytes.length)`. For a 204 No Content response, `bytes` is `"".getBytes()` which is length `0`. In JDK's `com.sun.net.httpserver.HttpServer`, passing `0` as the response body length signals *chunked* transfer encoding — not "no body". RFC 7230 requires that 204 responses carry no body at all. Java's own `HttpClient` (used by `ScanAgentClient`) may hang or throw on the malformed response, breaking the agent poll loop.

**Fix:** Use `sendResponseHeaders(204, -1)` for no-body responses:
```java
private void sendNoContent(HttpExchange ex) throws IOException {
    ex.sendResponseHeaders(204, -1);
    ex.getResponseBody().close();
}
```
Call this instead of `send(ex, 204, "")` in `handleWork`.

---

### BUG-10: Bearer token sent in request body during agent registration (credential leak)

**Severity:** Critical
**File:** `src/main/java/com/portscanner/api/ScanAgentClient.java` — `register()` (line ~75)
**File:** `src/main/java/com/portscanner/api/dto/AgentRegistration.java`

**Problem:** `ScanAgentClient.register()` populates the `token` field of `AgentRegistration` and sends it in the JSON body. The coordinator's `handleRegister` never reads `reg.getToken()` — auth is already done via the `Authorization` header. The result is the shared secret appearing redundantly in request bodies, where it can be logged, stored in agent records, or captured in network traces.

**Fix:** Remove the `token` field from `AgentRegistration`. The header is the sole auth mechanism.

---

### BUG-11: Agent sends `Authorization: Bearer null` when `--agent-token` is omitted

**Severity:** Important
**File:** `src/main/java/com/portscanner/api/ScanAgentClient.java` — `post()` and `get()` helpers, `heartbeat()`

**Problem:** All three HTTP helpers concatenate `"Bearer " + token` without a null check. When a user starts an agent without `--agent-token`, `token` is `null`, producing the literal header `Authorization: Bearer null`. The coordinator rejects this with 401, and the agent silently logs errors without a useful message.

**Fix:**
```java
if (token != null) builder.header("Authorization", "Bearer " + token);
```
Apply to all three request builders in `ScanAgentClient`.

---

### BUG-12: Dispatched work items are silently lost if agent crashes

**Severity:** Important
**File:** `src/main/java/com/portscanner/api/CoordinatorServer.java` — `handleWork()`

**Problem:** `workQueue.poll()` removes the `WorkItem` from the queue before the agent confirms completion. If the agent crashes between receiving the item and posting to `/agent/result`, the work item is permanently lost — the target host will never appear in scan results.

**Fix options:**
- Move items to an "in-flight" map on dispatch; move back to the queue on heartbeat timeout.
- At minimum, document the limitation with a `// NOTE: at-least-once delivery not implemented` comment and a log warning.

---

### BUG-13: `NucleiRunner` attempts HTTP against all open ports, not just web ports

**Severity:** Important
**File:** `src/main/java/com/portscanner/nuclei/NucleiRunner.java` — `run()` method
**File:** `src/main/java/com/portscanner/cli/ScanCommand.java` — nuclei execution loop

**Problem:** The nuclei execution loop in `ScanCommand` iterates over *all* open ports. For each, `NucleiRunner` fires HTTP connections with a 10-second timeout. On a host with 50 open ports, 48 of which are non-HTTP (SSH, FTP, SMTP, etc.), this fires 48 × N connection attempts that all hang for 10 seconds each — potentially adding 480 seconds of dead wait time per template set.

**Fix:** Gate nuclei execution on HTTP-capable ports only:
```java
for (ScanResult r : openPorts) {
    if (r.getHttpInfo() == null && !"HTTP".equals(r.getServiceName())
            && !"HTTPS".equals(r.getServiceName())) continue;
    List<NucleiResult> findings = runner.run(...);
}
```

---

### BUG-14: `RegexMatcher` recompiles patterns on every invocation (performance + ReDoS risk)

**Severity:** Important
**File:** `src/main/java/com/portscanner/nuclei/matcher/RegexMatcher.java` — line 14

**Problem:** `Pattern.compile(regex, Pattern.DOTALL)` is called inside the innermost loop — once per pattern per port scan. Running 100 templates against 100 open ports causes 10,000 uncached compilations. More critically, a malicious or accidentally catastrophic template regex can cause the JVM to hang (ReDoS).

**Fix:** Pre-compile patterns in `NucleiTemplateLoader` and store `Pattern` objects directly on the `Matcher` model, or use a `ConcurrentHashMap<String, Pattern>` cache in `RegexMatcher`:
```java
private static final Map<String, Pattern> CACHE = new ConcurrentHashMap<>();
Pattern p = CACHE.computeIfAbsent(regex, r -> Pattern.compile(r, Pattern.DOTALL));
```

---

### BUG-15: HTTPS port detection hardcoded to 443/8443 — fails on non-standard TLS ports

**Severity:** Important
**File:** `src/main/java/com/portscanner/nuclei/NucleiRunner.java` — line 46

**Problem:**
```java
String protocol = result.getPort() == 443 || result.getPort() == 8443 ? "https" : "http";
```
This sends plain HTTP to any TLS port that isn't 443 or 8443 (e.g. 9443, 4443, 8444). The connection will succeed at TCP level but receive a TLS handshake blob, causing all templates to false-negative silently.

**Fix:** Use the existing `tlsInfo` field as the authoritative signal:
```java
String protocol = result.getTlsInfo() != null ? "https" : "http";
```

---

### BUG-16: HTTP method not enforced on `GET /agent/work`, `GET /scans`, `PUT /agent/heartbeat`

**Severity:** Important
**File:** `src/main/java/com/portscanner/api/CoordinatorServer.java` — `handleWork()`, `handleScans()`, `handleHeartbeat()`

**Problem:** `handleRegister`, `handleResult`, and `handleSubmit` reject non-POST requests with 405. The GET and PUT handlers have no such check. A `POST /agent/work` will dequeue a work item as if it were a valid `GET`. This can silently drain the work queue from a misconfigured client.

**Fix:** Add method enforcement to all three handlers, e.g.:
```java
if (!"GET".equals(ex.getRequestMethod())) { send(ex, 405, "Method Not Allowed"); return; }
```

---

### BUG-17: `parsePorts` duplicated in `ScanAgentClient` without bounds validation

**Severity:** Important
**File:** `src/main/java/com/portscanner/api/ScanAgentClient.java` — `parsePorts()` (line ~129)

**Problem:** `ScanAgentClient.parsePorts` has no 1–65535 bounds validation. A coordinator-submitted `WorkItem` with `ports: "0-99999"` will be accepted and passed directly to `PortScanner`. The same logic is also duplicated in `ScanJobManager` and `ScanCommand` (three copies).

**Fix:** Extract a shared `PortRangeParser` utility class with validation used by all three callers.

---

### NOTE-01: `NucleiTemplateLoader` is non-recursive — will load 0 templates from real Nuclei repos

**Severity:** Minor
**File:** `src/main/java/com/portscanner/nuclei/NucleiTemplateLoader.java` — line 30

**Problem:** `Files.newDirectoryStream(dir, "*.yaml")` does not recurse into subdirectories. Real Nuclei template repositories (`nuclei-templates`) are organized into subdirectory trees (`cves/2023/`, `vulnerabilities/`). A user pointing `--nuclei-templates` at a cloned repo will load zero templates with no error.

**Fix:** Replace with `Files.walk(dir).filter(p -> p.toString().endsWith(".yaml"))`, or emit a warning when zero templates are loaded from a non-empty directory.

---

### NOTE-02: `workId` JSON response uses string concatenation — potential JSON injection

**Severity:** Minor
**File:** `src/main/java/com/portscanner/api/CoordinatorServer.java` — `handleSubmit()` line ~118

**Problem:**
```java
send(ex, 200, "{\"workId\":\"" + item.getWorkId() + "\"}");
```
If a caller supplies a `workId` containing `"` or `\`, the response is malformed JSON. All other responses in this file use `mapper.writeValueAsString()`.

**Fix:** Use `mapper.writeValueAsString(Map.of("workId", item.getWorkId()))`.

---

### NOTE-03: `NucleiResult.matched` field is always `true` and carries no information

**Severity:** Minor
**File:** `src/main/java/com/portscanner/model/NucleiResult.java` — `matched` field
**File:** `src/main/java/com/portscanner/nuclei/NucleiRunner.java` — line ~86

**Problem:** `NucleiRunner` only creates a `NucleiResult` when a match is confirmed (`.matched(true)` hardcoded). The list itself is the signal — the `matched` field is always `true` and adds confusion to JSON output.

**Fix:** Remove the `matched` field from `NucleiResult`, or document its intent as a placeholder for future negative-result tracking.

---

### NOTE-04: `WordMatcher` and `StatusMatcher` have no dedicated unit tests

**Severity:** Minor
**File:** `src/test/java/com/portscanner/nuclei/NucleiRunnerTest.java`

**Problem:** `NucleiRunnerTest` only tests the regex matcher path. The `negative` flag, `condition: and`, and multi-value `status` list paths in `WordMatcher` and `StatusMatcher` have no coverage. The `StatusMatcher` XOR logic (`matcher.isNegative() != result`) is easy to get wrong on boundary cases.

**Fix:** Add `@Test` methods for word matching (hit/miss, `condition: and`, `negative: true`) and status matching (in-list, not-in-list, `negative: true`) — either in `NucleiRunnerTest` or a new `MatcherTest` class.
