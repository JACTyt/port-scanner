# 🌐 Java Port Scanner Tool — Refined Project Plan

> **Version 2.0** — Deep research edition  
> Language: Java 17+ | Build: Maven | Stack: Picocli + Lombok + Jackson + JUnit 5

---

## ⚠️ Ethical & Legal Preamble

Before writing a single line of code, this must be understood:

Port scanning is a legally sensitive activity. The simple act of scanning a host you do not own or have explicit written permission to scan **can violate computer misuse laws** in many jurisdictions — including the EU's GDPR framework and various national cybercrime acts. Even where technically legal (e.g., scanning a public-facing IP in the US), it can still trigger Intrusion Detection Systems (IDS) and raise serious professional ethics questions.

**This tool is strictly for:**
- Scanning your own systems (localhost, your LAN)
- Systems where you have written authorization
- Educational lab environments (e.g., VirtualBox VMs)

**The tool will include a mandatory confirmation prompt** before scanning any non-localhost host.

---

## 🎯 Project Identity

A **multithreaded Java CLI tool** that scans a target host for open TCP ports, identifies known services via a built-in port map, optionally grabs service banners, and exports structured scan reports. Built clean, purposefully, and ethically — no bloat, no Spring Boot.

---

## 🛠️ Final Tech Stack

| Dependency | Version | Purpose | Why chosen |
|---|---|---|---|
| Java | 17+ | Core language | LTS, records, sealed classes |
| Maven | 3.9+ | Build & dependency management | Structured, widely known |
| Picocli | 4.7.6 | CLI argument parsing | Best-in-class Java CLI lib, auto `--help`, ANSI colors |
| Lombok | 1.18.x | Boilerplate elimination | Clean model classes with `@Data`, `@Builder` |
| Jackson Databind | 2.17+ | JSON serialization | Industry standard, no extra config needed |
| JUnit 5 | 5.10+ | Unit testing | Current standard, `@ParameterizedTest` support |
| Mockito | 5.x | Mocking in tests | Pair with JUnit 5 for socket mocking |

**Deliberately excluded:** Spring Boot (overkill), Netty (over-engineered for TCP connect scan), OpenCSV (Jackson can handle CSV-like output natively).

---

## 📁 Project Structure

```
port-scanner/
├── pom.xml
├── README.md
└── src/
    ├── main/
    │   ├── java/com/portscanner/
    │   │   ├── Main.java                  ← Entry point
    │   │   ├── cli/
    │   │   │   └── ScanCommand.java       ← Picocli @Command
    │   │   ├── scanner/
    │   │   │   ├── PortScanner.java       ← Core scanning logic
    │   │   │   └── BannerGrabber.java     ← Optional service banner retrieval
    │   │   ├── model/
    │   │   │   ├── ScanResult.java        ← Lombok @Data @Builder
    │   │   │   └── ScanReport.java        ← Aggregated report model
    │   │   ├── service/
    │   │   │   └── ServiceMapper.java     ← Port → service name lookup
    │   │   └── report/
    │   │       ├── ReportExporter.java    ← Interface
    │   │       ├── JsonExporter.java      ← Jackson implementation
    │   │       ├── CsvExporter.java       ← Plain CSV implementation
    │   │       └── TextExporter.java      ← Human-readable TXT
    │   └── resources/
    │       └── services.json             ← Port-to-service map (extensible)
    └── test/
        └── java/com/portscanner/
            ├── scanner/PortScannerTest.java
            └── service/ServiceMapperTest.java
```

---

## 📋 Major Tasks — Deep Dive

---

### ✅ Task 1 — Project Setup
**Goal:** A clean, runnable Maven skeleton with all dependencies wired and an executable fat JAR target.

**How we'll do it:**
1. Generate project with `mvn archetype:generate` using `maven-archetype-quickstart`
2. Configure `pom.xml`:
   - Add all 5 dependencies
   - Configure `maven-shade-plugin` to produce a fat/uber JAR (single portable executable)
   - Configure `maven-compiler-plugin` for Java 17 with Lombok annotation processing
3. Enable Lombok in IDE (IntelliJ: install plugin + enable annotation processing)
4. Verify project compiles: `mvn clean compile`

**Key `pom.xml` section:**
```xml
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-shade-plugin</artifactId>
  <configuration>
    <manifestEntries>
      <Main-Class>com.portscanner.Main</Main-Class>
    </manifestEntries>
  </configuration>
</plugin>
```

**Human judgment call:** Choose the base package name and decide whether to use Java modules (`module-info.java`). For a course project, skip modules — adds complexity without benefit.
**AI contribution:** Generate the full `pom.xml` and folder structure in seconds.

**Time estimate:** 5 minutes

---

### ✅ Task 2 — CLI Interface (Picocli)
**Goal:** Parse, validate, and expose all user-configurable parameters via a polished CLI with auto-generated `--help`.

**How we'll do it:**
- Create `ScanCommand` implementing `Callable<Integer>` (returns exit code)
- Define all options with `@Option` annotations
- Add input validation via Picocli's built-in constraints + custom `ITypeConverter`
- Wire `Main.java` to call `new CommandLine(new ScanCommand()).execute(args)`

**Complete CLI API:**
```bash
# Basic scan
java -jar scanner.jar --host 192.168.1.1 --ports 1-1024

# Full options
java -jar scanner.jar \
  --host scanme.nmap.org \
  --ports 1-65535 \
  --timeout 200 \
  --threads 100 \
  --banner \
  --output report.json

# Auto-generated help (free from Picocli)
java -jar scanner.jar --help
```

**`ScanCommand.java` structure:**
```java
@Command(
  name = "portscanner",
  mixinStandardHelpOptions = true,
  version = "1.0",
  description = "A fast multithreaded TCP port scanner"
)
public class ScanCommand implements Callable<Integer> {

  @Option(names = {"--host", "-h"}, required = true, description = "Target hostname or IP")
  private String host;

  @Option(names = {"--ports", "-p"}, defaultValue = "1-1024",
          description = "Port range, e.g. 1-1024 or 80,443,8080")
  private String portRange;

  @Option(names = {"--timeout", "-t"}, defaultValue = "200",
          description = "Connection timeout in ms (default: 200)")
  private int timeout;

  @Option(names = {"--threads"}, defaultValue = "100",
          description = "Thread pool size (default: 100)")
  private int threads;

  @Option(names = {"--banner"}, description = "Attempt banner grabbing on open ports")
  private boolean grabBanner;

  @Option(names = {"--output", "-o"}, description = "Output file (.json, .csv, .txt)")
  private String outputFile;
}
```

**Validation logic:**
- Port range: supports `1-1024` (range) and `80,443,8080` (list) formats
- Timeout: must be between 50ms and 5000ms
- Threads: capped at 200 to avoid overwhelming the OS socket limit
- Host: resolved via `InetAddress.getByName()` — throws `UnknownHostException` if invalid

**Human judgment call:** Define what "valid input" means for your actual use — should the tool allow scanning port 0? Allow hostnames with underscores? These edge cases matter.
**AI contribution:** Full Picocli annotation code, regex for port range parsing.

**Time estimate:** 10 minutes

---

### ✅ Task 3 — Core Port Scanner
**Goal:** Attempt a TCP connect on each port and classify it as open, closed, or filtered.

**How we'll do it:**
- Each scan is a `Callable<ScanResult>` submitted to the thread pool
- Use `Socket.connect(new InetSocketAddress(host, port), timeout)` pattern
- Three outcomes based on exception type:

| Exception | Port State | Meaning |
|---|---|---|
| No exception | `OPEN` | Connection accepted |
| `ConnectException` | `CLOSED` | Port actively refused |
| `SocketTimeoutException` | `FILTERED` | Firewall silently dropped packet |
| `IOException` (other) | `ERROR` | Network error |

**Core scan method:**
```java
public ScanResult scanPort(String host, int port, int timeoutMs) {
    long start = System.currentTimeMillis();
    try (Socket socket = new Socket()) {
        socket.connect(new InetSocketAddress(host, port), timeoutMs);
        long responseTime = System.currentTimeMillis() - start;
        return ScanResult.builder()
            .port(port)
            .status(PortStatus.OPEN)
            .responseTimeMs(responseTime)
            .build();
    } catch (ConnectException e) {
        return ScanResult.builder().port(port).status(PortStatus.CLOSED).build();
    } catch (SocketTimeoutException e) {
        return ScanResult.builder().port(port).status(PortStatus.FILTERED).build();
    } catch (IOException e) {
        return ScanResult.builder().port(port).status(PortStatus.ERROR).build();
    }
}
```

**`ScanResult` model (Lombok-powered):**
```java
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScanResult {
    private int port;
    private PortStatus status;       // OPEN, CLOSED, FILTERED, ERROR
    private String serviceName;      // e.g. "HTTP", "SSH"
    private String banner;           // Optional, from BannerGrabber
    private long responseTimeMs;
}
```

**Important design decision:** Only report open ports in output by default. Closed ports are noise. Add a `--show-all` flag if needed.

**Human judgment call:** Should `FILTERED` ports appear in the report? Security professionals care about filtered ports (they reveal firewall rules). Default: yes, but in a separate section.
**AI contribution:** Full socket logic, exception hierarchy handling, Lombok model.

**Time estimate:** 15 minutes

---

### ✅ Task 4 — Multithreading
**Goal:** Scan hundreds of ports in parallel to make the tool fast enough to be practical.

**Performance reality check:**
- Sequential scan of 1024 ports at 200ms timeout = ~3.4 minutes ❌
- Parallel scan with 100 threads = ~2-4 seconds ✅

**How we'll do it:**
- Use `ExecutorService` with `Executors.newFixedThreadPool(threads)`
- Submit all port scan `Callable`s upfront, collect `Future<ScanResult>` handles
- Add a live progress counter using `AtomicInteger` + `\r` carriage return trick

**Thread pool implementation:**
```java
ExecutorService executor = Executors.newFixedThreadPool(threadCount);
List<Future<ScanResult>> futures = new ArrayList<>();

for (int port = startPort; port <= endPort; port++) {
    final int p = port;
    futures.add(executor.submit(() -> scanPort(host, p, timeout)));
}

// Collect results (maintains port order)
List<ScanResult> results = new ArrayList<>();
for (Future<ScanResult> future : futures) {
    results.add(future.get(timeout + 500, TimeUnit.MILLISECONDS));
}

executor.shutdown();
```

**Progress indicator:**
```java
AtomicInteger scanned = new AtomicInteger(0);
// In each Callable, after scan:
System.out.printf("\rScanning... %d/%d ports", scanned.incrementAndGet(), totalPorts);
```

**Thread pool sizing guidance:**
- Default: 100 threads — good balance for most home/lab networks
- Lower to 50 for slow networks or cautious scanning
- Max cap: 200 (above this, OS-level socket limits become a bottleneck)
- Formula: `min(portCount, 200)` — no point spinning up 500 threads for 20 ports

**Human judgment call:** Thread count is a tuning parameter that depends on the network environment, target host resilience, and whether IDS evasion matters. This is a judgment call only the human can make.
**AI contribution:** `ExecutorService` boilerplate, `Future` collection pattern, `AtomicInteger` progress counter.

**Time estimate:** 10 minutes

---

### ✅ Task 5 — Service Detection & Banner Grabbing
**Goal:** Enrich open port results with service names and optionally live banner data.

**Two-layer approach:**

**Layer 1 — Static Port Map (always runs):**
- `ServiceMapper` class holds a `HashMap<Integer, String>` of ~60 well-known ports
- Loaded from bundled `services.json` for extensibility
- Zero network overhead — just a lookup

**Key mappings included:**
```
20/21 → FTP    22 → SSH       23 → Telnet    25 → SMTP
53 → DNS       80 → HTTP      110 → POP3     143 → IMAP
443 → HTTPS    445 → SMB      3306 → MySQL   3389 → RDP
5432 → Postgres  6379 → Redis   8080 → HTTP-Alt  27017 → MongoDB
```

**Layer 2 — Banner Grabbing (optional, `--banner` flag):**
- Attempt to read the first 1024 bytes from the open socket's `InputStream`
- Many services (FTP, SMTP, SSH, HTTP) emit a greeting banner automatically
- Set a short read timeout (1000ms) to avoid hanging
- Useful for discovering software versions (e.g., `SSH-2.0-OpenSSH_8.9`)

```java
public String grabBanner(String host, int port, int timeoutMs) {
    try (Socket socket = new Socket()) {
        socket.connect(new InetSocketAddress(host, port), timeoutMs);
        socket.setSoTimeout(1000);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(socket.getInputStream())
        );
        return reader.readLine(); // First line = banner
    } catch (Exception e) {
        return null; // Banner grab failed silently
    }
}
```

**Ethics note:** Banner grabbing goes beyond passive observation — it actively reads data from the open port. Only use this with explicit permission on target systems.

**Human judgment call:** Which ports warrant banner grabbing? HTTP (port 80) won't auto-emit a banner — you'd need to send `GET / HTTP/1.0\r\n\r\n` first. Deciding when to send protocol-specific probes is a design choice.
**AI contribution:** Full `ServiceMapper` with the 60-port JSON map, `BannerGrabber` class.

**Time estimate:** 10 minutes

---

### ✅ Task 6 — Report Export
**Goal:** Save scan results in a structured, useful format for later analysis.

**How we'll do it:**
- `ReportExporter` interface with a single `export(ScanReport report, Path outputPath)` method
- Three concrete implementations, chosen based on output file extension
- `ScanReport` is a Jackson-annotated aggregate model

**`ScanReport` model:**
```java
@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScanReport {
    private String host;
    private String resolvedIp;
    private LocalDateTime scannedAt;
    private long durationMs;
    private int totalScanned;
    private int openCount;
    private int filteredCount;
    private List<ScanResult> openPorts;
    private List<ScanResult> filteredPorts;
}
```

**JSON output sample:**
```json
{
  "host": "192.168.1.1",
  "resolvedIp": "192.168.1.1",
  "scannedAt": "2026-03-10T14:30:00",
  "durationMs": 3240,
  "totalScanned": 1024,
  "openCount": 3,
  "openPorts": [
    { "port": 22, "status": "OPEN", "serviceName": "SSH",
      "banner": "SSH-2.0-OpenSSH_8.9", "responseTimeMs": 12 },
    { "port": 80, "status": "OPEN", "serviceName": "HTTP", "responseTimeMs": 8 },
    { "port": 443, "status": "OPEN", "serviceName": "HTTPS", "responseTimeMs": 9 }
  ]
}
```

**TXT output sample:**
```
============================================================
PORT SCAN REPORT
============================================================
Host         : 192.168.1.1
Scanned At   : 2026-03-10 14:30:00
Duration     : 3.24 seconds
Ports Scanned: 1024  |  Open: 3  |  Filtered: 12
------------------------------------------------------------
PORT     STATE     SERVICE     RESPONSE    BANNER
22       OPEN      SSH         12ms        SSH-2.0-OpenSSH_8.9
80       OPEN      HTTP        8ms         -
443      OPEN      HTTPS       9ms         -
============================================================
```

**Format selection logic:**
```java
ReportExporter exporter = switch (getExtension(outputFile)) {
    case "json" -> new JsonExporter(objectMapper);
    case "csv"  -> new CsvExporter();
    default     -> new TextExporter();
};
```

**Human judgment call:** Which format serves your audience? JSON for piping into other tools, TXT for human reading, CSV for spreadsheet analysis.
**AI contribution:** Full Jackson serialization, formatted TXT table renderer.

**Time estimate:** 10 minutes

---

## 🤝 Human vs AI Delegation — Final Analysis

| Task | Human Strength | AI Strength | Collaboration Impact |
|---|---|---|---|
| Project Setup | Scope decisions, module choice | Maven boilerplate, pom.xml | ⭐⭐ Medium |
| CLI Interface | Defining what "valid" means for real use | Picocli annotations, validation code | ⭐⭐⭐ High |
| Core Scanner | Timeout strategy, port state semantics | Socket logic, exception hierarchy | ⭐⭐⭐ High |
| Multithreading | Thread count tuning, IDS awareness | ExecutorService patterns, Future handling | ⭐⭐⭐ High |
| Service Detection | Choosing relevant services, banner ethics | Port map generation, BannerGrabber code | ⭐⭐ Medium |
| Report Export | Audience-appropriate format choice | Jackson serialization, TXT formatting | ⭐⭐⭐ High |
| Ethics / Legal | **Only the human** — full ownership | Research, documentation | ⭐⭐⭐⭐ Critical |

---

## 🧪 Testing Strategy

| Test | What to test | How |
|---|---|---|
| `PortScannerTest` | Open port detection on localhost | Spin up `ServerSocket` on a test port |
| `PortScannerTest` | Closed port returns `CLOSED` | Scan a port with no `ServerSocket` |
| `ServiceMapperTest` | Known ports map correctly | Assert `mapper.getService(22).equals("SSH")` |
| `ServiceMapperTest` | Unknown port returns "Unknown" | Assert port 9999 maps to "Unknown" |
| `ReportExporterTest` | JSON output is valid | Parse output with Jackson, assert fields |
| `ScanCommandTest` | Invalid host rejected | Assert exit code != 0 |

---

## 💡 Key Architectural Insights

> **Why `Callable` over `Runnable` for port tasks?**
> `Callable<ScanResult>` returns a value and can throw checked exceptions. `Runnable` returns void. For a scanner, you need the result back — `Callable` is the right abstraction.

> **Why TCP connect scan only (not SYN scan)?**
> SYN (half-open) scans require raw socket access, which requires root/admin privileges and uses lower-level APIs outside standard Java. TCP connect scan is less stealthy but works fine for educational and authorized scanning.

> **Why cap threads at 200?**
> Each open socket consumes a file descriptor. Operating systems impose per-process limits (typically 1024 on Linux). Exceeding this causes `java.net.SocketException: Too many open files`. Capping at 200 leaves a safe margin.

> **Why `try-with-resources` on every Socket?**
> Unclosed sockets are a resource leak that silently exhausts the connection pool. `try-with-resources` guarantees `socket.close()` even on exception paths.

---

## 🗓️ Estimated Time Breakdown

| Task | Estimated Time |
|---|---|
| Project Setup | 5 min |
| CLI Interface (Picocli) | 10 min |
| Core Port Scanner | 15 min |
| Multithreading | 10 min |
| Service Detection + Banner | 10 min |
| Report Export | 10 min |
| **Total** | **~60 minutes** |

---

## 🔮 Future Extensions (Post-Course)

| Feature | Complexity | Notes |
|---|---|---|
| UDP scanning | Medium | Stateless — much harder than TCP |
| Subnet scanning (CIDR) | Medium | Add `--subnet 192.168.1.0/24` flag |
| OS fingerprinting | High | TTL analysis, TCP window size heuristics |
| CVE lookup per service | High | Integrate with NVD API |
| GraalVM native binary | Medium | Picocli has built-in GraalVM support |
| JavaFX GUI | Medium | Visual port map dashboard |

---

*This document was created as part of a structured AI-human collaboration exercise. All code should be tested only on authorized systems.*
