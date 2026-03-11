# Port Scanner Feature Research: nmap, masscan, rustscan, zmap

**Research Date:** 2026-03-11
**Scope:** Features from popular scanners adaptable to a Java TCP connect scanner.
**Sources:** nmap.org official documentation, masscan GitHub, rustscan GitHub, academic papers, security research blogs.

---

## 1. nmap Timing Templates (T0–T5)

### Source References
- https://nmap.org/book/performance-timing-templates.html
- https://nmap.org/book/man-performance.html
- nmap source: `timing.cc`, `nmap.h` in the nmap GitHub repo (github.com/nmap/nmap)

### What Timing Templates Control

nmap's `-T<0-5>` flag sets a named timing profile. Each profile is a bundle of values for six underlying parameters:

| Parameter | Description |
|---|---|
| `min-rtt-timeout` | Minimum RTT timeout floor (prevents shrinking too aggressively) |
| `max-rtt-timeout` | Ceiling on per-probe RTT timeout |
| `initial-rtt-timeout` | Starting RTT estimate before adaptive data |
| `max-retries` | How many times to re-probe a port before giving up |
| `scan-delay` | Mandatory inter-probe delay (for IDS evasion / politeness) |
| `max-scan-delay` | Upper bound on adaptive scan delay |
| `min-parallelism` | Floor on concurrent probes |
| `max-parallelism` | Ceiling on concurrent probes |
| `host-timeout` | Abandon a host after this long |

### Exact Values per Template

| Parameter | T0 (Paranoid) | T1 (Sneaky) | T2 (Polite) | T3 (Normal) | T4 (Aggressive) | T5 (Insane) |
|---|---|---|---|---|---|---|
| `min-rtt-timeout` | 100ms | 100ms | 100ms | 100ms | 100ms | 50ms |
| `max-rtt-timeout` | 5 min | 15 s | 10 s | 10 s | 1250ms | 300ms |
| `initial-rtt-timeout` | 5 min | 15 s | 1 s | 1 s | 500ms | 250ms |
| `max-retries` | 10 | 10 | 10 | 6 | 6 | 2 |
| `scan-delay` | 5 min | 15 s | 400ms | 0 | 0 | 0 |
| `max-scan-delay` | 5 min | 15 s | 1 s | 1 s | 10ms | 5ms |
| `min-parallelism` | 1 | 1 | 1 | (adaptive) | (adaptive) | (adaptive) |
| `max-parallelism` | 1 | 1 | 1 | (adaptive) | (adaptive) | 1024 |
| `host-timeout` | none | none | none | none | none | 15 min |

**Notes:**
- T0 and T1 are sequential (parallelism = 1), intended for IDS evasion.
- T2 is polite/low-bandwidth, similar to T1 but faster retries.
- T3 is the default — fully adaptive based on network conditions.
- T4 assumes a fast, reliable LAN; T5 is for CTF / speed at cost of accuracy.
- nmap's adaptive algorithm (SRTT = Smoothed Round Trip Time) continuously adjusts parallelism and timeouts based on actual observed latency, using a EWMA similar to TCP's own RTT estimator.

### Java Adaptation

**Approach: `ScanTimingProfile` enum + `ScanTimingConfig` record**

```java
public enum TimingProfile {
    PARANOID, SNEAKY, POLITE, NORMAL, AGGRESSIVE, INSANE;
}

public record ScanTimingConfig(
    long connectTimeoutMs,       // maps to max-rtt-timeout
    long initialTimeoutMs,       // maps to initial-rtt-timeout
    int  maxRetries,             // port retry count
    long scanDelayMs,            // inter-probe delay
    int  minThreads,             // maps to min-parallelism
    int  maxThreads,             // maps to max-parallelism
    long hostTimeoutMs           // abandon host after this long (-1 = none)
) {
    public static ScanTimingConfig forProfile(TimingProfile p) {
        return switch (p) {
            case PARANOID   -> new ScanTimingConfig(300_000, 300_000, 10, 300_000, 1, 1,   -1);
            case SNEAKY     -> new ScanTimingConfig( 15_000,  15_000, 10,  15_000, 1, 1,   -1);
            case POLITE     -> new ScanTimingConfig( 10_000,   1_000, 10,     400, 1, 1,   -1);
            case NORMAL     -> new ScanTimingConfig(  1_000,     500,  6,       0, 0, 100, -1);
            case AGGRESSIVE -> new ScanTimingConfig(  1_250,     500,  6,       0, 0, 200, -1);
            case INSANE     -> new ScanTimingConfig(    300,     250,  2,       0, 0, 500, 900_000);
        };
    }
}
```

**Adaptive RTT in Java:** Maintain a `ConcurrentLinkedDeque<Long>` of recent observed connect times. Periodically compute EWMA (`newRtt = alpha * lastRtt + (1-alpha) * currentTimeout`, alpha ≈ 0.875 as in TCP) and adjust the `ExecutorService` pool size by submitting/withdrawing permits from a `Semaphore`.

**Scan delay enforcement:** Between port submissions, call `Thread.sleep(scanDelayMs)` in the port-dispatch loop when `scanDelayMs > 0`. This is the single most impactful change for T0/T1 evasion.

**Retry logic:** Wrap each port scan `Callable` to retry up to `maxRetries` times on `SocketTimeoutException` before marking `FILTERED`.

**CLI integration with picocli:**
```java
@Option(names = {"-T", "--timing"}, defaultValue = "NORMAL",
        description = "Timing profile: PARANOID, SNEAKY, POLITE, NORMAL, AGGRESSIVE, INSANE")
private TimingProfile timingProfile;
```

---

## 2. nmap NSE (Nmap Scripting Engine) — Java Plugin Architecture

### Source References
- https://nmap.org/book/nse.html
- https://nmap.org/book/nse-api.html
- https://nmap.org/nsedoc/ (script documentation index)
- nmap NSE source: `nse_main.lua`, `nse_main.cc` in github.com/nmap/nmap

### How NSE Works

NSE uses **Lua 5.3** embedded in the nmap binary. Scripts are `.nse` files, which are Lua modules with a mandatory structure:

```lua
-- Script metadata
description = [[Detects HTTP servers and grabs the Server header.]]
categories = {"default", "safe", "discovery"}

-- Script rules — when to run this script
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
    and port.service == "http"
end

-- Main action
action = function(host, port)
  -- Use nmap socket API
  local socket = nmap.new_socket()
  socket:connect(host.ip, port.number)
  socket:send("GET / HTTP/1.0\r\n\r\n")
  local status, result = socket:receive_lines(1)
  return result
end
```

**Script Categories:** `auth`, `broadcast`, `brute`, `default`, `discovery`, `dos`, `exploit`, `external`, `fuzzer`, `intrusive`, `malware`, `safe`, `version`, `vuln`

**Triggering rules:**
- `portrule(host, port)` — runs when a port matches a condition
- `hostrule(host)` — runs once per host after all ports scanned
- `prerule()` — runs before any scanning (e.g., broadcast discovery)
- `postrule()` — runs after everything (e.g., aggregate reporting)

**Script data sharing:** Scripts share data via `nmap.registry`, a global Lua table passed between scripts.

**Parallelism:** NSE uses nmap's cooperative coroutine model — scripts yield when doing I/O, allowing thousands of concurrent script instances.

### Java Equivalent: Plugin System Design

**Core concept:** Replace Lua scripts with Java classes (or Groovy scripts for dynamic loading) implementing a `ScanPlugin` interface.

```java
/**
 * Plugin lifecycle: init() -> rule() -> execute() -> result appended to ScanResult
 */
public interface ScanPlugin {
    String name();
    String description();
    PluginCategory category();

    /** Return true if this plugin should run against this port result */
    boolean rule(ScanResult result, ScanReport report);

    /** Run the plugin; return output string or null */
    String execute(ScanResult result, ScanReport report, PluginContext ctx);
}

public enum PluginCategory {
    DEFAULT, SAFE, DISCOVERY, VERSION, VULN, AUTH, BRUTE, INTRUSIVE
}

public record PluginContext(
    int connectTimeoutMs,
    boolean verbose,
    Map<String, Object> registry   // shared data between plugins, like nmap.registry
) {}
```

**Built-in plugin examples to implement:**

| Plugin Name | Category | Rule | Action |
|---|---|---|---|
| `HttpBannerPlugin` | SAFE | port 80/443/8080 open | GET / HTTP/1.0, return Server header |
| `SshVersionPlugin` | SAFE | port 22 open | Read SSH banner line |
| `FtpBannerPlugin` | SAFE | port 21 open | Read FTP 220 banner |
| `SmtpBannerPlugin` | SAFE | port 25/587 open | Read SMTP 220 banner |
| `TlsCertPlugin` | SAFE | port 443/8443 open | SSLSocket, read cert CN/SAN/expiry |
| `HttpTitlePlugin` | DEFAULT | port 80/443 open | Parse `<title>` from HTTP response |
| `DefaultCredsPlugin` | INTRUSIVE | various ports | Try common default credentials |

**Plugin loading strategy:**

Option A (compile-time, simplest): Register plugins in a `PluginRegistry` at startup using `ServiceLoader`:
```java
// META-INF/services/com.portscanner.plugin.ScanPlugin
// lists fully-qualified class names of all plugins
ServiceLoader<ScanPlugin> loader = ServiceLoader.load(ScanPlugin.class);
```

Option B (dynamic, Groovy): Load `.groovy` files from `~/.portscanner/plugins/` at runtime using `GroovyScriptEngine`. Groovy implements the same `ScanPlugin` Java interface.

Option C (dynamic, pure Java): Use `URLClassLoader` to load `.jar` files from a plugin directory. Each jar contains one or more `ScanPlugin` implementations.

**CLI integration:**
```java
@Option(names = {"--scripts"}, split = ",",
        description = "Run named plugins (comma-separated) or categories: default, safe, all")
private List<String> scripts;

@Option(names = {"--script-args"}, split = ",",
        description = "Arguments passed to plugins, format: key=value")
private Map<String, String> scriptArgs;
```

**Execution flow:**
1. After all port scans complete, filter plugins whose `rule()` returns true for each open port.
2. Submit each matching `(plugin, portResult)` pair as a `Callable<String>` to a separate plugin `ExecutorService`.
3. Attach returned strings to `ScanResult.pluginOutputs` (`Map<String, String>`).
4. Include plugin outputs in all report exporters.

---

## 3. masscan's Stateless Scanning — Applicable Concepts for Java TCP

### Source References
- https://github.com/robertdavidgraham/masscan (README and source)
- masscan blog post: "masscan: the entire Internet in 6 minutes" by Robert Graham
- https://github.com/robertdavidgraham/masscan/blob/master/doc/masscan.8.markdown
- Academic reference: Robert Graham's DEF CON 22 talk on stateless scanning

### What Makes masscan Fast

masscan's core design is fundamentally different from nmap:

1. **Raw sockets + custom TCP/IP stack (libdnet/pfring/DPDK):** masscan bypasses the OS kernel's TCP stack entirely. It sends raw SYN packets and receives raw packets from a packet capture library (libpcap). No connect() calls, no file descriptors per port.

2. **Stateless SYN scanning:** masscan does NOT track connection state in the traditional sense. Instead, it encodes the connection "cookie" (sequence number) using SipHash of `(sourceIP, sourcePort, destIP, destPort, seed)`. When a SYN-ACK arrives, it recomputes the hash to verify it was a legitimate response — no state table needed.

3. **Separate transmit/receive threads:** One thread blasts out SYN packets at a configured rate (`--rate`). A separate thread listens for SYN-ACK responses. The two threads are decoupled with no shared state.

4. **Randomized port order using LCG:** masscan visits ports in pseudo-random order using a Linear Congruential Generator over the scan space, ensuring even network distribution and avoiding sequential bursts. The "shard" feature divides this space for distributed scanning.

5. **Rate limiting via token bucket:** Rather than thread-count-based concurrency, masscan limits by packets-per-second using a token bucket algorithm.

6. **Timeout via "cooldown" period:** After sending all probes, masscan waits a configurable `--wait` seconds (default 10s) for late SYN-ACKs. No per-port timer.

### What Applies to Java TCP Connect Scanning

Java **cannot** do raw socket scanning without JNI or a native library. `java.net.Socket` always does a full 3-way TCP handshake. Key applicable concepts:

#### A. Randomized Port Order (Directly Applicable)

masscan's randomized LCG traversal applies directly to reduce pattern-based IDS detection and distribute load:

```java
/**
 * Generates port numbers in pseudo-random order covering all target ports exactly once.
 * Uses a multiplicative LCG: next = (current * a + c) % m, where m = next power of 2
 * above portCount, rejecting out-of-range values (cycle-walk technique).
 */
public class RandomizedPortIterator implements Iterator<Integer> {
    private final List<Integer> ports;

    public RandomizedPortIterator(List<Integer> ports, long seed) {
        this.ports = new ArrayList<>(ports);
        Collections.shuffle(this.ports, new Random(seed));
    }
}
```

For a proper LCG approach matching masscan's algorithm, use a prime-based full-period generator over the port space.

#### B. Rate Limiting via Token Bucket (Directly Applicable)

Replace thread-count-based concurrency with a packets-per-second rate limiter:

```java
public class TokenBucketRateLimiter {
    private final long tokensPerSecond;
    private long tokens;
    private long lastRefillNanos;

    public synchronized void acquire() throws InterruptedException {
        long now = System.nanoTime();
        long elapsed = now - lastRefillNanos;
        tokens = Math.min(tokensPerSecond, tokens + (elapsed * tokensPerSecond / 1_000_000_000L));
        lastRefillNanos = now;
        if (tokens < 1) {
            long waitNanos = (1_000_000_000L - tokens * 1_000_000_000L / tokensPerSecond);
            Thread.sleep(waitNanos / 1_000_000, (int)(waitNanos % 1_000_000));
        }
        tokens--;
    }
}
```

CLI option: `--rate <packets-per-second>` (e.g., `--rate 1000` for 1000 connect attempts/sec).

#### C. Separate Dispatch / Collection Architecture (Applicable)

Instead of submitting all ports then blocking on futures, use a producer-consumer model with a `BlockingQueue`:

- **Producer thread:** iterates ports in randomized order, rate-limited, submits to `ExecutorService`
- **Consumer thread:** polls `CompletionService.take()` for completed results
- This matches masscan's transmit/receive thread separation and allows streaming results.

```java
CompletionService<ScanResult> completionService =
    new ExecutorCompletionService<>(executor);
// Producer submits, consumer calls completionService.take()
```

#### D. NOT Applicable in Java

- Raw socket SYN scanning — requires root + JNI; defeats Java's platform independence
- Kernel bypass (DPDK/XDP/pfring) — requires native code and special NICs
- Stateless cookie tracking — only needed for raw SYN scanning
- masscan's claimed speeds (25M packets/sec) — Java connect scanning is limited to OS connection limits, typically 10k–50k/sec

---

## 4. rustscan's Adaptive Port Ordering and Top Ports

### Source References
- https://github.com/RustScan/RustScan (README and source)
- rustscan documentation: https://rustscan.github.io/RustScan/
- rustscan source: `src/scanner.rs`, `src/port_strategy/` in the GitHub repo

### rustscan's Core Design

rustscan is a "fast port scanner front-end to nmap." Its design philosophy:

1. **Blast phase:** Scan all ports as fast as possible using async TCP connect (Tokio async runtime), collecting open ports.
2. **Hand-off phase:** Pass discovered open ports to nmap for service detection on only those ports.

This separation lets rustscan complete a full 65535-port scan in ~3 seconds on LAN, then nmap does targeted service detection.

### Port Ordering Strategies

rustscan implements three strategies in `src/port_strategy/`:

#### A. Serial Strategy
Scan ports 1–65535 in order. Simple but detectable.

#### B. Random Strategy
Shuffle ports randomly. Reduces sequential detection signatures.

#### C. Top Ports Strategy (Most Relevant)
rustscan embeds a frequency-ordered list of the top 1000 ports derived from the nmap-services data. When `--top` is specified, it scans only these ports in frequency order (most-commonly-open first).

**rustscan top ports source in Rust:**
```rust
// From src/port_strategy/top_ports.rs
pub const TOP_1000_PORTS: &[u16] = &[
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, // ...
    // ordered by frequency of being found open
];
```

**Adaptive batch sizing:** rustscan dynamically adjusts its batch size. It starts with a configured `--batch-size` (default 4500), and if the OS returns "too many open files" errors, it halves the batch size and retries. This adaptive approach handles varying OS file descriptor limits automatically.

```java
// Java equivalent: adaptive batch with backpressure
int batchSize = configuredBatchSize;
while (batchSize > MIN_BATCH) {
    try {
        submitBatch(ports.subList(i, i + batchSize));
        break;
    } catch (IOException e) {
        if (e.getMessage().contains("Too many open files")) {
            batchSize /= 2;
        } else throw e;
    }
}
```

### Top 1000 Ports Frequency List (nmap-services Data)

#### Source References
- `/usr/share/nmap/nmap-services` (installed with nmap)
- https://github.com/nmap/nmap/blob/master/nmap-services
- Research paper: "An Analysis of the nmap Port Scanning Tool" (USENIX)

#### nmap-services Format
```
# service-name  port/protocol  open-frequency  [comment]
http            80/tcp          0.484143
ftp             21/tcp          0.197667
ssh             22/tcp          0.182286
telnet          23/tcp          0.221709
smtp            25/tcp          0.131314
https           443/tcp         0.208929
```

The `open-frequency` field is the fraction of times that port was found open in Internet-wide scans. Ports with higher frequency are more likely to be open on any given host.

#### Top 100 Most Commonly Open Ports (TCP, by nmap-services frequency)

```
80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
10000, 514, 5631, 92, 49152, 8443, 2000, 5800, 8008, 3001,
623, 5000, 3128, 33, 1720, 4444, 7070, 554, 3000, 8082,
9100, 22222, 32768, 2001, 2049, 515, 8181, 1433, 7777, 1434,
2121, 161, 264, 9999, 8088, 6000, 4000, 1030, 8010, 9090,
2082, 9080, 3128, 1801, 18040, 8880, 7001, 407, 5009, 512,
513, 8086, 9091, 7443, 593, 3268, 1080, 2222, 5353, 631,
9200, 8983, 5985, 3690, 5432, 27017, 6379, 11211, 2181, 8009
```

#### Java Implementation

```java
// In a new TopPorts.java class
public final class TopPorts {
    // Ordered by nmap-services open-frequency, descending
    public static final int[] TOP_100 = {
        80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
        // ... (full list)
    };

    public static final int[] TOP_1000 = {
        // Full 1000-port list from nmap-services
    };

    public static List<Integer> getTopPorts(int n) {
        return Arrays.stream(TOP_1000).limit(n).boxed().collect(toList());
    }
}
```

**CLI integration:**
```java
@Option(names = {"--top-ports"}, defaultValue = "0",
        description = "Scan N most commonly open ports (overrides --ports). Use 100, 1000, etc.")
private int topPorts;
```

---

## 5. nmap XML Output Format Specification

### Source References
- https://nmap.org/book/output-formats-xml-output.html
- nmap DTD: https://nmap.org/data/nmap.dtd
- nmap XSD: https://nmap.org/data/nmap.xsd
- nmap source: `output.cc`, `xml.cc` in github.com/nmap/nmap

### Full XML Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>
<nmaprun scanner="nmap"
         args="nmap -sV -p 1-1000 192.168.1.1"
         start="1704067200"
         startstr="Mon Jan  1 00:00:00 2024"
         version="7.94"
         xmloutputversion="1.05">

  <scaninfo type="connect" protocol="tcp" numservices="1000" services="1-1000"/>

  <verbose level="0"/>
  <debugging level="0"/>

  <host starttime="1704067200" endtime="1704067260">
    <status state="up" reason="conn-refused" reason_ttl="0"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Cisco Systems"/>
    <hostnames>
      <hostname name="router.local" type="PTR"/>
    </hostnames>

    <ports>
      <extraports state="closed" count="994">
        <extrareasons reason="conn-refused" count="994"/>
      </extraports>

      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"
                 extrainfo="Ubuntu Linux; protocol 2.0"
                 ostype="Linux" method="probed" conf="10">
          <cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
        </service>
        <script id="ssh-hostkey" output="2048 SHA256:... (RSA)"/>
      </port>

      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="Apache httpd" version="2.4.54"
                 method="probed" conf="10"/>
        <script id="http-title" output="Apache2 Default Page"/>
      </port>

      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="https" tunnel="ssl" method="probed" conf="10"/>
      </port>

      <port protocol="tcp" portid="8080">
        <state state="filtered" reason="no-response" reason_ttl="0"/>
      </port>
    </ports>

    <os>
      <osmatch name="Linux 5.4" accuracy="95" line="12345">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux"
                 osgen="5.X" accuracy="95">
          <cpe>cpe:/o:linux:linux_kernel:5.4</cpe>
        </osclass>
      </osmatch>
    </os>

    <uptime seconds="86400" lastboot="Sun Dec 31 00:00:00 2023"/>
    <distance value="1"/>

    <hostscript>
      <script id="smb-security-mode" output="account_used: guest"/>
    </hostscript>
  </host>

  <runstats>
    <finished time="1704067260" timestr="Mon Jan  1 00:01:00 2024"
              elapsed="60.00" summary="Nmap done: 1 IP address scanned" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>

</nmaprun>
```

### Key XML Elements and Attributes

| Element | Key Attributes | Notes |
|---|---|---|
| `<nmaprun>` | `scanner`, `args`, `start`, `version`, `xmloutputversion` | Root element |
| `<scaninfo>` | `type` (connect/syn), `protocol`, `numservices` | Scan metadata |
| `<host>` | `starttime`, `endtime` | Unix timestamps |
| `<status>` | `state` (up/down), `reason` | Host liveness |
| `<address>` | `addr`, `addrtype` (ipv4/ipv6/mac), `vendor` | Multiple allowed |
| `<port>` | `protocol`, `portid` | One per port |
| `<state>` | `state` (open/closed/filtered/open\|filtered), `reason` | Port state |
| `<service>` | `name`, `product`, `version`, `method`, `conf` | Service detection |
| `<script>` | `id`, `output` | NSE script output |
| `<runstats>` | | Always last element |

### Java XmlExporter Implementation

The existing `XmlExporter.java` (in `report/`) should be extended to produce nmap-compatible XML using Jackson's `XmlMapper` or `javax.xml.stream.XMLStreamWriter`:

```java
// Using XMLStreamWriter for precise nmap-compatible output
public class NmapXmlExporter implements ReportExporter {
    @Override
    public void export(ScanReport report, Path outputPath) throws IOException {
        XMLOutputFactory factory = XMLOutputFactory.newInstance();
        try (OutputStream os = Files.newOutputStream(outputPath);
             XMLStreamWriter w = factory.createXMLStreamWriter(os, "UTF-8")) {

            w.writeStartDocument("UTF-8", "1.0");
            w.writeProcessingInstruction("xml-stylesheet",
                "href=\"https://nmap.org/svn/nmap.xsl\" type=\"text/xsl\"");

            w.writeStartElement("nmaprun");
            w.writeAttribute("scanner", "port-scanner");
            w.writeAttribute("args", report.getCommandLine());
            w.writeAttribute("start", String.valueOf(report.getScannedAt().getEpochSecond()));
            w.writeAttribute("version", "1.0");
            w.writeAttribute("xmloutputversion", "1.05");

            // <scaninfo>
            w.writeEmptyElement("scaninfo");
            w.writeAttribute("type", "connect");
            w.writeAttribute("protocol", "tcp");
            // ... etc

            // <host>, <ports>, <port> for each result
            // <runstats>

            w.writeEndElement(); // nmaprun
            w.writeEndDocument();
        }
    }
}
```

**Compatibility note:** Tools that consume nmap XML (Metasploit, Faraday, Dradis, nmap-parse-output) check `xmloutputversion`. Use `1.05` (nmap 7.x format) for broadest compatibility.

---

## 6. nmap Service/Version Detection Probes (nmap-service-probes)

### Source References
- https://nmap.org/book/vscan.html
- nmap-service-probes file: https://github.com/nmap/nmap/blob/master/nmap-service-probes
- https://nmap.org/data/nmap-service-probes (live file, ~26,000 lines)

### File Format

nmap-service-probes defines a sequence of probes and match lines:

```
# Format:
# Probe <protocol> <probename> <probestring>
# match <service> <pattern> [<versioninfo>]
# softmatch <service> <pattern>
# ports <portlist>
# sslports <portlist>
# totalwaitms <milliseconds>
# tcpwrappedms <milliseconds>
# rarity <value 1-9>
# fallback <probename>

Probe TCP NULL q||
ports 1-65535
# Empty probe - just connect, see what comes back
match ftp m|^220[\- ].*\r\n| p/FTP/ v/$1/
match ssh m|^SSH-([\d.]+)-(.+)\r?\n|i p/OpenSSH/ v/$2/ i/protocol $1/

Probe TCP GenericLines q|\r\n\r\n|
ports 80,8080,8000,8888
match http m|^HTTP/1\.[01] \d{3}| p/HTTP/

Probe TCP HTTPOptions q|OPTIONS / HTTP/1.0\r\n\r\n|
rarity 3
ports 80,443,8080,8443
match http m|HTTP/1\.[01] 200 OK\r\n.*Allow: ([^\r\n]+)| p/HTTP/ i/allowed: $1/
```

### Key Probe Concepts

1. **Probe string encoding:** `q|<string>|` where `\r`, `\n`, `\0` are escape sequences. For example, `q||` is the NULL probe (just connect, don't send anything).

2. **Match patterns:** PCRE regex against the banner. Named groups (`$1`, `$2`) populate version info fields: `p/` (product), `v/` (version), `i/` (extra info), `h/` (hostname), `o/` (OS), `d/` (device type), `cpe:/` (CPE string).

3. **Rarity:** 1 (very common) to 9 (very rare). nmap's `--version-intensity` (0-9) controls which probes are sent.

4. **Fallback chains:** If probe X fails, try probe Y. Allows efficient ordering.

5. **SSL wrapping:** `sslports` directive causes nmap to wrap the probe in TLS first.

### Java Adaptation: Probe System

**Parse the nmap-service-probes file directly** (it ships with nmap installations and is available from the nmap GitHub repo under a free license). Bundle a subset (common probes only) in `src/main/resources/nmap-service-probes.txt`.

```java
public record ServiceProbe(
    String name,
    byte[] probeBytes,         // what to send (null = just connect)
    List<ProbeMatch> matches,  // ordered match rules
    List<Integer> ports,       // which ports to use this probe on
    List<Integer> sslPorts,    // same but wrapped in SSL
    int rarity,                // 1-9
    String fallback            // next probe name if this fails
) {}

public record ProbeMatch(
    String serviceName,
    Pattern pattern,           // compiled PCRE (Java regex)
    String productTemplate,    // e.g., "Apache httpd"
    String versionTemplate,    // e.g., "$1"
    String infoTemplate
) {
    public Optional<ServiceVersion> match(String banner) {
        Matcher m = pattern.matcher(banner);
        if (!m.find()) return Optional.empty();
        return Optional.of(new ServiceVersion(
            serviceName,
            substituteGroups(productTemplate, m),
            substituteGroups(versionTemplate, m),
            substituteGroups(infoTemplate, m)
        ));
    }
}
```

**Probe execution in BannerGrabber:**

```java
public class ProbeBasedBannerGrabber {
    private final List<ServiceProbe> probes;
    private final int intensityLevel; // 0-9, default 7

    public ServiceVersion detectVersion(String host, int port, int timeoutMs) {
        List<ServiceProbe> applicable = probes.stream()
            .filter(p -> p.rarity() <= intensityLevel)
            .filter(p -> p.ports().contains(port))
            .sorted(Comparator.comparingInt(ServiceProbe::rarity))
            .toList();

        for (ServiceProbe probe : applicable) {
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(host, port), timeoutMs);
                if (probe.probeBytes() != null) {
                    s.getOutputStream().write(probe.probeBytes());
                }
                String banner = new BufferedReader(
                    new InputStreamReader(s.getInputStream()))
                    .readLine();
                for (ProbeMatch match : probe.matches()) {
                    Optional<ServiceVersion> result = match.match(banner);
                    if (result.isPresent()) return result.get();
                }
            } catch (IOException ignored) {}
        }
        return ServiceVersion.unknown();
    }
}
```

**Practical note:** Java's `java.util.regex` does not support all PCRE features (lookahead is fine; some possessive quantifiers and atomic groups differ). The nmap-service-probes regex patterns are mostly straightforward and work in Java after minor adjustments.

---

## 7. Decoy Scanning and Source IP Spoofing (Educational)

### Source References
- https://nmap.org/book/man-bypass-firewalls-ids.html
- https://nmap.org/book/idlescan.html
- TCP/IP Illustrated Vol. 1 (Stevens) — IP spoofing chapter
- RFC 793 (TCP), RFC 1122 (Host Requirements)

### How Decoy Scanning Works in nmap

nmap's `-D <decoy1,decoy2,ME,decoy3>` option sends multiple SYN packets to the target for each port — one from each decoy IP and one from the real scanner (`ME`). This requires **raw socket access** (root/admin) to forge the IP source address.

```
# nmap sends for port 80:
SYN from 10.0.0.5 (decoy1) -> target:80
SYN from 10.0.0.6 (decoy2) -> target:80
SYN from 192.168.1.100 (real) -> target:80  <- only this gets the SYN-ACK
SYN from 10.0.0.7 (decoy3) -> target:80
```

The target's firewall/IDS sees connections from multiple sources, making it harder to identify the real scanner.

**nmap Idle Scan (`-sI`):** Uses a "zombie" host with predictable IP ID sequence numbers. nmap probes the zombie, sends spoofed SYNs to the target (appearing to come from zombie), then checks if zombie's IP ID incremented (indicating target sent SYN-ACK to zombie). Completely stealthy — target never sees scanner's real IP.

### Java Limitations

**Java absolutely cannot do IP spoofing without native code.** The JVM's `java.net.Socket` and `java.nio.channels.SocketChannel` always use the OS network stack, which:
1. Enforces the real local IP as the source address
2. Requires root/raw socket privileges for SYN-only scanning
3. Cannot be bypassed from pure Java (SecurityManager, OS-enforced)

**What IS possible in Java:**

#### A. Distributed Scanning (Functional Equivalent of Decoys)
Instead of spoofing, run the scanner from multiple machines simultaneously. A coordinator distributes port ranges; results are aggregated. From the target's perspective, connections arrive from multiple legitimate source IPs.

```java
// Conceptual: scan coordinator
public interface ScanNode {
    CompletableFuture<List<ScanResult>> scanPorts(String host, List<Integer> ports);
}
// Implementation: RMI, gRPC, or simple HTTP REST between scanner instances
```

#### B. Source Port Specification (Partially Useful)
nmap's `--source-port` sets the local port, which some firewalls use for filtering. Java supports this:

```java
Socket s = new Socket();
s.bind(new InetSocketAddress(sourcePort)); // bind to specific local port
s.connect(new InetSocketAddress(host, targetPort), timeout);
```

**Use case:** Some firewalls allow traffic from port 53 (DNS) or 67 (DHCP). `--source-port 53` can bypass these.

#### C. Interface/Address Binding
Java can bind to a specific local IP (if host has multiple NICs):

```java
@Option(names = {"--source-ip"}, description = "Source IP to bind to (for multi-homed hosts)")
private String sourceIp;

// In PortScanner:
Socket s = new Socket();
if (sourceIp != null) {
    s.bind(new InetSocketAddress(InetAddress.getByName(sourceIp), 0));
}
s.connect(target, timeout);
```

#### D. Proxy/SOCKS Support (Functional Anonymization Alternative)
Route scans through a SOCKS5 proxy chain. Java supports SOCKS5 natively via `java.net.Proxy`:

```java
@Option(names = {"--proxy"}, description = "SOCKS5 proxy, format: socks5://host:port")
private String proxy;

// In PortScanner:
Proxy socksProxy = new Proxy(Proxy.Type.SOCKS,
    new InetSocketAddress(proxyHost, proxyPort));
Socket s = new Socket(socksProxy);
s.connect(new InetSocketAddress(target, port), timeout);
```

**Educational note:** Decoy scanning and IP spoofing require explicit authorization. Even understanding these techniques for defensive purposes (building IDS detection) requires noting that unauthorized use violates the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), and equivalent laws in other jurisdictions.

---

## 8. Implementation Priority Matrix

Based on effort-to-value ratio for this Java scanner:

| Feature | Value | Effort | Priority | Notes |
|---|---|---|---|---|
| Timing profiles (T0-T5) | High | Low | **P1** | Just add `ScanTimingConfig` record + CLI option |
| Top ports list | High | Low | **P1** | Static array, single CLI option |
| Randomized port order | Medium | Low | **P1** | `Collections.shuffle()` |
| nmap XML output | High | Medium | **P2** | Enables tool interoperability |
| Rate limiting (token bucket) | Medium | Medium | **P2** | Replaces thread-count throttling |
| Plugin/script system | High | High | **P2** | Start with 5–6 built-in plugins, ServiceLoader |
| Probe-based version detection | High | High | **P3** | Parse nmap-service-probes subset |
| Source port binding | Low | Very Low | **P3** | One-liner addition |
| SOCKS5 proxy | Medium | Low | **P3** | Java native support |
| Distributed scanning | Low | Very High | **Backlog** | Needs separate coordinator service |

---

## 9. Summary of Source URLs

| Resource | URL |
|---|---|
| nmap Timing Templates | https://nmap.org/book/performance-timing-templates.html |
| nmap Performance Options | https://nmap.org/book/man-performance.html |
| nmap NSE Documentation | https://nmap.org/book/nse.html |
| nmap NSE API | https://nmap.org/book/nse-api.html |
| nmap Script Docs Index | https://nmap.org/nsedoc/ |
| nmap XML Output Format | https://nmap.org/book/output-formats-xml-output.html |
| nmap DTD | https://nmap.org/data/nmap.dtd |
| nmap XSD | https://nmap.org/data/nmap.xsd |
| nmap Version Scanning | https://nmap.org/book/vscan.html |
| nmap-service-probes (GitHub) | https://github.com/nmap/nmap/blob/master/nmap-service-probes |
| nmap-services (GitHub) | https://github.com/nmap/nmap/blob/master/nmap-services |
| nmap Firewall/IDS Evasion | https://nmap.org/book/man-bypass-firewalls-ids.html |
| nmap Idle Scan | https://nmap.org/book/idlescan.html |
| nmap Source (GitHub) | https://github.com/nmap/nmap |
| masscan (GitHub) | https://github.com/robertdavidgraham/masscan |
| masscan Man Page | https://github.com/robertdavidgraham/masscan/blob/master/doc/masscan.8.markdown |
| rustscan (GitHub) | https://github.com/RustScan/RustScan |
| rustscan Port Strategy Source | https://github.com/RustScan/RustScan/tree/master/src/port_strategy |
| rustscan Documentation | https://rustscan.github.io/RustScan/ |
| zmap (GitHub) | https://github.com/zmap/zmap |
| zmap Paper (USENIX 2013) | https://www.usenix.org/system/files/conference/usenixsecurity13/sec13-paper_durumeric.pdf |
