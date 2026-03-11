# Advanced Port Scanning & Network Scanning Techniques
## Research Findings for Java CLI Port Scanner

**Date:** 2026-03-11
**Author:** Claude Code (claude-sonnet-4-6) — compiled from existing knowledge (cutoff: August 2025)
**Note:** Web search was unavailable during this session. Source URLs are canonical references to be verified manually.

---

## Table of Contents

1. [OS Fingerprinting Techniques](#1-os-fingerprinting-techniques)
2. [Service Version Detection Beyond Banner Grabbing](#2-service-version-detection-beyond-banner-grabbing)
3. [SYN Scan Alternatives Without Raw Sockets](#3-syn-scan-alternatives-without-raw-sockets)
4. [SSL/TLS Port Inspection](#4-ssltls-port-inspection)
5. [HTTP/HTTPS Service Probing & Framework Detection](#5-httphttps-service-probing--framework-detection)
6. [Integration Notes for This Project](#6-integration-notes-for-this-project)

---

## 1. OS Fingerprinting Techniques

### Overview

OS fingerprinting infers the remote operating system by examining observable network stack behaviors.
Nmap's OS detection engine (described in the nmap book, Chapter 8) uses a battery of TCP, UDP, and ICMP
probes and compares responses against a database of ~2,500 OS signatures. Java cannot replicate the full
nmap approach without raw sockets (which require elevated privileges and a native library like pcap4j),
but several passive and semi-passive techniques are achievable with standard Java sockets.

### 1.1 TTL-Based OS Inference (Passive, Achievable)

**Technique:** The initial Time-To-Live (TTL) value set by an OS when it sends a TCP SYN-ACK is
OS-specific. By sending a connect() and measuring the TTL of the response packet, the OS family can be
inferred.

| TTL Range Observed | Likely OS Family        |
|--------------------|-------------------------|
| 64                 | Linux, macOS, Android   |
| 128                | Windows (all versions)  |
| 255                | Cisco IOS, Solaris, BSD |
| 60                 | Older HP-UX             |

**Java Implementation Approach:**

Java's standard `java.net.Socket` does not expose the incoming packet's TTL. To read TTL from received
packets you need one of these approaches:

**Option A — Java's `InetAddress.isReachable()` with raw ICMP (limited):**
`InetAddress.isReachable(timeout)` uses ICMP Echo on Unix (requires root) or TCP port 7 on Windows.
It does not expose TTL. This is a dead end for TTL reading.

**Option B — Pcap4J (recommended for full OS fingerprinting):**
Pcap4J is a pure-Java wrapper around libpcap/WinPcap/Npcap. It allows capturing raw packets and
inspecting IP headers including TTL fields.

```java
// Dependency (Maven):
// <groupId>org.pcap4j</groupId>
// <artifactId>pcap4j-core</artifactId>
// <version>1.8.2</version>

PcapNetworkInterface nif = Pcaps.getDevByName("eth0");
PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
handle.setFilter("tcp and src host " + targetIp, BpfProgram.BpfCompileMode.OPTIMIZE);
handle.loop(10, (PacketListener) packet -> {
    IpV4Packet ipPacket = packet.get(IpV4Packet.class);
    if (ipPacket != null) {
        int ttl = ipPacket.getHeader().getTtlAsInt();
        // Map TTL to OS family
    }
});
```

**Option C — /proc/net/tcp parsing (Linux-only, no extra dependencies):**
On Linux, `/proc/net/tcp` shows socket state but not TTL. This does not help with TTL.

**Option D — ProcessBuilder + system tools (cross-platform hack):**
Run `ping -c 1 <host>` and parse the TTL field from ping output. Fragile but dependency-free.

```java
Process p = new ProcessBuilder("ping", "-c", "1", host).start();
String output = new String(p.getInputStream().readAllBytes());
// Parse "ttl=64" from output using regex: Pattern.compile("ttl=(\\d+)", Pattern.CASE_INSENSITIVE)
```

**Limitations:** TTL observed by the scanner has already been decremented by hops in transit. To get the
original TTL, add the hop count (from traceroute) to the observed TTL, then round up to the nearest
common initial value (64, 128, or 255).

### 1.2 TCP Window Size Fingerprinting (Requires Pcap4J)

**Technique:** The TCP window size in a SYN-ACK is OS-specific:

| TCP Window Size | OS                         |
|-----------------|----------------------------|
| 65535           | Windows XP / macOS older   |
| 8192            | Windows Vista/7/8/10/11    |
| 5840            | Linux 2.4 kernel           |
| 14600           | Linux 2.6+ (common)        |
| 65535           | FreeBSD / OpenBSD          |
| 4128            | Cisco IOS                  |

**Java Implementation:** Requires pcap4j to inspect the TCP header of the incoming SYN-ACK packet.

```java
TcpPacket tcpPacket = packet.get(TcpPacket.class);
if (tcpPacket != null && tcpPacket.getHeader().isSyn() && tcpPacket.getHeader().isAck()) {
    int windowSize = tcpPacket.getHeader().getWindowAsInt();
    // Match against signature database
}
```

### 1.3 TCP Options Fingerprinting (Requires Pcap4J)

**Technique:** The TCP options present in a SYN-ACK, their order, and their values form a signature:
- **MSS (Maximum Segment Size):** 1460 = Ethernet; 512 = some Windows; 536 = conservative default
- **SACK (Selective Acknowledgment):** Present in Linux, Windows Vista+; absent in some older systems
- **Timestamps (RFC 1323):** Present in Linux/macOS; absent in many Windows versions by default
- **Window Scale:** Present in modern OSes; value differs
- **NOP padding order:** OS-specific alignment preference

Nmap encodes the TCP options sequence as a string like `M*NW6ST` in its OS fingerprint database
(see: `/usr/share/nmap/nmap-os-db`).

**Java Implementation:** Pcap4J exposes TCP options as a list:

```java
List<TcpOption> options = tcpPacket.getHeader().getOptions();
StringBuilder optionSignature = new StringBuilder();
for (TcpOption opt : options) {
    optionSignature.append(opt.getKind().name()).append(",");
}
// Compare optionSignature against a local OS signature map
```

**Practical recommendation:** For a Java CLI tool without native library dependencies, limit OS
fingerprinting to TTL parsing via ping output (Option D above) and document pcap4j as an optional
enhanced mode enabled with a `--os-detect` flag. The model class `ScanResult` could gain a
`String osGuess` field.

**Reference:** Nmap OS Detection internals — https://nmap.org/book/osdetect.html
**Reference:** Pcap4J project — https://www.pcap4j.org/

---

## 2. Service Version Detection Beyond Banner Grabbing

### Overview

The current implementation reads the first line of a socket's InputStream as a banner. This is sufficient
for self-announcing protocols (FTP, SSH, SMTP) but misses services that require a specific handshake
before they respond, or that respond on the application layer only (HTTP, TLS, databases).

Nmap's version detection (`-sV`) works by sending a sequence of probes from `nmap-service-probes` and
matching responses against ~11,000 regex patterns. This section defines a tractable subset for Java.

### 2.1 Protocol-Specific Handshakes

The current `Probe` interface (payload-only) is the right foundation. Each probe below would be a new
`implements Probe` class with a richer response matcher.

#### 2.1.1 MySQL/MariaDB Detection (Port 3306)

MySQL sends an initial handshake packet immediately on connect. The format:
- 3-byte little-endian packet length
- 1-byte packet number (always 0 for initial)
- 1-byte protocol version (10 for MySQL 5+, 9 for older)
- Null-terminated server version string

**Java Implementation:**

```java
// No payload needed — MySQL sends first
public class MysqlProbe implements Probe {
    @Override public byte[] getPayload() { return null; }
    @Override public String getName() { return "MySQL"; }

    public String parseVersion(byte[] response) {
        if (response == null || response.length < 5) return null;
        // Protocol byte at index 4; version string starts at index 5
        int end = 5;
        while (end < response.length && response[end] != 0) end++;
        return new String(response, 5, end - 5, StandardCharsets.UTF_8);
    }
}
```

The `BannerGrabber` currently uses `readLine()` which only captures the first text line. For binary
protocols like MySQL, the grabber needs a raw byte read mode:

```java
byte[] buf = new byte[256];
int read = socket.getInputStream().read(buf);
byte[] response = Arrays.copyOf(buf, read);
```

#### 2.1.2 PostgreSQL Detection (Port 5432)

PostgreSQL does NOT send a banner on connect. The client must send a `StartupMessage` first.
A minimal unauthenticated probe: send a cancel request or an invalid startup to elicit an error response.

```java
// Minimal startup message (4-byte length, 4-byte protocol version 3.0)
byte[] startup = new byte[]{0,0,0,8,  0,3,0,0};
socket.getOutputStream().write(startup);
// Server responds with 'R' (authentication) or 'E' (error), both reveal it's PostgreSQL
int type = socket.getInputStream().read();
// 'R' (82) = AuthenticationRequest, 'E' (69) = ErrorResponse
```

#### 2.1.3 MongoDB Detection (Port 27017)

MongoDB's wire protocol uses an `OP_QUERY` or `OP_MSG`. A simpler approach: attempt TCP connect and
look for the server greeting in newer versions (4.x+) which send a `hello` message on auth failure.
Alternatively, send a minimal `isMaster` OP_QUERY:

```java
// Minimal MongoDB OP_QUERY for isMaster — 41-byte frame
// See: https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/
```

#### 2.1.4 Redis Detection (Port 6379)

Redis speaks a text-based protocol (RESP). Send `PING\r\n` and expect `+PONG\r\n`.

```java
public class RedisProbe implements Probe {
    @Override public byte[] getPayload() { return "*1\r\n$4\r\nPING\r\n".getBytes(StandardCharsets.UTF_8); }
    @Override public String getName() { return "Redis"; }
}
// Response "+PONG" confirms Redis; "-ERR" may reveal Redis with auth required
```

#### 2.1.5 Memcached Detection (Port 11211)

```java
// Send: "version\r\n"
// Expect: "VERSION 1.6.x\r\n"
public class MemcachedProbe implements Probe {
    @Override public byte[] getPayload() { return "version\r\n".getBytes(StandardCharsets.UTF_8); }
    @Override public String getName() { return "Memcached"; }
}
```

#### 2.1.6 DNS Detection (Port 53)

DNS over TCP starts with a 2-byte length prefix. Send a standard query for `version.bind` (CHAOS class)
which many DNS servers answer with their software version string:

```java
// version.bind CHAOS TXT query — 29-byte DNS message
// This is the same query nmap uses for DNS version detection
byte[] dnsQuery = buildVersionBindQuery();
```

#### 2.1.7 RTSP Detection (Port 554)

```java
// Send: "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"
// Expect: "RTSP/1.0 200 OK" or similar
```

### 2.2 Enhancing the Probe Interface for Binary Protocols

The current `Probe` interface returns `byte[] getPayload()` and the grabber reads one line. A richer
design that fits the existing architecture:

```java
public interface Probe {
    byte[] getPayload();
    String getName();

    // NEW: override to parse raw bytes instead of relying on readLine()
    default boolean readRawBytes();  // return true for binary protocols

    // NEW: extract a version string from raw response bytes
    default String parseVersion(byte[] rawResponse) { return null; }
}
```

The `BannerGrabber.grabBanner()` method would branch on `probe.readRawBytes()` to use a byte array
read instead of `BufferedReader.readLine()`.

### 2.3 Response Pattern Matching (Regex-Based Version Extraction)

Rather than hardcoding version parsers per probe, maintain a map of regex patterns applied to banner
strings — similar in concept to nmap-service-probes but much smaller:

```java
// In a new class: VersionExtractor.java
Map<String, Pattern> VERSION_PATTERNS = Map.of(
    "SSH",      Pattern.compile("SSH-(\\S+)"),
    "FTP",      Pattern.compile("(?i)(?:vsFTPd|ProFTPD|FileZilla)\\s+([\\d.]+)"),
    "SMTP",     Pattern.compile("(?i)(?:Postfix|Sendmail|Exim)\\s+([\\d.]+)"),
    "HTTP",     Pattern.compile("(?i)Server:\\s+(\\S+)"),
    "MySQL",    Pattern.compile("([\\d.]+(?:-[A-Za-z]+)?)\\x00")
);
```

The extracted version would be stored as a new field `String serviceVersion` on `ScanResult`.

**Reference:** Nmap service probes file format — https://nmap.org/book/vscan-fileformat.html

---

## 3. SYN Scan Alternatives Without Raw Sockets

### Overview

SYN scan (`-sS` in nmap) requires raw socket access (root/Administrator) to forge TCP packets with
only the SYN flag set, then inspect the SYN-ACK or RST response without completing the handshake.
Java's `java.net.Socket` always performs a full TCP three-way handshake, so true SYN scanning is
not directly achievable. However, several related techniques can be approximated or implemented.

### 3.1 Why FIN/XMAS/NULL Scans Are Not Achievable in Standard Java

FIN scan (`-sF`), XMAS scan (`-sX`), and NULL scan (`-sN`) work by sending TCP segments with
non-standard flag combinations to exploit RFC 793's specification that a closed port must respond
with RST, while an open port silently drops the packet:

- **NULL scan:** No TCP flags set
- **FIN scan:** Only FIN flag set
- **XMAS scan:** FIN + URG + PSH flags set

All three require constructing raw TCP segments — impossible with `java.net.Socket`. They would require
either pcap4j + raw socket access, or a JNI bridge. Additionally, Windows ignores all three scan types
(sends RST for both open and closed ports), making them unreliable even if implementable.

**Verdict:** Do not implement FIN/XMAS/NULL scans in standard Java. Document this limitation clearly
when `--help` is invoked.

### 3.2 Connect Scan Optimizations (Already Partially Implemented)

The current implementation uses blocking `Socket.connect()`. Meaningful optimizations:

#### 3.2.1 NIO-Based Async Connect (Already Implemented via NioPortScanner)

The project already has `NioPortScanner` using `java.nio`. Key optimization: using `Selector` with
`OP_CONNECT` allows a single thread to manage hundreds of in-flight connection attempts simultaneously,
reducing total scan time dramatically vs. thread-per-port.

**Improvement suggestion for `NioPortScanner`:** After the initial connect, also register `OP_READ`
and attempt a one-shot banner read on the same channel before closing, avoiding the separate
`BannerGrabber` reconnection cost.

#### 3.2.2 Adaptive Timeout Tuning

The current timeout is a fixed global value. For LAN targets, a 20–50ms timeout is sufficient.
For WAN targets, 200–500ms is appropriate. An adaptive strategy:

1. Ping the target once (using `InetAddress.isReachable()`) and measure RTT
2. Set `--timeout` automatically to `max(50, rtt * 3)` if not explicitly specified by the user

```java
long start = System.currentTimeMillis();
boolean reachable = InetAddress.getByName(host).isReachable(1000);
long rtt = System.currentTimeMillis() - start;
int adaptiveTimeout = reachable ? (int) Math.max(50, rtt * 3) : 200;
```

#### 3.2.3 Port Ordering for Speed

Scanning ports in random order rather than sequential order reduces detection by simple IDS rules
that look for sequential sweeps. It also reduces scan time on networks that rate-limit sequential
source connections. Implement by shuffling the port list before submitting to the executor.

```java
Collections.shuffle(portList);  // already trivial to add to PortScanner
```

#### 3.2.4 Early-Exit on Refused Connection

`ConnectException` (ECONNREFUSED) arrives near-instantly — no need to wait for the timeout.
The current implementation handles this correctly via exception classification. Ensure the thread
pool is large enough that FILTERED ports (which wait for the full timeout) do not block CLOSED
port results from being processed.

### 3.3 UDP Scan Improvements (Existing UdpScanner)

The project has `UdpScanner`. UDP scanning improvements:

#### 3.3.1 Protocol-Specific UDP Payloads

Sending an empty UDP datagram to most ports yields no response. Protocol-specific payloads
elicit responses that confirm the service:

| Port | Payload | Expected Response |
|------|---------|-------------------|
| 53   | DNS query bytes | DNS response |
| 161  | SNMP GetRequest (v1 community "public") | SNMP response |
| 123  | NTP client request (48 bytes, leap=3) | NTP timestamp response |
| 1900 | `M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n...` | UPnP SSDP response |
| 5353 | mDNS query | mDNS response |
| 69   | TFTP read request | TFTP response / error |

#### 3.3.2 ICMP Port Unreachable Detection

When a UDP datagram hits a closed port, the remote OS sends an ICMP Port Unreachable (type 3, code 3)
back. Java's `DatagramSocket` translates received ICMP Port Unreachable into a `PortUnreachableException`
on the next `receive()` call (on some platforms), which allows distinguishing CLOSED from FILTERED
UDP ports — a key limitation of the current UDP scan.

```java
try {
    socket.receive(responsePacket);
    return PortStatus.OPEN;  // received data
} catch (PortUnreachableException e) {
    return PortStatus.CLOSED;  // ICMP port unreachable received
} catch (SocketTimeoutException e) {
    return PortStatus.FILTERED;  // no response — firewall likely
}
```

**Caveat:** `PortUnreachableException` is only thrown reliably on Linux with JDK 17+. On Windows and
macOS it is unreliable due to ICMP handling differences. Always note the platform in logs.

**Reference:** RFC 793 (TCP) — https://www.rfc-editor.org/rfc/rfc793
**Reference:** Nmap scan types — https://nmap.org/book/man-port-scanning-techniques.html

---

## 4. SSL/TLS Port Inspection

### Overview

Many ports serve TLS-wrapped protocols (HTTPS on 443, SMTPS on 465, IMAPS on 993, LDAPS on 636, etc.).
The current implementation connects a plain `Socket` to these ports and reads a banner, which yields
nothing useful since TLS negotiation must happen first. This section covers how to use Java's
`SSLSocket` and `SSLEngine` to extract rich TLS metadata.

### 4.1 Basic TLS Connection with SSLSocket

**Java Implementation:**

```java
import javax.net.ssl.*;
import java.security.cert.*;

public class TlsInspector {

    public TlsInfo inspect(String host, int port, int timeoutMs) {
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            try (SSLSocket sslSocket = (SSLSocket) factory.createSocket()) {
                sslSocket.connect(new InetSocketAddress(host, port), timeoutMs);
                sslSocket.setSoTimeout(timeoutMs);

                // Disable hostname verification for scanning purposes
                // (target cert may not match hostname used in scan)
                SSLParameters params = sslSocket.getSSLParameters();
                params.setEndpointIdentificationAlgorithm(null);
                sslSocket.setSSLParameters(params);

                sslSocket.startHandshake();
                SSLSession session = sslSocket.getSession();

                return TlsInfo.builder()
                    .protocol(session.getProtocol())           // e.g. "TLSv1.3"
                    .cipherSuite(session.getCipherSuite())     // e.g. "TLS_AES_256_GCM_SHA384"
                    .certificates(session.getPeerCertificates())
                    .build();
            }
        } catch (SSLHandshakeException e) {
            // TLS exists but cert validation failed — still TLS-capable
            return TlsInfo.builder().tlsCapable(true).error(e.getMessage()).build();
        } catch (Exception e) {
            return TlsInfo.builder().tlsCapable(false).build();
        }
    }
}
```

### 4.2 Certificate Inspection

The `session.getPeerCertificates()` array returns `java.security.cert.Certificate[]`. Cast each to
`X509Certificate` for full inspection:

```java
for (Certificate cert : session.getPeerCertificates()) {
    if (cert instanceof X509Certificate x509) {
        String subject    = x509.getSubjectX500Principal().getName();
        String issuer     = x509.getIssuerX500Principal().getName();
        Date notBefore    = x509.getNotBefore();
        Date notAfter     = x509.getNotAfter();
        boolean expired   = notAfter.before(new Date());
        boolean expireSoon = notAfter.before(Date.from(Instant.now().plus(30, ChronoUnit.DAYS)));

        // Extract SANs (Subject Alternative Names)
        Collection<List<?>> sans = x509.getSubjectAlternativeNames();
        // Each List: index 0 = type (2=DNS, 7=IP), index 1 = value string

        // Extract serial number
        BigInteger serial = x509.getSerialNumber();

        // Signature algorithm
        String sigAlg = x509.getSigAlgName();  // e.g. "SHA256withRSA"

        // Public key details
        PublicKey pubKey = x509.getPublicKey();
        int keySize = ((RSAPublicKey) pubKey).getModulus().bitLength();  // for RSA
    }
}
```

### 4.3 Detecting Weak Configurations

After handshake, check for weak configurations and add findings to the scan result:

```java
List<String> weaknesses = new ArrayList<>();
String protocol = session.getProtocol();
if ("SSLv3".equals(protocol) || "TLSv1".equals(protocol) || "TLSv1.1".equals(protocol)) {
    weaknesses.add("DEPRECATED_PROTOCOL:" + protocol);
}
String cipher = session.getCipherSuite();
if (cipher.contains("RC4") || cipher.contains("NULL") || cipher.contains("EXPORT") || cipher.contains("anon")) {
    weaknesses.add("WEAK_CIPHER:" + cipher);
}
if (cipher.contains("DES") && !cipher.contains("3DES")) {
    weaknesses.add("WEAK_CIPHER:DES");
}
```

### 4.4 Enumerating Supported TLS Versions

To enumerate which TLS versions a server supports, make separate connection attempts forcing each
protocol version:

```java
String[] versionsToTest = {"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"};
Map<String, Boolean> supported = new LinkedHashMap<>();
for (String version : versionsToTest) {
    SSLContext ctx = SSLContext.getInstance(version);
    ctx.init(null, trustAllCerts, null);  // use trust-all TrustManager for scanning
    SSLSocketFactory factory = ctx.getSocketFactory();
    try (SSLSocket s = (SSLSocket) factory.createSocket(host, port)) {
        s.setEnabledProtocols(new String[]{version});
        s.startHandshake();
        supported.put(version, true);
    } catch (SSLHandshakeException | SSLException e) {
        supported.put(version, false);
    }
}
```

**Note on TrustManager:** For scanning, use a no-op `X509TrustManager` that accepts all certificates.
This is intentional for a scanner (you are investigating, not authenticating):

```java
TrustManager[] trustAllCerts = new TrustManager[]{
    new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public void checkServerTrusted(X509Certificate[] c, String a) {}
    }
};
SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(null, trustAllCerts, null);
```

### 4.5 STARTTLS Detection

Some protocols (SMTP port 25, IMAP port 143, FTP port 21) upgrade plain connections to TLS via
STARTTLS. The probe logic must send the protocol-specific upgrade command before switching to SSL:

```java
// SMTP STARTTLS example
Socket plain = new Socket(host, 25);
BufferedReader reader = new BufferedReader(new InputStreamReader(plain.getInputStream()));
PrintWriter writer = new PrintWriter(plain.getOutputStream(), true);
reader.readLine();  // read "220 smtp.example.com ESMTP"
writer.println("EHLO scanner");
// Read multi-line EHLO response
String line;
while ((line = reader.readLine()) != null && line.startsWith("250-")) { /* read extensions */ }
writer.println("STARTTLS");
String response = reader.readLine();  // "220 2.0.0 Ready to start TLS"
if (response != null && response.startsWith("220")) {
    // Upgrade to SSLSocket
    SSLSocket sslSocket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(
        plain, host, 25, true);
    sslSocket.startHandshake();
    // Now inspect session as above
}
```

Similar STARTTLS logic applies to IMAP (send `a001 STARTTLS\r\n`) and FTP (send `AUTH TLS\r\n`).

### 4.6 New Model Fields

Add a new `TlsInfo` model class (Lombok `@Data @Builder`):

```java
@Data @Builder @JsonInclude(JsonInclude.Include.NON_NULL)
public class TlsInfo {
    private boolean tlsCapable;
    private String protocol;           // "TLSv1.3"
    private String cipherSuite;
    private List<String> supportedProtocols;
    private String certSubject;
    private String certIssuer;
    private String certExpiry;         // ISO-8601 string
    private boolean certExpired;
    private boolean certExpiringSoon;  // within 30 days
    private List<String> certSans;     // Subject Alternative Names
    private String certSignatureAlg;
    private Integer certKeyBits;
    private List<String> weaknesses;   // deprecated protocols, weak ciphers
    private String error;
}
```

Add `TlsInfo tlsInfo` to `ScanResult`. Wire it in: after a port is confirmed OPEN, if it is a
well-known TLS port (443, 465, 993, 995, 8443, 636, etc.) or if the first banner attempt fails,
attempt `TlsInspector.inspect()`.

**New CLI flag:** `--tls` — run TLS inspection on all open ports (not just known-TLS ports).

**Reference:** Java SSLSocket API — https://docs.oracle.com/en/java/docs/api/java.base/javax/net/ssl/SSLSocket.html
**Reference:** X509Certificate API — https://docs.oracle.com/en/java/docs/api/java.base/java/security/cert/X509Certificate.html
**Reference:** STARTTLS (RFC 3207 for SMTP) — https://www.rfc-editor.org/rfc/rfc3207

---

## 5. HTTP/HTTPS Service Probing & Framework Detection

### Overview

The current `HttpProbe` sends `GET / HTTP/1.0\r\n\r\n` and the `BannerGrabber` reads only the first
line (the status line). This misses the response headers where nearly all useful service fingerprinting
information lives. A dedicated `HttpInspector` class that reads all response headers and optionally
the response body would enable rich framework and server detection.

### 5.1 Reading Full HTTP Response Headers

```java
public class HttpInspector {

    public HttpInfo inspect(String host, int port, boolean useTls, int timeoutMs) {
        try (Socket socket = useTls
                ? createTlsSocket(host, port, timeoutMs)
                : createPlainSocket(host, port, timeoutMs)) {

            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // HTTP/1.1 with Host header to handle virtual hosting
            out.print("GET / HTTP/1.1\r\n");
            out.print("Host: " + host + "\r\n");
            out.print("User-Agent: Mozilla/5.0 (compatible; PortScanner/1.0)\r\n");
            out.print("Accept: */*\r\n");
            out.print("Connection: close\r\n");
            out.print("\r\n");
            out.flush();

            // Read status line
            String statusLine = in.readLine();

            // Read headers into map
            Map<String, String> headers = new LinkedHashMap<>();
            String line;
            while ((line = in.readLine()) != null && !line.isEmpty()) {
                int colon = line.indexOf(':');
                if (colon > 0) {
                    String key = line.substring(0, colon).trim().toLowerCase();
                    String val = line.substring(colon + 1).trim();
                    headers.put(key, val);
                }
            }

            return HttpInfo.builder()
                .statusLine(statusLine)
                .headers(headers)
                .serverHeader(headers.get("server"))
                .poweredBy(headers.get("x-powered-by"))
                .build();
        } catch (Exception e) {
            return HttpInfo.builder().error(e.getMessage()).build();
        }
    }
}
```

### 5.2 Server Software Detection from Headers

The `Server:` response header is the primary fingerprint. Common values and what they reveal:

| Server Header Value | Software |
|---------------------|----------|
| `Apache/2.4.57 (Ubuntu)` | Apache httpd + OS |
| `nginx/1.24.0` | nginx |
| `Microsoft-IIS/10.0` | IIS on Windows Server |
| `cloudflare` | Behind Cloudflare CDN |
| `AmazonS3` | AWS S3 static hosting |
| `openresty/1.21.4` | OpenResty (nginx + Lua) |
| `Jetty(10.0.x)` | Eclipse Jetty (Java) |
| `Kestrel` | ASP.NET Core |
| `gunicorn/20.1.0` | Python Gunicorn |
| `uvicorn` | Python ASGI (FastAPI etc.) |
| `lighttpd/1.4.71` | lighttpd |
| `WEBrick/1.7.0` | Ruby WEBrick |

**Regex-based extraction:**

```java
Pattern APACHE    = Pattern.compile("Apache/([\\d.]+)");
Pattern NGINX     = Pattern.compile("nginx/([\\d.]+)");
Pattern IIS       = Pattern.compile("Microsoft-IIS/([\\d.]+)");
Pattern JETTY     = Pattern.compile("Jetty\\(([^)]+)\\)");
Pattern OPENRESTY = Pattern.compile("openresty/([\\d.]+)");
```

### 5.3 Framework Detection from X-Powered-By and Other Headers

```java
// X-Powered-By header values
"PHP/8.2.0"           -> PHP version
"ASP.NET"             -> .NET Framework
"Express"             -> Node.js Express
"Next.js"             -> Next.js (React SSR)
"Servlet/5.0"         -> Java Servlet container

// Additional fingerprinting headers
"X-Generator"         -> CMS (e.g. "WordPress 6.4", "Drupal 10")
"X-Drupal-Cache"      -> Drupal specifically
"X-Pingback"          -> WordPress XML-RPC endpoint
"X-AspNet-Version"    -> ASP.NET version
"X-Runtime"           -> Ruby on Rails (value = response time in seconds)
"Via"                 -> Proxy / CDN info
"X-Varnish"           -> Varnish cache
"CF-Cache-Status"     -> Cloudflare
"X-Amz-Cf-Id"        -> Amazon CloudFront
```

**Implementation — header-to-framework map:**

```java
Map<String, String> HEADER_FINGERPRINTS = Map.of(
    "x-powered-by",     "(?i)(PHP/[\\d.]+|ASP\\.NET|Express|Next\\.js)",
    "x-generator",      "(?i)(WordPress|Drupal|Joomla|Ghost)",
    "x-drupal-cache",   "Drupal",
    "x-runtime",        "Ruby on Rails",
    "x-varnish",        "Varnish Cache",
    "cf-ray",           "Cloudflare CDN"
);

List<String> detectedFrameworks = new ArrayList<>();
for (var entry : HEADER_FINGERPRINTS.entrySet()) {
    String headerValue = headers.get(entry.getKey());
    if (headerValue != null) {
        Matcher m = Pattern.compile(entry.getValue()).matcher(headerValue);
        if (m.find()) detectedFrameworks.add(m.group(1) != null ? m.group(1) : entry.getValue());
    }
}
```

### 5.4 HTTP Response Body Fingerprinting (Optional)

Reading a limited portion of the response body (e.g., first 2KB) allows detecting:

- **WordPress:** `<meta name="generator" content="WordPress 6.x">` or `/wp-content/` in page source
- **Drupal:** `<meta name="Generator" content="Drupal">` or `sites/default/files`
- **Joomla:** `/media/jui/js/` or `<meta name="generator" content="Joomla">`
- **Jenkins:** `<title>Dashboard [Jenkins]</title>` or `<a href="/jenkins/">`
- **GitLab:** `<title>GitLab</title>` or `content="GitLab"`
- **Grafana:** `<title>Grafana</title>`
- **Kibana:** `kbn-name: kibana` in headers or body
- **Spring Boot Actuator:** `/actuator` path returns JSON with app info

```java
// Read up to 2048 bytes of body
char[] bodyBuf = new char[2048];
int bodyRead = in.read(bodyBuf);
String bodySnippet = bodyRead > 0 ? new String(bodyBuf, 0, bodyRead) : "";

Map<String, String> BODY_FINGERPRINTS = Map.of(
    "WordPress",  "(?i)(wp-content|wp-json|WordPress)",
    "Drupal",     "(?i)(Drupal|sites/default/files)",
    "Joomla",     "(?i)(Joomla|/media/jui/)",
    "Jenkins",    "(?i)(Jenkins|hudson)",
    "Grafana",    "(?i)Grafana",
    "Spring",     "(?i)(Spring Boot|Whitelabel Error Page)"
);
```

### 5.5 Security Header Audit

While reading headers for fingerprinting, simultaneously audit for missing security headers.
This adds immediate operational value for pentesters and sysadmins:

```java
List<String> missingSecurity = new ArrayList<>();
String[] SECURITY_HEADERS = {
    "strict-transport-security",  // HSTS
    "content-security-policy",    // CSP
    "x-frame-options",            // Clickjacking protection
    "x-content-type-options",     // MIME sniffing protection
    "referrer-policy",
    "permissions-policy"
};
for (String h : SECURITY_HEADERS) {
    if (!headers.containsKey(h)) missingSecurity.add(h.toUpperCase());
}
```

### 5.6 Redirect Following and Virtual Host Detection

A `301` or `302` response with a `Location` header may reveal:
- Whether HTTP redirects to HTTPS (indicating TLS is available)
- The canonical hostname (revealing virtual host or CDN)
- Subdirectory structure of the application

```java
if (statusLine != null && (statusLine.contains(" 301 ") || statusLine.contains(" 302 "))) {
    String location = headers.get("location");
    if (location != null && location.startsWith("https://")) {
        httpInfo.setRedirectsToHttps(true);
        httpInfo.setCanonicalUrl(location);
    }
}
```

### 5.7 New Model Fields

Add `HttpInfo` as a Lombok `@Data @Builder` model class:

```java
@Data @Builder @JsonInclude(JsonInclude.Include.NON_NULL)
public class HttpInfo {
    private String statusLine;
    private Map<String, String> headers;
    private String serverHeader;
    private String poweredBy;
    private String serverVersion;       // extracted from Server header
    private List<String> frameworks;    // detected frameworks
    private List<String> cdnProviders;  // Cloudflare, CloudFront, etc.
    private List<String> missingSecurityHeaders;
    private boolean redirectsToHttps;
    private String canonicalUrl;
    private String bodyFingerprint;     // e.g. "WordPress 6.4"
    private String error;
}
```

Add `HttpInfo httpInfo` to `ScanResult`. Wire: if port is in the well-known HTTP set (80, 8080, 8000,
8888, 3000, 5000) or if `TlsInfo.tlsCapable == true`, run `HttpInspector.inspect()`.

**New CLI flag:** `--http` — run HTTP header inspection on all open ports (attempt HTTP on any open port,
not just well-known ones). Many services run HTTP on non-standard ports.

**Reference:** OWASP Secure Headers Project — https://owasp.org/www-project-secure-headers/
**Reference:** MDN HTTP Headers — https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers

---

## 6. Integration Notes for This Project

### 6.1 Summary of New Fields Required in Existing Models

**`ScanResult` additions:**
```java
private String serviceVersion;      // parsed version string (e.g. "OpenSSH_9.3p1")
private TlsInfo tlsInfo;            // populated for TLS-capable ports
private HttpInfo httpInfo;          // populated for HTTP-capable ports
private String osGuess;             // populated only if --os-detect used with pcap4j
```

**`ScanReport` additions:**
```java
private String osGuess;             // consensus OS guess across all port results
private int tlsPortCount;           // number of ports with TLS
private int expiredCertCount;       // number of expired certificates found
```

### 6.2 Suggested New CLI Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--tls` | false | Run TLS inspection on open ports (cert details, protocol versions, weak ciphers) |
| `--http` | false | Run full HTTP header analysis (framework detection, security headers) |
| `--version-detect` / `-V` | false | Run protocol-specific probes for version extraction |
| `--os-detect` | false | Enable OS fingerprinting (requires pcap4j on classpath, needs privileges) |

These flags follow the nmap convention of layering capabilities (`-sV`, `-O`, `-A`) so that a basic
scan remains fast and non-intrusive, while advanced probing is opt-in.

### 6.3 New Classes to Create

| Class | Package | Purpose |
|-------|---------|---------|
| `TlsInspector` | `scanner/` | SSLSocket-based TLS handshake and cert inspection |
| `HttpInspector` | `scanner/` | Full HTTP response header and body analysis |
| `VersionExtractor` | `service/` | Regex-based version string extraction from banners |
| `TlsInfo` | `model/` | Lombok model for TLS findings |
| `HttpInfo` | `model/` | Lombok model for HTTP findings |
| `TlsProbe` | `scanner/probe/` | Probe that wraps SSLSocket instead of plain Socket |
| `MysqlProbe` | `scanner/probe/` | Binary protocol probe for MySQL/MariaDB |
| `RedisProbe` | `scanner/probe/` | RESP protocol probe for Redis |
| `MemcachedProbe` | `scanner/probe/` | Text protocol probe for Memcached |

### 6.4 Existing Code to Extend

- **`BannerGrabber`** — add raw byte read mode for binary protocols; add optional TLS upgrade path
- **`ProbeRegistry`** — register new probes (Redis port 6379, Memcached 11211, MySQL 3306, PostgreSQL 5432)
- **`Probe` interface** — add `default boolean readRawBytes()` and `default String parseVersion(byte[])`
- **`ScanCommand`** — add `--tls`, `--http`, `--version-detect`, `--os-detect` picocli options
- **`PortScanner`** — after collecting open-port results, conditionally run TlsInspector / HttpInspector
- **`TextExporter` / `HtmlExporter`** — render new TlsInfo and HttpInfo fields in output

### 6.5 Prioritization Recommendation

Ranked by implementation effort vs. value delivered:

1. **HIGH VALUE, LOW EFFORT** — Full HTTP header reading + framework detection (section 5.1–5.5)
   — Extends existing `HttpProbe`; no new dependencies; add ~150 lines
2. **HIGH VALUE, MEDIUM EFFORT** — TLS inspection with `SSLSocket` (section 4.1–4.4)
   — Pure Java, no new dependencies; add ~200 lines + `TlsInfo` model
3. **MEDIUM VALUE, LOW EFFORT** — Redis, Memcached, MySQL probes (section 2.1)
   — Add 3 new `Probe` implementations; minor `BannerGrabber` changes
4. **MEDIUM VALUE, MEDIUM EFFORT** — STARTTLS detection for SMTP/IMAP (section 4.5)
   — Requires protocol-aware upgrade logic in BannerGrabber
5. **MEDIUM VALUE, HIGH EFFORT** — Binary protocol version parsing (section 2.2–2.3)
   — Requires BannerGrabber refactor to raw byte mode
6. **LOW VALUE, HIGH EFFORT** — OS fingerprinting with pcap4j (section 1.2–1.3)
   — Adds native dependency (libpcap/Npcap); requires elevated privileges; limited accuracy

---

## References

All references below are to canonical authoritative sources. URLs should be verified as they may change.

- Nmap OS Detection: https://nmap.org/book/osdetect.html
- Nmap Port Scanning Techniques: https://nmap.org/book/man-port-scanning-techniques.html
- Nmap Service Version Detection: https://nmap.org/book/vscan.html
- Nmap Service Probe File Format: https://nmap.org/book/vscan-fileformat.html
- Pcap4J Java Library: https://www.pcap4j.org/
- Java SSLSocket API (Java 17): https://docs.oracle.com/en/java/docs/api/java.base/javax/net/ssl/SSLSocket.html
- Java X509Certificate API: https://docs.oracle.com/en/java/docs/api/java.base/java/security/cert/X509Certificate.html
- RFC 793 (TCP): https://www.rfc-editor.org/rfc/rfc793
- RFC 3207 (SMTP STARTTLS): https://www.rfc-editor.org/rfc/rfc3207
- RFC 4346 (TLS 1.1): https://www.rfc-editor.org/rfc/rfc4346
- RFC 8446 (TLS 1.3): https://www.rfc-editor.org/rfc/rfc8446
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- MDN Web Docs — HTTP Headers: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
- MySQL Client/Server Protocol: https://dev.mysql.com/doc/internals/en/client-server-protocol.html
- MongoDB Wire Protocol: https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/
- Redis RESP Protocol: https://redis.io/docs/reference/protocol-spec/
