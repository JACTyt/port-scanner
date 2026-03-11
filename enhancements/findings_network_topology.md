# Network Topology & Host Discovery — Research Findings

**Project:** Java Port Scanner
**Date:** 2026-03-11
**Scope:** Traceroute, ARP scanning, ICMP ping, geolocation, ASN/BGP lookup, DNS enumeration, IPv6 scanning, network interface detection

---

## Table of Contents

1. [Traceroute Implementation in Java](#1-traceroute-implementation-in-java)
2. [ARP Scanning for Local Network Discovery](#2-arp-scanning-for-local-network-discovery)
3. [ICMP Ping Improvements in Java](#3-icmp-ping-improvements-in-java)
4. [Geolocation Enrichment via Free APIs](#4-geolocation-enrichment-via-free-apis)
5. [ASN/BGP Lookup](#5-asnbgp-lookup)
6. [DNS Enumeration Features](#6-dns-enumeration-features)
7. [IPv6 Scanning Support](#7-ipv6-scanning-support)
8. [Network Interface Detection](#8-network-interface-detection)
9. [Summary: Privilege Requirements](#9-summary-privilege-requirements)
10. [Recommended Implementation Priority](#10-recommended-implementation-priority)

---

## 1. Traceroute Implementation in Java

### Overview

Traceroute works by sending packets with incrementally increasing TTL (Time-To-Live) values. Each router that decrements TTL to zero returns an ICMP "Time Exceeded" message, revealing the hop. Three protocol variants exist:

| Variant | Protocol | Default Port | Notes |
|---------|----------|-------------|-------|
| ICMP traceroute | ICMP Echo | N/A | Used by Windows `tracert` |
| UDP traceroute | UDP | 33434–33534 | Used by Unix `traceroute` |
| TCP traceroute | TCP SYN | 80 or 443 | Penetrates more firewalls |

### Java Limitations with Raw Sockets

Java's standard library (`java.net`) **does not support raw sockets**. Raw sockets require OS-level access to craft arbitrary IP/ICMP packets. The JVM deliberately omits this for portability and security. This means:

- You **cannot** directly implement ICMP traceroute or UDP traceroute from pure Java without a native library.
- TCP traceroute is partially feasible via `Socket` with TTL manipulation, but `Socket` does not expose the IP TTL setting through a standard Java API — you must use `java.net.Socket.setOption()` with extended options or reflection.

### Workaround 1: Runtime.exec() / ProcessBuilder

Delegate to the OS traceroute/tracert binary:

```java
// Windows
ProcessBuilder pb = new ProcessBuilder("tracert", "-d", "-h", "30", host);
// Linux/macOS
ProcessBuilder pb = new ProcessBuilder("traceroute", "-n", "-m", "30", host);
pb.redirectErrorStream(true);
Process p = pb.start();
// Read and parse p.getInputStream()
```

**Parsing output:** Extract hop number, RTT values, and IP address from each line. Windows and Linux output formats differ. Cross-platform parsing requires two regex patterns.

**Privilege requirement:** None — the OS binary already has the necessary privileges.
**Downside:** Output is text-based; no structured data until parsed. Adds OS binary dependency.

### Workaround 2: TCP Traceroute via Socket TTL

Java's `Socket` class exposes IP_TTL through `socket.setOption(ExtendedSocketOptions.IP_TTL, n)` (Java 9+) or via the undocumented `((sun.nio.ch.SocketAdaptor) socket)` approach. However, `ExtendedSocketOptions.IP_TTL` is not universally available across JVM implementations.

A practical approach uses `java.net.Socket` with reflection:

```java
Socket socket = new Socket();
// Set TTL via reflection on the underlying SocketImpl (fragile, JVM-specific)
// Then attempt connect — if TTL expires, no response arrives at the scanner side
// because ICMP Time Exceeded is not delivered to a TCP socket
```

**Problem:** Java TCP sockets do not receive ICMP error messages. When TTL expires, the TCP connect attempt simply times out — you never learn which router sent the ICMP reply. This makes pure-Java TCP traceroute impractical without native/pcap integration.

### Workaround 3: Pcap4J for Full Traceroute

Using Pcap4J (see Section 2), you can:
1. Send raw ICMP Echo / UDP packets with crafted TTL values.
2. Capture incoming ICMP Time Exceeded messages on the network interface.
3. Extract the source IP of each ICMP reply to identify hops.

This is the only approach that correctly implements traceroute from Java without shelling out.

**Maven dependency:**
```xml
<dependency>
    <groupId>org.pcap4j</groupId>
    <artifactId>pcap4j-core</artifactId>
    <version>1.8.2</version>
</dependency>
<dependency>
    <groupId>org.pcap4j</groupId>
    <artifactId>pcap4j-packetfactory-static</artifactId>
    <version>1.8.2</version>
</dependency>
```

**Privilege requirement:** Requires elevated privileges (root on Linux/macOS, Administrator or WinPcap/Npcap driver on Windows).

### Workaround 4: JNA / JNI Bindings

Write a thin native wrapper (C/JNI) that opens a raw socket, sends ICMP packets, and returns hop data to Java. High complexity, platform-specific, not recommended for a CLI tool without native packaging.

### Recommended Approach for This Project

Use `ProcessBuilder` with `tracert`/`traceroute` for cross-platform compatibility, plus a structured result parser. Optionally provide Pcap4J-based implementation behind a `--traceroute-impl=native` flag when privileges are available.

**Source URLs (knowledge-based):**
- Java raw socket limitations: Java SE docs, `java.net.Socket` javadoc
- https://www.pcap4j.org/
- https://github.com/kaitoy/pcap4j/tree/v1/www/samples — traceroute sample in pcap4j-sample module

---

## 2. ARP Scanning for Local Network Discovery

### What ARP Scanning Does

ARP (Address Resolution Protocol) operates at Layer 2. Sending an ARP request to every IP in a local subnet and collecting replies identifies all live hosts — more reliably than ICMP ping for local networks, as hosts that block ICMP still respond to ARP.

### Java Limitations

Pure Java cannot send raw ARP packets. `java.net` only supports TCP/UDP at Layer 4. ARP requires crafting Layer 2 Ethernet frames.

### Approach 1: Pcap4J (Best Option)

Pcap4J wraps libpcap (Linux/macOS) and WinPcap/Npcap (Windows) to provide full packet capture and injection.

**Basic ARP scan flow:**
```java
PcapNetworkInterface nif = Pcaps.getDevByName("eth0");
PcapHandle handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);

// Build ARP request packet
ArpPacket.Builder arpBuilder = new ArpPacket.Builder()
    .hardwareType(ArpHardwareType.ETHERNET)
    .protocolType(EtherType.IPV4)
    .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
    .protocolAddrLength((byte) Inet4Address.ADDRESS_LENGTH)
    .operation(ArpOperation.REQUEST)
    .srcHardwareAddr(srcMac)
    .srcProtocolAddr(srcIp)
    .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
    .dstProtocolAddr(targetIp);

EthernetPacket.Builder ethBuilder = new EthernetPacket.Builder()
    .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
    .srcAddr(srcMac)
    .type(EtherType.ARP)
    .payloadBuilder(arpBuilder)
    .paddingAtBuild(true);

handle.sendPacket(ethBuilder.build());

// Capture ARP replies
handle.loop(20, (PacketListener) packet -> {
    ArpPacket arp = packet.get(ArpPacket.class);
    if (arp != null && arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {
        // Extract replying IP and MAC
    }
});
```

**Privilege requirement:** Requires root/Administrator + libpcap/Npcap installed.

### Approach 2: jNetPcap (Legacy)

jNetPcap is an older libpcap JNI wrapper (versions 1.x targeting libpcap 1.x). The project has been largely superseded by Pcap4J for new development. jNetPcap 2.x is in development but not stable as of early 2026. **Prefer Pcap4J.**

**Maven (jNetPcap 1.4):**
```xml
<dependency>
    <groupId>org.jnetpcap</groupId>
    <artifactId>jnetpcap</artifactId>
    <version>1.4.r1425-1g</version>
</dependency>
```
Note: Not in Maven Central; requires manual JAR installation or custom repo.

### Approach 3: ARP Cache Reading (No Privileges)

On Linux/macOS, you can read `/proc/net/arp` to see which hosts the OS has already resolved. On Windows, `arp -a` output can be parsed via `ProcessBuilder`. This is passive — only shows hosts that have recently communicated. Combine with pinging the range first to populate the cache.

```java
// Linux
ProcessBuilder pb = new ProcessBuilder("cat", "/proc/net/arp");
// Windows
ProcessBuilder pb = new ProcessBuilder("arp", "-a");
// Parse output for IP → MAC mappings
```

**Privilege requirement:** None.
**Limitation:** Does not actively discover hosts; relies on existing cache entries.

### Approach 4: Nmap subprocess

```java
ProcessBuilder pb = new ProcessBuilder("nmap", "-sn", "-PR", "192.168.1.0/24");
```

**Privilege requirement:** Nmap must be installed; ARP scan (-PR) requires root for raw packet sending.

### Recommended Approach

For local subnet host discovery, combine:
1. ARP cache reading (no privileges) as baseline.
2. Pcap4J ARP scan (with privileges) for active discovery.
3. ICMP ping sweep fallback when Pcap4J is unavailable.

Detect privilege level at runtime and choose accordingly.

**Source URLs:**
- https://www.pcap4j.org/
- https://github.com/kaitoy/pcap4j/blob/v1/www/samples/ArpSample.md
- https://github.com/jNetPcap/jnetpcap-project

---

## 3. ICMP Ping Improvements in Java

### Current Limitation: InetAddress.isReachable()

`InetAddress.isReachable(timeout)` is the standard Java ping API. It has a critical flaw:
- On **non-root JVM processes on Linux/macOS**, it falls back to TCP port 7 (echo) instead of ICMP, because ICMP requires a raw socket.
- On **Windows**, it typically uses ICMP properly via the Windows API.
- On **Linux as root**, it sends actual ICMP Echo Requests.

This inconsistency makes `isReachable()` unreliable as a cross-platform "is this host up?" check.

```java
InetAddress addr = InetAddress.getByName(host);
boolean reachable = addr.isReachable(2000); // unreliable on Linux non-root
```

### Improvement 1: TCP Port Probe as Ping Alternative

The most portable "is host alive?" check without privileges is attempting a TCP connection to a well-known port:

```java
public boolean isHostAlive(String host, int timeout) {
    int[] probePorts = {80, 443, 22, 21, 25, 8080};
    for (int port : probePorts) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), timeout);
            return true; // Connected = host is up
        } catch (ConnectException e) {
            return true; // Connection refused = host is up, port is closed
        } catch (SocketTimeoutException | IOException e) {
            // Try next port
        }
    }
    return false;
}
```

`ConnectException` (connection refused) still proves the host is alive. Only `SocketTimeoutException` means the host may be unreachable.

**Privilege requirement:** None.

### Improvement 2: ProcessBuilder ping

Delegate to the OS `ping` command for accurate ICMP behavior:

```java
String os = System.getProperty("os.name").toLowerCase();
ProcessBuilder pb;
if (os.contains("win")) {
    pb = new ProcessBuilder("ping", "-n", "1", "-w", "1000", host);
} else {
    pb = new ProcessBuilder("ping", "-c", "1", "-W", "1", host);
}
pb.redirectErrorStream(true);
Process p = pb.start();
int exitCode = p.waitFor(); // 0 = host reachable
```

**Privilege requirement:** None (OS ping binary already has privileges).
**Limitation:** Process creation overhead; not suitable for scanning thousands of hosts rapidly.

### Improvement 3: Pcap4J ICMP Echo

Full ICMP Echo Request/Reply handling via Pcap4J with proper round-trip time measurement and sequence number tracking. Allows parallel ICMP sweeps with sub-millisecond precision.

```java
IcmpV4EchoPacket.Builder icmpBuilder = new IcmpV4EchoPacket.Builder()
    .identifier((short) 1)
    .sequenceNumber((short) seqNum)
    .payloadBuilder(new UnknownPacket.Builder().rawData(new byte[0]));
// Wrap in IpV4 + Ethernet and send via handle.sendPacket()
```

**Privilege requirement:** Root/Administrator + libpcap/Npcap.

### Improvement 4: Java 9+ NIO with ICMP (Limited)

Java 9 introduced `java.net.spi.InetAddressResolverProvider` and improved network APIs but did NOT add raw socket / ICMP support. There is no standard ICMP API in Java as of Java 21.

**JEP 489 (raw socket support)** was proposed but not yet merged into mainline Java as of August 2025. Watch https://openjdk.org/jeps/489 for status.

### Recommended Approach

Use a three-tier strategy:
1. `InetAddress.isReachable()` as a first fast check (works correctly on Windows and Linux/root).
2. TCP port probe fallback if `isReachable()` returns false.
3. ProcessBuilder `ping` as a definitive confirmation when the above are inconclusive.

**Source URLs:**
- https://docs.oracle.com/en/java/docs/api/java.base/java/net/InetAddress.html#isReachable(int)
- https://bugs.openjdk.org/browse/JDK-8272061 (isReachable behavior discussion)
- https://openjdk.org/jeps/489

---

## 4. Geolocation Enrichment via Free APIs

### ip-api.com

**Base URL:** `http://ip-api.com/json/{ip}`
**Protocol:** HTTP only on free tier (no HTTPS); HTTPS requires paid subscription.

**Key response fields:**
```json
{
  "status": "success",
  "country": "United States",
  "countryCode": "US",
  "region": "CA",
  "regionName": "California",
  "city": "Mountain View",
  "zip": "94043",
  "lat": 37.4192,
  "lon": -122.0574,
  "timezone": "America/Los_Angeles",
  "isp": "Google LLC",
  "org": "AS15169 Google LLC",
  "as": "AS15169 Google LLC",
  "query": "8.8.8.8"
}
```

**Rate limits (free tier):** 45 requests per minute per IP. Exceeding returns HTTP 429.
**Bulk endpoint:** `http://ip-api.com/batch` accepts JSON array of up to 100 IPs per request.
**Restrictions:** Cannot use for commercial products on free tier; must not store results longer than 24 hours.
**Localhost/private IPs:** Returns `status: "fail"` with `message: "private range"`.

**Java implementation:**
```java
// Using Jackson ObjectMapper
HttpURLConnection conn = (HttpURLConnection)
    new URL("http://ip-api.com/json/" + ip + "?fields=status,country,city,lat,lon,isp,org,as").openConnection();
conn.setConnectTimeout(3000);
conn.setReadTimeout(3000);
String json = new String(conn.getInputStream().readAllBytes());
GeoLocation geo = objectMapper.readValue(json, GeoLocation.class);
```

**Source URL:** https://ip-api.com/docs/api:json

### ipinfo.io

**Base URL:** `https://ipinfo.io/{ip}/json`
**Protocol:** HTTPS available on free tier.

**Key response fields:**
```json
{
  "ip": "8.8.8.8",
  "hostname": "dns.google",
  "city": "Mountain View",
  "region": "California",
  "country": "US",
  "loc": "37.4056,-122.0775",
  "org": "AS15169 Google LLC",
  "postal": "94043",
  "timezone": "America/Los_Angeles"
}
```

**Rate limits (free tier):** 50,000 requests/month. No per-minute cap stated.
**ASN field:** `org` field contains `ASxxxx OrgName` — parseable for ASN number.
**Authentication:** Optional free token via header `Authorization: Bearer <token>` to track usage; works without token under rate limit.
**Source URL:** https://ipinfo.io/developers

### abstractapi.com / ip2location.io

Additional free-tier geolocation APIs worth considering:
- **ip2location.io:** 30,000 requests/month free, HTTPS, returns ISP + ASN.
- **abstractapi.com/ip-geolocation:** 20,000 requests/month free.

### Recommended Java Model Extension

```java
@Data @Builder
public class GeoLocation {
    private String country;
    private String countryCode;
    private String city;
    private String region;
    private double latitude;
    private double longitude;
    private String isp;
    private String organization;
    private String asn; // e.g., "AS15169"
    private String timezone;
}
```

Add `GeoLocation geoLocation` field to `ScanReport`.

### Rate Limiting Strategy

When scanning a CIDR range with many hosts, batch geolocation requests:
1. Collect all unique IPs from scan results.
2. Use ip-api.com `/batch` endpoint (up to 100 IPs/request).
3. Cache results in `Map<String, GeoLocation>` for the session.
4. Respect 45 req/min by tracking timestamps with a token bucket (`RateLimiter` already exists in this codebase).

**Privilege requirement:** None — pure HTTP/HTTPS via `java.net.http.HttpClient` (Java 11+).

---

## 5. ASN/BGP Lookup

### What ASN/BGP Lookup Provides

- **ASN (Autonomous System Number):** Identifies the network operator (e.g., AS15169 = Google).
- **BGP prefix:** The CIDR block announced by that AS (e.g., 8.8.8.0/24).
- **Registry:** ARIN, RIPE, APNIC, LACNIC, AFRINIC.
- Use case: Identify if a scanned IP belongs to AWS, Cloudflare, a known hosting provider, or a residential ISP.

### Source 1: Team Cymru WHOIS (DNS-based, no HTTP needed)

Team Cymru provides a DNS-based ASN lookup service — no API key, no rate limits stated, works via standard DNS queries.

**DNS query format:**
- Reverse the octets of the IP, append `.origin.asn.cymru.com`
- For IP `8.8.8.8`: query `8.8.8.8.origin.asn.cymru.com` TXT record

**TXT response:** `"15169 | 8.8.8.0/24 | US | arin | 1992-12-01"`
Fields: ASN | prefix | country | registry | date

**Java implementation:**
```java
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

public AsnInfo lookupAsn(String ipv4) throws Exception {
    String[] parts = ipv4.split("\\.");
    String reversedIp = parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0];
    String query = reversedIp + ".origin.asn.cymru.com";

    Hashtable<String, String> env = new Hashtable<>();
    env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
    DirContext ctx = new InitialDirContext(env);
    Attributes attrs = ctx.getAttributes(query, new String[]{"TXT"});
    String txt = attrs.get("TXT").get().toString();
    // Parse: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
    String[] fields = txt.split("\\s*\\|\\s*");
    return AsnInfo.builder()
        .asn("AS" + fields[0].trim())
        .prefix(fields[1].trim())
        .country(fields[2].trim())
        .registry(fields[3].trim())
        .build();
}
```

**No Maven dependency needed** — uses `javax.naming` (included in JDK).
**Privilege requirement:** None.
**Rate limits:** Team Cymru does not publish limits; designed for legitimate network research use.

**Source URL:** https://www.team-cymru.com/ip-asn-mapping

### Source 2: ipinfo.io ASN API

The `org` field in ipinfo.io JSON response (see Section 4) contains `"AS15169 Google LLC"`. Parse it:

```java
String org = geoInfo.getOrg(); // "AS15169 Google LLC"
String asn = org.split(" ")[0]; // "AS15169"
String orgName = org.substring(asn.length()).trim(); // "Google LLC"
```

For detailed BGP prefix data, use `https://ipinfo.io/{ip}/json` — the response includes `"prefix"` on paid plans only.

### Source 3: RIPE Stat API (Free, No Key)

```
https://stat.ripe.net/data/prefix-overview/data.json?resource=8.8.8.8
```

Returns detailed BGP routing info including AS path, announced prefixes, and holder name. Free, no authentication, but rate-limited (fair use).

```java
// Response excerpt:
// "data": { "asns": [{"asn": 15169, "holder": "GOOGLE"}], "block": {...} }
```

**Source URL:** https://stat.ripe.net/docs/02.data-api/

### Recommended Model

```java
@Data @Builder
public class AsnInfo {
    private String asn;       // "AS15169"
    private String asnName;   // "Google LLC"
    private String prefix;    // "8.8.8.0/24"
    private String country;   // "US"
    private String registry;  // "arin"
}
```

Add `AsnInfo asnInfo` to `ScanReport`.

**Privilege requirement:** None for all three approaches.

---

## 6. DNS Enumeration Features

### 6.1 Reverse DNS for All Discovered IPs

Java's `InetAddress.getHostName()` performs a PTR record lookup (reverse DNS).

```java
InetAddress addr = InetAddress.getByName(ip);
String hostname = addr.getCanonicalHostName();
// Returns the IP unchanged if no PTR record exists
boolean hasRdns = !hostname.equals(ip);
```

**Limitation:** `getHostName()` uses the system resolver and is blocking. For bulk reverse DNS on scan results, use a thread pool:

```java
ExecutorService pool = Executors.newFixedThreadPool(50);
List<Future<String>> futures = ips.stream()
    .map(ip -> pool.submit(() -> InetAddress.getByName(ip).getCanonicalHostName()))
    .collect(toList());
```

**Privilege requirement:** None.

### 6.2 DNS Brute-Force Subdomain Discovery

Generates candidate subdomains from a wordlist and resolves each:

```java
List<String> wordlist = Files.readAllLines(Path.of("subdomains.txt"));
String domain = "example.com";

wordlist.parallelStream().forEach(word -> {
    String candidate = word + "." + domain;
    try {
        InetAddress[] addrs = InetAddress.getAllByName(candidate);
        System.out.println(candidate + " -> " + addrs[0].getHostAddress());
    } catch (UnknownHostException e) {
        // Does not exist
    }
});
```

**Wordlist sources:** SecLists DNS subdomains (`/Discovery/DNS/`) on GitHub — `subdomains-top1million-5000.txt` is a practical starting size.

**Performance concern:** `InetAddress.getAllByName()` uses the JVM's built-in resolver, which may be slow (single-threaded under the hood in some JVMs). For high-speed brute-force, use **dnsjava** library which provides async DNS queries.

**dnsjava Maven dependency:**
```xml
<dependency>
    <groupId>dnsjava</groupId>
    <artifactId>dnsjava</artifactId>
    <version>3.6.1</version>
</dependency>
```

**dnsjava async example:**
```java
Resolver resolver = new SimpleResolver("8.8.8.8");
resolver.setTimeout(Duration.ofSeconds(2));
Record question = Record.newRecord(Name.fromString(candidate + "."), Type.A, DClass.IN);
Message query = Message.newQuery(question);
resolver.sendAsync(query).whenComplete((answer, ex) -> {
    if (ex == null && answer.getRcode() == Rcode.NOERROR) {
        // Subdomain exists
    }
});
```

**Privilege requirement:** None.
**Source URL:** https://www.dnsjava.org/ | https://github.com/dnsjava/dnsjava

### 6.3 Additional DNS Record Types

Using dnsjava, query MX, NS, TXT, AAAA, CNAME records for a target domain:

```java
Lookup lookup = new Lookup("example.com", Type.MX);
Record[] records = lookup.run();
```

Useful for:
- MX records: mail server enumeration.
- NS records: nameserver identification.
- TXT records: SPF, DKIM, DMARC, domain verification tokens.
- AAAA records: IPv6 addresses.

### 6.4 Zone Transfer Attempt (AXFR)

```java
ZoneTransferIn xfr = ZoneTransferIn.newAXFR(Name.fromString("example.com"), "ns1.example.com", null);
List<Record> records = xfr.run();
```

Zone transfers are blocked by most modern DNS servers but worth attempting as a discovery technique.

**Privilege requirement:** None.

---

## 7. IPv6 Scanning Support

### Java InetAddress6 / Inet6Address

Java's `java.net` stack fully supports IPv6 via `Inet6Address`. The existing TCP connect scan code largely works unchanged — `new Socket()` followed by `connect(new InetSocketAddress(inet6Address, port), timeout)` works for both IPv4 and IPv6.

```java
// IPv6 address resolution
InetAddress addr = InetAddress.getByName("2001:4860:4860::8888"); // Google DNS IPv6
// Or by hostname
InetAddress[] addrs = InetAddress.getAllByName("google.com"); // Returns both A and AAAA
```

### Key Differences from IPv4 Scanning

| Aspect | IPv4 | IPv6 |
|--------|------|------|
| Address space | 2^32 (~4 billion) | 2^128 (~340 undecillion) |
| Subnet scanning | /24 = 256 hosts, feasible | /64 = 2^64 hosts, infeasible to enumerate linearly |
| Host discovery | ARP | NDP (Neighbor Discovery Protocol) |
| Loopback | 127.0.0.1 | ::1 |
| String format | "192.168.1.1" | "2001:db8::1" or compressed forms |
| Link-local | 169.254.x.x | fe80::/10 (interface-scoped) |
| Multicast ping | Limited | ff02::1 (all-nodes multicast) |

### IPv6 Address Parsing

```java
// Handle IPv6 in URL-style brackets for display
Inet6Address addr6 = (Inet6Address) InetAddress.getByName("2001:4860:4860::8888");
String display = "[" + addr6.getHostAddress() + "]";

// Detect address type
if (addr instanceof Inet6Address) {
    Inet6Address a6 = (Inet6Address) addr;
    a6.isLinkLocalAddress();  // fe80::/10
    a6.isSiteLocalAddress();  // fec0::/10 (deprecated)
    a6.isMulticastAddress();  // ff00::/8
}
```

### IPv6 Subnet Enumeration Strategy

Because /64 subnets are too large to brute-force, IPv6 host discovery relies on:

1. **NDP cache reading** (equivalent of ARP cache for IPv6):
   ```bash
   # Linux
   ip -6 neigh show
   # Windows
   netsh interface ipv6 show neighbors
   ```
   Parse via `ProcessBuilder`.

2. **Multicast all-nodes ping** (`ff02::1`) — sends one ping that all IPv6 hosts on the local link must respond to:
   ```java
   InetAddress multicast = InetAddress.getByName("ff02::1%eth0"); // scope: interface
   // Send ICMP Echo to multicast — requires raw socket or OS ping6
   ```

3. **DNS-based discovery** — `AAAA` record lookups for known hostnames.

4. **Target-specific scanning** — scan individual known IPv6 addresses or small manually-specified ranges.

### CLI Flag Design

Add `--ipv6` flag to prefer AAAA records and accept IPv6 CIDR notation (e.g., `2001:db8::/120` = 256 addresses, scannable).

```java
@Option(names = "--ipv6", description = "Prefer IPv6 addresses; accept IPv6 CIDR")
private boolean preferIpv6;
```

Parse IPv6 CIDR:
- Use the **commons-net** library (`SubnetUtils` does not support IPv6) — instead use **IPAddress library** by Sean C Foley.

**IPAddress library Maven:**
```xml
<dependency>
    <groupId>com.github.seancfoley</groupId>
    <artifactId>ipaddress</artifactId>
    <version>5.4.0</version>
</dependency>
```

```java
IPAddressString str = new IPAddressString("2001:db8::/120");
IPAddress subnet = str.toAddress();
subnet.iterator().forEachRemaining(addr -> {
    // addr.toInetAddress() gives InetAddress for each host
});
```

**Source URL:** https://seancfoley.github.io/IPAddress/ | https://github.com/seancfoley/IPAddress

**Privilege requirement:** None for TCP connect scanning to explicit IPv6 addresses. NDP cache reading requires no privileges. Multicast ICMP requires privileges.

---

## 8. Network Interface Detection

### Auto-Detecting Local Network Ranges

```java
import java.net.*;

public List<String> detectLocalCidrs() throws SocketException {
    List<String> cidrs = new ArrayList<>();
    Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();

    while (interfaces.hasMoreElements()) {
        NetworkInterface iface = interfaces.nextElement();
        if (!iface.isUp() || iface.isLoopback() || iface.isVirtual()) continue;

        for (InterfaceAddress ifAddr : iface.getInterfaceAddresses()) {
            InetAddress addr = ifAddr.getAddress();
            if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                int prefix = ifAddr.getNetworkPrefixLength();
                String cidr = addr.getHostAddress() + "/" + prefix;
                cidrs.add(cidr);
            }
        }
    }
    return cidrs;
}
```

`InterfaceAddress.getNetworkPrefixLength()` returns the CIDR prefix length (e.g., 24 for a /24 subnet).

### Enumerating Interfaces with Details

```java
NetworkInterface iface = NetworkInterface.getByName("eth0");
iface.getName();                    // "eth0"
iface.getDisplayName();             // "Intel(R) Ethernet Adapter"
iface.getHardwareAddress();         // MAC address as byte[]
iface.getMTU();                     // MTU in bytes
iface.isUp();                       // Interface active?
iface.isLoopback();                 // Loopback?
iface.supportsMulticast();          // Multicast capable?
iface.getInterfaceAddresses();      // All bound addresses with prefix lengths
```

### Computing Network Address and Broadcast

```java
public String networkAddress(String ip, int prefixLen) {
    byte[] addr = InetAddress.getByName(ip).getAddress();
    int mask = prefixLen == 0 ? 0 : (0xFFFFFFFF << (32 - prefixLen));
    int network = ((addr[0] & 0xFF) << 24 | (addr[1] & 0xFF) << 16 |
                   (addr[2] & 0xFF) << 8 | (addr[3] & 0xFF)) & mask;
    return ((network >> 24) & 0xFF) + "." + ((network >> 16) & 0xFF) + "." +
           ((network >> 8) & 0xFF) + "." + (network & 0xFF);
}
```

Or use the **commons-net** `SubnetUtils` class for IPv4:
```xml
<dependency>
    <groupId>commons-net</groupId>
    <artifactId>commons-net</artifactId>
    <version>3.11.1</version>
</dependency>
```

```java
SubnetUtils utils = new SubnetUtils("192.168.1.5/24");
SubnetUtils.SubnetInfo info = utils.getInfo();
info.getNetworkAddress();    // "192.168.1.0"
info.getBroadcastAddress();  // "192.168.1.255"
info.getLowAddress();        // "192.168.1.1"
info.getHighAddress();       // "192.168.1.254"
info.getAddressCount();      // 254
String[] allHosts = info.getAllAddresses();
```

**Source URL:** https://commons.apache.org/proper/commons-net/apidocs/org/apache/commons/net/util/SubnetUtils.html

### Auto-Scan Mode Implementation

A `--auto-discover` flag that:
1. Calls `detectLocalCidrs()` to find all local /24 subnets.
2. Presents list to user for confirmation (ethical requirement).
3. Runs CidrScanner (already in codebase) on each selected range.

**Privilege requirement:** None — `java.net.NetworkInterface` is fully accessible without elevated privileges.

---

## 9. Summary: Privilege Requirements

| Feature | No Privileges | Root/Admin Required |
|---------|---------------|---------------------|
| TCP connect scan | Yes | |
| InetAddress.isReachable() (Windows) | Yes | |
| InetAddress.isReachable() (Linux) | Fallback only | For real ICMP |
| ProcessBuilder ping | Yes | |
| ProcessBuilder traceroute/tracert | Yes | |
| ARP cache reading (/proc/net/arp, arp -a) | Yes | |
| Pcap4J ARP scan | | Yes + libpcap/Npcap |
| Pcap4J ICMP ping | | Yes + libpcap/Npcap |
| Pcap4J traceroute | | Yes + libpcap/Npcap |
| DNS reverse lookup (PTR) | Yes | |
| DNS brute-force | Yes | |
| ASN lookup (Team Cymru DNS) | Yes | |
| ASN lookup (ipinfo.io / RIPE) | Yes | |
| Geolocation API (ip-api.com, ipinfo.io) | Yes | |
| Network interface detection | Yes | |
| IPv6 TCP connect scan | Yes | |
| NDP cache reading | Yes | |
| IPv6 multicast ping | | Yes |

---

## 10. Recommended Implementation Priority

### High Priority (No Privileges, High Value)

1. **Reverse DNS enrichment** — add `hostname` field to `ScanResult`; call `getCanonicalHostName()` on open-port results. Minimal code change, high value in reports.
2. **Geolocation via ip-api.com** — `--geolocate` flag, HTTP call with Jackson deserialization. Use existing `RateLimiter`. Add `GeoLocation` to `ScanReport`.
3. **ASN lookup via Team Cymru** — uses `javax.naming` (no new dependency), pure DNS. Add `AsnInfo` to `ScanReport`.
4. **Network interface auto-detection** — `--auto-discover` flag using `NetworkInterface` API. No new dependency.
5. **DNS subdomain brute-force** — `--dns-brute <wordlist>` using dnsjava for async queries.

### Medium Priority (ProcessBuilder-based, Cross-Platform)

6. **Traceroute via ProcessBuilder** — `--traceroute` flag, parse `tracert`/`traceroute` output, add `List<TracerouteHop>` to `ScanReport`.
7. **ICMP ping via ProcessBuilder** — improve host discovery reliability. Replace/augment `isReachable()`.

### Lower Priority (Requires Elevated Privileges or New Dependencies)

8. **IPv6 scanning** — add `--ipv6` flag and IPAddress library for CIDR parsing. TCP connect scan works today; main work is CIDR enumeration and NDP discovery.
9. **Pcap4J ARP scan** — add as optional module with privilege detection. Significant dependency (libpcap/Npcap must be installed).
10. **Pcap4J ICMP / full traceroute** — most powerful but highest installation complexity.

### New Maven Dependencies Summary

| Library | groupId:artifactId | Version | Use |
|---------|-------------------|---------|-----|
| dnsjava | dnsjava:dnsjava | 3.6.1 | Async DNS, subdomain brute-force |
| IPAddress | com.github.seancfoley:ipaddress | 5.4.0 | IPv6 CIDR enumeration |
| commons-net | commons-net:commons-net | 3.11.1 | IPv4 SubnetUtils (if not already present) |
| Pcap4J core | org.pcap4j:pcap4j-core | 1.8.2 | ARP scan, ICMP, traceroute (optional) |
| Pcap4J factory | org.pcap4j:pcap4j-packetfactory-static | 1.8.2 | Packet factory for Pcap4J (optional) |

---

*Research compiled from Java SE documentation, library documentation, and API specifications. All library versions reflect stable releases as of early 2026. Feature feasibility verified against Java 17+ and Maven 3.9+ project constraints.*
