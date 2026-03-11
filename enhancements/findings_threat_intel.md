# Threat Intelligence & Security API Research Findings

**Purpose:** Evaluate external APIs and offline datasets for enriching port scanner results with threat intelligence, IP reputation, geolocation, CVE data, and exploit information.

**Knowledge basis:** Training data up to August 2025. Fields marked `[VERIFY]` are volatile (pricing tiers, exact rate limits) and should be confirmed against the source URL before implementation.

---

## Table of Contents

1. [Shodan API](#1-shodan-api)
2. [GreyNoise API](#2-greynoise-api)
3. [Censys API](#3-censys-api)
4. [AbuseIPDB API](#4-abuseipdb-api)
5. [ExploitDB / MITRE ATT&CK](#5-exploitdb--mitre-attck)
6. [Offline NVD CVE Feeds (Local SQLite)](#6-offline-nvd-cve-feeds-local-sqlite)
7. [IPinfo.io / ip-api.com (Geolocation & ASN)](#7-ipinfoio--ip-apicom-geolocation--asn)
8. [Have I Been Pwned (HIBP)](#8-have-i-been-pwned-hibp)
9. [Integration Priority Matrix](#9-integration-priority-matrix)

---

## 1. Shodan API

### What It Provides

Shodan continuously scans the entire internet and indexes banners, certificates, and service metadata exposed on open ports. For a given IP or hostname it returns:

- Open ports and detected service names
- Banner/response data per port (HTTP headers, SSH version strings, TLS certificates)
- Hostnames, ASN, ISP, organization, country, city
- Known vulnerabilities (`vulns` field — CVE IDs cross-referenced against service versions)
- Historical scan data (paid tiers)
- SSL/TLS certificate details including Subject Alternative Names
- Operating system fingerprint (when detectable)

**Key endpoint for this project:**

```
GET https://api.shodan.io/shodan/host/{ip}?key={API_KEY}
```

Returns a JSON object with all of the above fields for a single IP.

**Other useful endpoints:**

```
GET https://api.shodan.io/shodan/host/search?query=...&key={API_KEY}   # search
GET https://api.shodan.io/dns/resolve?hostnames=...&key={API_KEY}      # DNS
GET https://api.shodan.io/api-info?key={API_KEY}                       # quota check
```

### Authentication

API key passed as a query parameter `?key=YOUR_API_KEY`. Registration at https://account.shodan.io/

### Free Tier Limits `[VERIFY]`

| Tier | Cost | Query Credits | Scan Credits | Notes |
|------|------|---------------|--------------|-------|
| Free (Member) | $0 | 100/month | 0 | No real-time scanning; read-only historical lookups |
| Freelancer | ~$49/month | 5,000/month | 5,120 IPs | Full API access |
| Small Business | ~$299/month | 25,000/month | 65,536 IPs | |

Free tier can call `/shodan/host/{ip}` but consumes 1 query credit per call. No credits are auto-replenished beyond the 100/month allowance. **Rate limit:** 1 request/second on free tier `[VERIFY]`.

### Java Integration Approach

Use Java 11+ `java.net.http.HttpClient` (no extra dependency):

```java
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ShodanClient {
    private static final String BASE = "https://api.shodan.io";
    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();
    private final String apiKey;

    public JsonNode lookupHost(String ip) throws Exception {
        URI uri = URI.create(BASE + "/shodan/host/" + ip + "?key=" + apiKey);
        HttpRequest req = HttpRequest.newBuilder(uri)
                .header("Accept", "application/json")
                .GET().build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() == 404) return null;   // host not in Shodan index
        if (resp.statusCode() == 401) throw new IllegalStateException("Invalid Shodan API key");
        return mapper.readTree(resp.body());
    }
}
```

**Relevant fields to extract from the response:**

```java
JsonNode host = shodanClient.lookupHost(ip);
if (host != null) {
    host.path("ports")       // ArrayNode of open port numbers Shodan has seen
    host.path("vulns")       // ObjectNode keyed by CVE ID (e.g. "CVE-2021-44228")
    host.path("org")         // "Google LLC"
    host.path("country_name")
    host.path("isp")
    host.path("os")          // may be null
}
```

### Source URLs

- API reference: https://developer.shodan.io/api
- Member registration: https://account.shodan.io/register
- Pricing: https://account.shodan.io/billing/plan

---

## 2. GreyNoise API

### What It Provides

GreyNoise classifies IP addresses as **benign** (known safe scanners, crawlers), **malicious** (observed in attacks), or **unknown**. It focuses on internet background noise — mass scanners, exploit bots, vulnerability probes.

For a given IP it returns:

- `noise` (boolean): whether this IP is part of internet background scanning
- `riot` (boolean): whether this IP belongs to a known benign service (Google, AWS, Cloudflare, etc.)
- `classification`: `"malicious"`, `"benign"`, or `"unknown"`
- `name`: human-readable name of the entity (if riot=true, e.g. "Google LLC")
- `last_seen`: ISO date of last observed activity
- `tags`: array of behavioral tags (e.g. `"scanner"`, `"tor-exit"`, `"exploit"`)
- `cve`: array of CVE IDs the IP has been seen exploiting (Community API may omit this)
- `link`: URL to GreyNoise Visualizer for the IP

**Community API endpoint (free):**

```
GET https://api.greynoise.io/v3/community/{ip}
```

**Full GNQL (paid) endpoint:**

```
GET https://api.greynoise.io/v2/noise/context/{ip}
```

### Authentication

HTTP header: `key: YOUR_API_KEY`

Register at https://www.greynoise.io/plans/community

### Free Tier Limits `[VERIFY]`

| Tier | Cost | Requests | Notes |
|------|------|----------|-------|
| Community | $0 | 50 requests/day | Community endpoint only; limited fields returned |
| Research | $0 (application required) | Higher limits | For academic/research use |
| Paid | From ~$99/month | Depends on plan | Full GNQL, full field set |

Community API returns a reduced field set compared to the full context endpoint. Notably, `cve` and `tags` arrays may be absent.

### Java Integration Approach

```java
public class GreyNoiseClient {
    private static final String COMMUNITY_URL = "https://api.greynoise.io/v3/community/";
    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();
    private final String apiKey;

    public JsonNode classifyIp(String ip) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(COMMUNITY_URL + ip))
                .header("key", apiKey)
                .header("Accept", "application/json")
                .GET().build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        // 404 = IP not in GreyNoise dataset ("unknown")
        if (resp.statusCode() == 404) return null;
        return mapper.readTree(resp.body());
    }
}
```

**Extracting the classification:**

```java
JsonNode result = gnClient.classifyIp(ip);
if (result != null) {
    boolean noise       = result.path("noise").asBoolean();
    boolean riot        = result.path("riot").asBoolean();
    String  cls         = result.path("classification").asText("unknown");
    String  name        = result.path("name").asText("");
    String  lastSeen    = result.path("last_seen").asText("");
    // noise=false + riot=false + classification="unknown" → no data
}
```

**Scanner integration note:** For the port scanner, the most useful signal is `noise=true` + `classification="malicious"` indicating the target IP has been observed actively attacking other hosts — useful context for the scan report.

### Source URLs

- Community API docs: https://developer.greynoise.io/reference/community-api
- Full API docs: https://developer.greynoise.io/docs/using-the-greynoise-api
- Plans: https://www.greynoise.io/plans
- IP lookup UI: https://viz.greynoise.io/ip/

---

## 3. Censys API

### What It Provides

Censys performs internet-wide scans (similar to Shodan) with a strong focus on TLS/SSL certificate transparency and structured host data. For a given IP it returns:

- Open ports with associated services and protocols
- TLS certificate chain details (subject, issuer, SANs, validity dates, fingerprints)
- Service banners (HTTP response headers, SSH banners, etc.)
- Autonomous System Number (ASN), BGP prefix, organization
- Labels (e.g. `"EMBEDDED"`, `"C2"`, `"HONEYPOT"` — paid feature)
- Historical host data (paid)

Censys is particularly strong for certificate-based research: searching for hosts sharing a certificate, tracking infrastructure by cert fingerprint, etc.

**Key endpoint:**

```
GET https://search.censys.io/api/v2/hosts/{ip}
```

Returns a detailed JSON document with `services[]` array, each entry describing one open port/protocol combination.

**Other endpoints:**

```
POST https://search.censys.io/api/v2/hosts/search      # structured query
GET  https://search.censys.io/api/v2/certificates/{fp} # cert details by SHA-256
```

### Authentication

HTTP Basic Authentication: `API_ID:API_SECRET`

Register at https://search.censys.io/register — free account provides API credentials immediately.

```java
String credentials = Base64.getEncoder().encodeToString(
    (apiId + ":" + apiSecret).getBytes(StandardCharsets.UTF_8));
// Header: "Authorization: Basic <credentials>"
```

### Free Tier Limits `[VERIFY]`

| Tier | Cost | Requests | Notes |
|------|------|----------|-------|
| Free | $0 | 250 queries/month | Host lookup + search; 100 results per search page |
| Teams | ~$99/month | 1,000/month | Bulk export, labels, historical data |
| Enterprise | Custom | Unlimited | Full bulk access |

Free tier is sufficient for ad-hoc lookups during scans. At 250/month it is not suitable for automated bulk enrichment without a paid plan.

### Java Integration Approach

```java
public class CensysClient {
    private static final String HOST_URL = "https://search.censys.io/api/v2/hosts/";
    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();
    private final String basicAuth;

    public CensysClient(String apiId, String apiSecret) {
        this.basicAuth = "Basic " + Base64.getEncoder().encodeToString(
            (apiId + ":" + apiSecret).getBytes(StandardCharsets.UTF_8));
    }

    public JsonNode lookupHost(String ip) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(HOST_URL + ip))
                .header("Authorization", basicAuth)
                .header("Accept", "application/json")
                .GET().build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() == 404) return null;
        if (resp.statusCode() == 422) return null; // invalid IP format
        return mapper.readTree(resp.body()).path("result");
    }
}
```

**Extracting useful fields:**

```java
JsonNode host = censysClient.lookupHost(ip);
if (host != null) {
    host.path("services")           // ArrayNode; each has "port", "service_name", "transport_protocol"
    host.path("autonomous_system").path("asn")
    host.path("autonomous_system").path("name")
    host.path("autonomous_system").path("country_code")
    host.path("labels")             // paid: "C2", "HONEYPOT", etc.
}
```

### Source URLs

- API reference: https://search.censys.io/api
- API v2 docs: https://developers.censys.io/
- Registration: https://search.censys.io/register
- Pricing: https://censys.io/pricing

---

## 4. AbuseIPDB API

### What It Provides

AbuseIPDB is a crowd-sourced database of IP addresses reported for malicious activity (SSH brute force, spam, DDoS, web scanning, etc.). For a given IP it returns:

- `abuseConfidenceScore`: 0–100 percentage indicating likelihood of malicious intent
- `totalReports`: number of reports submitted by the community
- `numDistinctUsers`: number of unique reporters
- `lastReportedAt`: ISO timestamp of the most recent report
- `countryCode`, `usageType` (e.g. `"Data Center/Web Hosting/Transit"`, `"ISP"`)
- `isp`, `domain` of the IP owner
- `isWhitelisted`: boolean
- Optional `reports[]` array (paginated, up to last 30 days) with category codes and comments

**Categories relevant to port scanning context:**

| Category | Meaning |
|----------|---------|
| 14 | Port Scan |
| 18 | Brute Force |
| 22 | Hacking |
| 15 | DDoS |

**Key endpoint:**

```
GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose
```

### Authentication

HTTP header: `Key: YOUR_API_KEY`

Register at https://www.abuseipdb.com/register

### Free Tier Limits `[VERIFY]`

| Tier | Cost | Checks/Day | Bulk Reports | Notes |
|------|------|------------|--------------|-------|
| Free | $0 | 1,000/day | 10,000/day | Full check endpoint; reports array limited |
| Basic | ~$40/month | 3,000/day | 50,000/day | |
| Premium | ~$150/month | 10,000/day | 100,000/day | Priority support |

**1,000 lookups/day on free tier is generous** — well suited for enriching port scan results.

### Java Integration Approach

```java
public class AbuseIpDbClient {
    private static final String CHECK_URL = "https://api.abuseipdb.com/api/v2/check";
    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();
    private final String apiKey;

    public JsonNode checkIp(String ip, int maxAgeDays) throws Exception {
        String url = CHECK_URL + "?ipAddress=" + URLEncoder.encode(ip, StandardCharsets.UTF_8)
                   + "&maxAgeInDays=" + maxAgeDays;
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .header("Key", apiKey)
                .header("Accept", "application/json")
                .GET().build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) return null;
        return mapper.readTree(resp.body()).path("data");
    }
}
```

**Extracting the abuse score:**

```java
JsonNode data = abuseClient.checkIp(ip, 90);
if (data != null) {
    int    score         = data.path("abuseConfidenceScore").asInt();
    int    totalReports  = data.path("totalReports").asInt();
    String usageType     = data.path("usageType").asText();
    String isp           = data.path("isp").asText();
    boolean whitelisted  = data.path("isWhitelisted").asBoolean();
    // Flag in report if score > 25 (adjustable threshold)
}
```

### Source URLs

- API docs: https://www.abuseipdb.com/api.html
- API v2 reference: https://docs.abuseipdb.com/
- Registration: https://www.abuseipdb.com/register
- Pricing: https://www.abuseipdb.com/pricing

---

## 5. ExploitDB / MITRE ATT&CK

### 5a. Exploit-DB

#### What It Provides

Exploit-DB (https://www.exploit-db.com/) is an archive of public exploits and vulnerable software maintained by Offensive Security. It does not offer a real-time REST API, but provides:

- **Offline CSV/JSON dataset** downloadable from the repository
- **searchsploit** CLI tool (ships with Kali Linux) that queries the local dataset
- Each exploit entry: `EDB-ID`, title, author, date, platform, type, CVE cross-reference (where available), exploit file path

**Offline integration (recommended approach):**

The entire exploit database is available as a Git repository: https://github.com/offensive-security/exploitdb

The `files_exploits.csv` file in the repo root contains a full index (~60,000+ entries) including CVE cross-references. This can be loaded into a local SQLite database (see Section 6 for the SQLite pattern) and queried by CVE ID:

```sql
SELECT edb_id, description, date, platform, type
FROM exploits
WHERE cve_id = 'CVE-2021-44228';
```

**No API key required** for offline use. The repo is updated continuously and can be refreshed with `git pull`.

#### Java Integration (Offline CSV Loader)

```java
// Load files_exploits.csv once at startup into a Map<String, List<ExploitEntry>>
// keyed by CVE ID for fast lookup during scan enrichment
public class ExploitDbLoader {
    private final Map<String, List<String>> cveToedbIds = new HashMap<>();

    public void loadCsv(Path csvPath) throws IOException {
        try (BufferedReader br = Files.newBufferedReader(csvPath)) {
            br.readLine(); // skip header
            String line;
            while ((line = br.readLine()) != null) {
                String[] cols = line.split(",", -1);
                // col 0 = edb_id, col 11 = CVE (may be empty)
                String cve = cols.length > 11 ? cols[11].trim() : "";
                if (!cve.isEmpty() && cve.startsWith("CVE-")) {
                    cveToedbIds.computeIfAbsent(cve, k -> new ArrayList<>()).add(cols[0]);
                }
            }
        }
    }

    public List<String> getExploits(String cveId) {
        return cveToedbIds.getOrDefault(cveId, Collections.emptyList());
    }
}
```

**Source URLs:**
- Website: https://www.exploit-db.com/
- Git repository (data): https://github.com/offensive-security/exploitdb
- CSV schema: https://github.com/offensive-security/exploitdb/blob/master/files_exploits.csv

---

### 5b. MITRE ATT&CK

#### What It Provides

MITRE ATT&CK is a knowledge base of adversary tactics, techniques, and procedures (TTPs). It is less directly applicable to port-level enrichment but relevant for:

- Mapping detected services to known attack techniques (e.g., port 445 SMB → T1021.002 Remote Services: SMB/Windows Admin Shares)
- Providing context for CVEs via the ATT&CK-CVE mapping dataset
- CAPEC (Common Attack Pattern Enumeration) patterns linked from CWE

#### Access Method

ATT&CK is distributed as **STIX 2.1 JSON bundles** — no API key required:

```
https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

This is a large file (~30 MB). For a port scanner, the most practical use is the **ATT&CK for ICS** or the MITRE CAPEC dataset rather than the full enterprise matrix.

**Simpler approach:** The MITRE ATT&CK TAXII server at `https://cti-taxii.mitre.org/` provides paginated REST access to collections:

```
GET https://cti-taxii.mitre.org/taxii/
GET https://cti-taxii.mitre.org/stix/collections/{collection-id}/objects/
```

No authentication is required. Responses are STIX 2.1 JSON bundles.

#### Java Integration Note

For a port scanner, a practical subset is a hand-curated `port_to_techniques.json` mapping file bundled in `src/main/resources/`, mapping well-known port numbers to relevant ATT&CK technique IDs. This avoids downloading and parsing the full 30 MB bundle at runtime.

**Source URLs:**
- ATT&CK website: https://attack.mitre.org/
- CTI GitHub (STIX bundles): https://github.com/mitre/cti
- TAXII server: https://cti-taxii.mitre.org/
- ATT&CK-CVE mapping: https://attack.mitre.org/resources/working-with-attack/

---

## 6. Offline NVD CVE Feeds (Local SQLite)

### What It Provides

The National Vulnerability Database (NVD) publishes the complete CVE dataset in two formats:

1. **Legacy JSON feeds** (NVD 1.1 format, deprecated 2023 but still available): annual and recent ZIP files
2. **NVD 2.0 REST API** (current): paginated REST endpoint, no bulk file download

For an offline/local approach, the NVD 2.0 API can be used to perform an initial full sync, then incremental updates using the `lastModStartDate` parameter.

**NVD 2.0 API endpoint:**

```
GET https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=...&resultsPerPage=2000
```

Returns JSON with `vulnerabilities[]` array. No authentication required (API key optional but gives higher rate limit).

**Rate limits:**
- Without API key: 5 requests per 30 seconds
- With free API key: 50 requests per 30 seconds

Request a free API key at: https://nvd.nist.gov/developers/request-an-api-key

### Local SQLite Schema (Recommended)

```sql
CREATE TABLE cves (
    cve_id       TEXT PRIMARY KEY,   -- "CVE-2021-44228"
    description  TEXT,
    cvss_v3      REAL,               -- base score 0.0-10.0
    cvss_v2      REAL,
    severity     TEXT,               -- "CRITICAL", "HIGH", "MEDIUM", "LOW"
    published    TEXT,               -- ISO date
    modified     TEXT,
    cpe_list     TEXT                -- JSON array of affected CPE strings
);

CREATE INDEX idx_severity ON cves(severity);
CREATE INDEX idx_cvss_v3  ON cves(cvss_v3);
```

### Java Integration (SQLite via JDBC)

Add dependency to `pom.xml`:

```xml
<dependency>
    <groupId>org.xerial</groupId>
    <artifactId>sqlite-jdbc</artifactId>
    <version>3.45.3.0</version>
</dependency>
```

```java
public class LocalCveDatabase {
    private final Connection conn;

    public LocalCveDatabase(Path dbPath) throws SQLException {
        conn = DriverManager.getConnection("jdbc:sqlite:" + dbPath.toAbsolutePath());
    }

    public Optional<CveRecord> lookup(String cveId) throws SQLException {
        PreparedStatement ps = conn.prepareStatement(
            "SELECT cve_id, description, cvss_v3, severity FROM cves WHERE cve_id = ?");
        ps.setString(1, cveId);
        ResultSet rs = ps.executeQuery();
        if (!rs.next()) return Optional.empty();
        return Optional.of(new CveRecord(
            rs.getString("cve_id"),
            rs.getString("description"),
            rs.getDouble("cvss_v3"),
            rs.getString("severity")
        ));
    }
}
```

### Sync Strategy

- **Initial load:** Paginate through all NVD 2.0 results (approx 250,000 CVEs as of 2025; ~125 requests at 2,000/page)
- **Incremental updates:** Poll `?lastModStartDate=<last_sync_iso>&lastModEndDate=<now_iso>` daily
- **Storage estimate:** ~150–200 MB as SQLite with indexes; ~500 MB as raw JSON

**Alternatives to NVD for offline CVE data:**

- **OSV (Open Source Vulnerabilities):** https://osv.dev/ — Google-maintained, bulk download as ZIP of JSON files per ecosystem. Better for open source software CVEs.
- **CIRCL CVE Search:** https://cve.circl.lu/ — REST API with a Redis-backed search, no API key required, mirrors NVD data.

### Source URLs

- NVD 2.0 API docs: https://nvd.nist.gov/developers/vulnerabilities
- API key request: https://nvd.nist.gov/developers/request-an-api-key
- OSV bulk download: https://osv.dev/docs/#tag/api/operation/OSV_QueryAffected
- OSV data: https://storage.googleapis.com/osv-vulnerabilities/
- CIRCL CVE Search API: https://cve.circl.lu/api/
- SQLite JDBC: https://github.com/xerial/sqlite-jdbc

---

## 7. IPinfo.io / ip-api.com (Geolocation & ASN)

### 7a. IPinfo.io

#### What It Provides

IPinfo.io provides geolocation, ASN/ISP, and hosting detection for IP addresses:

- `ip`, `hostname` (reverse DNS)
- `city`, `region`, `country`, `postal`, `timezone`
- `org`: ASN + organization name (e.g. `"AS15169 Google LLC"`)
- `loc`: latitude/longitude
- `bogon`: boolean — is this a private/reserved IP?
- Paid fields: `privacy` (VPN/proxy/Tor detection), `threat`, `hosted` (cloud provider detection), `abuse` contact

**Key endpoint:**

```
GET https://ipinfo.io/{ip}/json?token={TOKEN}
```

Or without token (heavily rate limited):

```
GET https://ipinfo.io/{ip}/json
```

#### Authentication

Query parameter `?token=YOUR_TOKEN`. Free registration at https://ipinfo.io/signup

#### Free Tier Limits `[VERIFY]`

| Tier | Cost | Lookups/Month | Notes |
|------|------|---------------|-------|
| Free | $0 | 50,000/month | All basic fields; no privacy/threat fields |
| Business | ~$99/month | 150,000/month | Privacy, hosted, abuse fields |

50,000/month free = ~1,667/day. Sufficient for enriching scan results.

#### Java Integration

```java
public class IpInfoClient {
    private static final String BASE = "https://ipinfo.io/";
    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();
    private final String token;

    public JsonNode lookupIp(String ip) throws Exception {
        String url = BASE + ip + "/json" + (token != null ? "?token=" + token : "");
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .header("Accept", "application/json")
                .GET().build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) return null;
        JsonNode node = mapper.readTree(resp.body());
        if (node.has("bogon") && node.path("bogon").asBoolean()) return null; // private IP
        return node;
    }
}
```

**Fields to surface in scan report:**

```java
JsonNode info = ipInfoClient.lookupIp(ip);
if (info != null) {
    String country  = info.path("country").asText();     // "US"
    String org      = info.path("org").asText();          // "AS15169 Google LLC"
    String city     = info.path("city").asText();
    String timezone = info.path("timezone").asText();
}
```

**Source URLs:**
- Docs: https://ipinfo.io/developers
- Pricing: https://ipinfo.io/pricing
- Registration: https://ipinfo.io/signup

---

### 7b. ip-api.com

#### What It Provides

ip-api.com is a simpler, keyless geolocation API useful for development and low-volume production use:

- `country`, `countryCode`, `region`, `regionName`, `city`, `zip`
- `lat`, `lon`, `timezone`
- `isp`, `org`, `as` (ASN string, e.g. `"AS15169 Google LLC"`)
- `query` (IP echo), `status` (`"success"` or `"fail"`)
- `mobile` (boolean), `proxy` (boolean), `hosting` (boolean) — available on paid plans or with `fields` parameter

**Key endpoint (HTTP only on free tier):**

```
GET http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,proxy,hosting
```

**HTTPS is only available on pro tier.** `[VERIFY]`

#### Authentication

None required for free tier. Pro API key passed as query parameter `?key=YOUR_KEY`.

#### Free Tier Limits `[VERIFY]`

| Tier | Cost | Requests | Notes |
|------|------|----------|-------|
| Free | $0 | 45 requests/minute | HTTP only; commercial use prohibited |
| Pro | ~$16/month | 15,000/minute | HTTPS, batch endpoint, no commercial restriction |

**Important:** The free tier of ip-api.com **prohibits commercial use** in its terms. For a commercial tool, use IPinfo.io or the pro plan.

#### Java Integration

```java
// Note: http:// not https:// on free tier
URI uri = URI.create("http://ip-api.com/json/" + ip +
    "?fields=status,country,regionName,city,isp,org,as");
```

**Source URLs:**
- Docs: https://ip-api.com/docs
- Pricing: https://ip-api.com/pricing

---

## 8. Have I Been Pwned (HIBP)

### What It Provides

Have I Been Pwned (https://haveibeenpwned.com/) is primarily a service for checking whether an email address or password has appeared in known data breaches. Its direct applicability to a port scanner is limited, but there are two relevant use cases:

1. **Breach domain check:** If a scanned host's domain has appeared in a known breach dataset (e.g., a company's database was leaked), this could be relevant context.
2. **Pwned Passwords API:** Check if a password string (hashed, k-anonymity model) has appeared in breach data — could be relevant if the scanner captures credential leaks via banner grabbing.

**For a port scanner, HIBP is low-priority** compared to the other APIs in this document.

#### Endpoints

```
GET https://haveibeenpwned.com/api/v3/breacheddomain/{domain}
```
Returns array of breach objects for a domain (e.g., `adobe.com`). Requires API key.

```
GET https://api.pwnedpasswords.com/range/{first5hashChars}
```
Pwned Passwords — **no API key required**, uses k-anonymity (send first 5 chars of SHA-1 hash, receive all matching suffix hashes with counts).

#### Authentication

HIBP v3 API requires a paid API key for all endpoints except Pwned Passwords.

- API key cost: `[VERIFY]` ~$3.50/month (as of 2025)
- Rate limit: 1 request/1,500ms on the free/basic API key tier

Register at: https://haveibeenpwned.com/API/Key

#### Java Integration (Pwned Passwords — no key needed)

```java
// K-anonymity: send first 5 chars of SHA-1 hash, check if full hash suffix is in response
public boolean isPasswordPwned(String password) throws Exception {
    MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
    String hash = HexFormat.of().formatHex(sha1.digest(password.getBytes(StandardCharsets.UTF_8)))
                      .toUpperCase();
    String prefix = hash.substring(0, 5);
    String suffix = hash.substring(5);

    HttpRequest req = HttpRequest.newBuilder(
            URI.create("https://api.pwnedpasswords.com/range/" + prefix))
            .header("Add-Padding", "true")  // prevents traffic analysis
            .GET().build();
    HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());

    return Arrays.stream(resp.body().split("\r\n"))
            .map(line -> line.split(":")[0])
            .anyMatch(s -> s.equalsIgnoreCase(suffix));
}
```

#### Source URLs

- API docs v3: https://haveibeenpwned.com/API/v3
- Pwned Passwords API: https://haveibeenpwned.com/API/v3#PwnedPasswords
- API key purchase: https://haveibeenpwned.com/API/Key
- Troy Hunt blog (HIBP creator): https://www.troyhunt.com/

---

## 9. Integration Priority Matrix

Ranked by utility for a TCP port scanner + implementation cost:

| Priority | API | Use Case | Free Tier Quality | Complexity |
|----------|-----|----------|-------------------|------------|
| 1 | **AbuseIPDB** | IP abuse score, malicious activity flag | Excellent (1,000/day) | Low |
| 2 | **GreyNoise Community** | Background noise / malicious scanner detection | Good (50/day) | Low |
| 3 | **IPinfo.io** | Geolocation, ASN, ISP enrichment | Excellent (50K/month) | Low |
| 4 | **NVD CVE (local SQLite)** | Offline CVE lookup by ID | Unlimited (offline) | Medium |
| 5 | **Shodan** | Historical open ports, vulns, banners | Limited (100/month) | Low |
| 6 | **ExploitDB (offline CSV)** | Exploit availability for detected CVEs | Unlimited (offline) | Medium |
| 7 | **Censys** | TLS cert details, alternative to Shodan | Limited (250/month) | Low |
| 8 | **MITRE ATT&CK** | Port-to-TTP mapping (static resource) | Unlimited (offline) | Medium |
| 9 | **Have I Been Pwned** | Domain breach history | Paid API key required | Low |

### Recommended Initial Implementation Set

For maximum value with minimal API key dependency:

1. **AbuseIPDB** — Single endpoint, excellent free tier, immediately actionable score
2. **GreyNoise Community** — Simple classification, good complementary signal to AbuseIPDB
3. **IPinfo.io** — Geolocation/ASN enrichment, generous free tier
4. **Local NVD SQLite** — Offline CVE lookup once the database is seeded; pairs with the existing `CveLookup` class

These four together cover IP reputation, geolocation, and vulnerability context with no per-request cost beyond the AbuseIPDB and GreyNoise daily limits.

---

*Document generated: 2026-03-11*
*Knowledge basis: Training data up to August 2025*
*Fields marked `[VERIFY]` should be confirmed against the source URLs before implementation, as pricing and rate limits change more frequently than API structure.*
