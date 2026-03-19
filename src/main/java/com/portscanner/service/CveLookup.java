package com.portscanner.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.portscanner.model.CveEntry;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Queries the NIST NVD REST API v2 for CVEs matching a service+version keyword.
 * Returns enriched {@link CveEntry} objects with CVSS v3/v2 scores and descriptions.
 * Results are cached in-memory per session.
 * NVD rate limit: ~5 requests/30s without API key — enforced with delay.
 */
public class CveLookup {

    private static final String NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static final int MAX_RESULTS = 5;
    private static final long RATE_LIMIT_DELAY_MS = 6200; // ~1 req/6s to stay under 5/30s

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Map<String, List<CveEntry>> cache = new ConcurrentHashMap<>();
    private long lastRequestTime = 0;

    public CveLookup() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Extracts a searchable keyword from banner + service name.
     * E.g. "SSH-2.0-OpenSSH_8.9p1" → "OpenSSH 8.9p1"
     */
    public String extractKeyword(String serviceName, String banner) {
        if (banner == null || banner.isBlank()) {
            return serviceName != null ? serviceName : "";
        }
        String cleaned = banner.replaceAll("[_/]", " ").trim();
        return cleaned.length() > 60 ? cleaned.substring(0, 60) : cleaned;
    }

    /**
     * Looks up CVEs for the given keyword. Returns up to MAX_RESULTS enriched {@link CveEntry} objects.
     * Checks local SQLite database first; falls back to live NVD API if no local results.
     */
    public List<CveEntry> lookup(String keyword) {
        if (keyword == null || keyword.isBlank()) return List.of();
        if (cache.containsKey(keyword)) return cache.get(keyword);

        // Try local database first
        LocalCveDatabase localDb = new LocalCveDatabase();
        if (localDb.isDatabasePresent()) {
            List<String> localIds = localDb.query(keyword);
            if (!localIds.isEmpty()) {
                List<CveEntry> entries = localIds.stream()
                        .map(id -> CveEntry.builder().id(id).build())
                        .toList();
                cache.put(keyword, entries);
                return entries;
            }
        }

        enforceRateLimit();

        try {
            String encoded = URLEncoder.encode(keyword, StandardCharsets.UTF_8);
            String url = NVD_API + "?keywordSearch=" + encoded + "&resultsPerPage=" + MAX_RESULTS;

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("User-Agent", "portscanner-cve-lookup/1.0")
                    .timeout(Duration.ofSeconds(15))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            lastRequestTime = System.currentTimeMillis();

            if (response.statusCode() != 200) {
                cache.put(keyword, List.of());
                return List.of();
            }

            JsonNode root = objectMapper.readTree(response.body());
            JsonNode vulnerabilities = root.path("vulnerabilities");
            List<CveEntry> entries = new ArrayList<>();
            for (JsonNode vuln : vulnerabilities) {
                JsonNode cveNode = vuln.path("cve");
                String cveId = cveNode.path("id").asText(null);
                if (cveId == null) continue;

                CveEntry.CveEntryBuilder builder = CveEntry.builder().id(cveId);

                // Parse CVSS v3.1
                JsonNode metricsV31 = cveNode.path("metrics").path("cvssMetricV31");
                if (metricsV31.isArray() && metricsV31.size() > 0) {
                    JsonNode cvssData = metricsV31.get(0).path("cvssData");
                    double score = cvssData.path("baseScore").asDouble(0);
                    if (score > 0) {
                        builder.cvssV3(score);
                        builder.cvssVector(cvssData.path("vectorString").asText(null));
                        String sev = cvssData.path("baseSeverity").asText(null);
                        builder.severity(sev != null ? sev : CveEntry.deriveSeverity(score));
                    }
                }

                // Parse CVSS v3.0 as fallback
                if (!metricsV31.isArray() || metricsV31.size() == 0) {
                    JsonNode metricsV30 = cveNode.path("metrics").path("cvssMetricV30");
                    if (metricsV30.isArray() && metricsV30.size() > 0) {
                        JsonNode cvssData = metricsV30.get(0).path("cvssData");
                        double score = cvssData.path("baseScore").asDouble(0);
                        if (score > 0) {
                            builder.cvssV3(score);
                            builder.cvssVector(cvssData.path("vectorString").asText(null));
                            String sev = cvssData.path("baseSeverity").asText(null);
                            builder.severity(sev != null ? sev : CveEntry.deriveSeverity(score));
                        }
                    }
                }

                // Parse CVSS v2
                JsonNode metricsV2 = cveNode.path("metrics").path("cvssMetricV2");
                if (metricsV2.isArray() && metricsV2.size() > 0) {
                    double score = metricsV2.get(0).path("cvssData").path("baseScore").asDouble(0);
                    if (score > 0) builder.cvssV2(score);
                }

                // Parse description
                JsonNode descs = cveNode.path("descriptions");
                if (descs.isArray()) {
                    for (JsonNode desc : descs) {
                        if ("en".equals(desc.path("lang").asText())) {
                            String text = desc.path("value").asText(null);
                            if (text != null) {
                                builder.description(text.length() > 120 ? text.substring(0, 120) : text);
                            }
                            break;
                        }
                    }
                }

                entries.add(builder.build());
            }

            cache.put(keyword, entries);
            return entries;

        } catch (Exception e) {
            System.err.println("Warning: CVE lookup failed for '" + keyword + "': " + e.getMessage());
            cache.put(keyword, List.of());
            return List.of();
        }
    }

    private synchronized void enforceRateLimit() {
        long elapsed = System.currentTimeMillis() - lastRequestTime;
        if (elapsed < RATE_LIMIT_DELAY_MS) {
            try {
                Thread.sleep(RATE_LIMIT_DELAY_MS - elapsed);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
