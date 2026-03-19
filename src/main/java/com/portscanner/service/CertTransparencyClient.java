package com.portscanner.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.portscanner.model.CtLogEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Client for the crt.sh Certificate Transparency log API.
 * Finds subdomains of a domain by querying CT logs — discovers hosts that
 * may not appear in public DNS or zone files.
 */
public class CertTransparencyClient {

    private static final Logger log = LoggerFactory.getLogger(CertTransparencyClient.class);

    private static final String CRT_SH_URL = "https://crt.sh/?q=%25.%s&output=json";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final HttpClient httpClient;

    public CertTransparencyClient() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    /**
     * Queries Certificate Transparency logs for all certificate entries matching
     * {@code %.domain} and returns deduplicated, normalized subdomain names.
     * Wildcard prefixes are stripped; only names ending with the target domain are returned.
     *
     * @param domain the apex domain to search (e.g., "example.com")
     * @return deduplicated list of subdomain names (may be empty on error or no results)
     */
    public List<String> findSubdomains(String domain) {
        String normalizedDomain = domain.toLowerCase().trim();
        String url = String.format(CRT_SH_URL, normalizedDomain);
        log.debug("Querying CT logs: {}", url);

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(30))
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                log.warn("crt.sh returned HTTP {} for domain {}", response.statusCode(), domain);
                return List.of();
            }

            return parseSubdomains(response.body(), normalizedDomain);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.debug("CT recon interrupted for {}", domain);
            return List.of();
        } catch (Exception e) {
            log.debug("CT recon failed for {} — {}", domain, e.getMessage());
            return List.of();
        }
    }

    /**
     * Parses the crt.sh JSON response and extracts unique subdomain names.
     * Each entry's {@code name_value} may contain multiple newline-separated names.
     */
    List<String> parseSubdomains(String json, String targetDomain) {
        Set<String> subdomains = new LinkedHashSet<>();
        try {
            JsonNode root = MAPPER.readTree(json);
            if (!root.isArray()) return List.of();

            for (JsonNode entry : root) {
                JsonNode nameNode = entry.get("name_value");
                if (nameNode == null) continue;

                // name_value may contain multiple names separated by newlines
                for (String rawName : nameNode.asText().split("\n")) {
                    String name = rawName.trim().toLowerCase();
                    // Strip wildcard prefix
                    if (name.startsWith("*.")) {
                        name = name.substring(2);
                    }
                    // Only include names that are subdomains of (or equal to) the target
                    if (!name.isEmpty()
                            && (name.equals(targetDomain) || name.endsWith("." + targetDomain))) {
                        subdomains.add(name);
                    }
                }
            }
        } catch (Exception e) {
            log.debug("Error parsing CT log JSON: {}", e.getMessage());
        }
        return new ArrayList<>(subdomains);
    }

    /**
     * Returns the full list of {@link CtLogEntry} records from crt.sh for richer metadata
     * (issuer, validity dates). Useful for surfacing recently-expired certificates.
     */
    public List<CtLogEntry> findEntries(String domain) {
        String normalizedDomain = domain.toLowerCase().trim();
        String url = String.format(CRT_SH_URL, normalizedDomain);
        List<CtLogEntry> entries = new ArrayList<>();

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(30))
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonNode root = MAPPER.readTree(response.body());
                if (root.isArray()) {
                    for (JsonNode node : root) {
                        try {
                            entries.add(MAPPER.treeToValue(node, CtLogEntry.class));
                        } catch (Exception ignored) {
                            // Skip malformed entries
                        }
                    }
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            log.debug("CT entries fetch failed for {} — {}", domain, e.getMessage());
        }
        return entries;
    }
}
