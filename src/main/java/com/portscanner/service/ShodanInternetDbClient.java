package com.portscanner.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.portscanner.model.ShodanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;

/**
 * Queries the Shodan InternetDB API — a free, no-key-required endpoint that returns
 * known open ports, CPEs, CVEs, hostnames, and tags for an IP address.
 *
 * <pre>GET https://internetdb.shodan.io/{ip}</pre>
 */
public class ShodanInternetDbClient {

    private static final Logger log = LoggerFactory.getLogger(ShodanInternetDbClient.class);
    private static final String BASE_URL = "https://internetdb.shodan.io/";

    private final HttpClient http;
    private final ObjectMapper mapper;

    public ShodanInternetDbClient() {
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        this.mapper = new ObjectMapper();
    }

    /**
     * Query Shodan InternetDB for the given IP address.
     *
     * @param ip IPv4 or IPv6 address string
     * @return populated {@link ShodanResult}, or empty if the IP is not indexed or the request fails
     */
    public Optional<ShodanResult> query(String ip) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(BASE_URL + ip))
                    .header("User-Agent", "port-scanner/2.0")
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();

            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());

            if (resp.statusCode() == 404) {
                log.debug("Shodan InternetDB: no data indexed for {}", ip);
                return Optional.empty();
            }
            if (resp.statusCode() != 200) {
                log.warn("Shodan InternetDB returned HTTP {} for {}", resp.statusCode(), ip);
                return Optional.empty();
            }

            return Optional.of(mapper.readValue(resp.body(), ShodanResult.class));

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } catch (Exception e) {
            log.debug("Shodan InternetDB query failed for {}: {}", ip, e.getMessage());
            return Optional.empty();
        }
    }
}
