package com.portscanner.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.portscanner.model.GeoLocation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;

public class IpInfoClient {

    private static final Logger log = LoggerFactory.getLogger(IpInfoClient.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static Optional<GeoLocation> lookup(String ip, String token) {
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            String url = "https://ipinfo.io/" + ip + "/json";
            if (token != null && !token.isBlank()) {
                url += "?token=" + token;
            }

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                log.debug("IPinfo returned status {}", response.statusCode());
                return Optional.empty();
            }

            return parseResponse(response.body());
        } catch (Exception e) {
            log.debug("IPinfo lookup failed for {}: {}", ip, e.getMessage());
            return Optional.empty();
        }
    }

    static Optional<GeoLocation> parseResponse(String json) {
        try {
            JsonNode root = MAPPER.readTree(json);
            String ip = root.path("ip").asText(null);
            String hostname = root.path("hostname").asText(null);
            String city = root.path("city").asText(null);
            String region = root.path("region").asText(null);
            String country = root.path("country").asText(null);
            String org = root.path("org").asText(null);
            String timezone = root.path("timezone").asText(null);

            return Optional.of(GeoLocation.builder()
                    .ip(ip)
                    .hostname(hostname)
                    .city(city)
                    .region(region)
                    .country(country)
                    .org(org)
                    .timezone(timezone)
                    .build());
        } catch (Exception e) {
            log.debug("IPinfo parse failed: {}", e.getMessage());
            return Optional.empty();
        }
    }
}
