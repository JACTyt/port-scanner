package com.portscanner.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.portscanner.model.ThreatInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;

public class AbuseIpDbClient {

    private static final Logger log = LoggerFactory.getLogger(AbuseIpDbClient.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static Optional<ThreatInfo> check(String ip, String apiKey) {
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            String url = "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip + "&maxAgeInDays=90";
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Key", apiKey)
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                log.debug("AbuseIPDB returned status {}", response.statusCode());
                return Optional.empty();
            }

            return parseResponse(response.body());
        } catch (Exception e) {
            log.debug("AbuseIPDB check failed for {}: {}", ip, e.getMessage());
            return Optional.empty();
        }
    }

    static Optional<ThreatInfo> parseResponse(String json) {
        try {
            JsonNode root = MAPPER.readTree(json);
            JsonNode data = root.get("data");
            if (data == null) return Optional.empty();

            int score = data.path("abuseConfidenceScore").asInt(0);
            int reports = data.path("totalReports").asInt(0);
            String isp = data.path("isp").asText(null);

            return Optional.of(ThreatInfo.builder()
                    .abuseConfidenceScore(score)
                    .abuseReportCount(reports)
                    .isp(isp)
                    .build());
        } catch (Exception e) {
            log.debug("AbuseIPDB parse failed: {}", e.getMessage());
            return Optional.empty();
        }
    }
}
