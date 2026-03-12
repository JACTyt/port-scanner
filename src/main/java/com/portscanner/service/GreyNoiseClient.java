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

public class GreyNoiseClient {

    private static final Logger log = LoggerFactory.getLogger(GreyNoiseClient.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static Optional<ThreatInfo> check(String ip, String apiKey) {
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            String url = "https://api.greynoise.io/v3/community/" + ip;
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET();
            if (apiKey != null && !apiKey.isBlank()) {
                builder.header("key", apiKey);
            }
            HttpRequest request = builder.build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                log.debug("GreyNoise returned status {}", response.statusCode());
                return Optional.empty();
            }

            return parseResponse(response.body());
        } catch (Exception e) {
            log.debug("GreyNoise check failed for {}: {}", ip, e.getMessage());
            return Optional.empty();
        }
    }

    static Optional<ThreatInfo> parseResponse(String json) {
        try {
            JsonNode root = MAPPER.readTree(json);
            String classification = root.path("classification").asText(null);
            boolean noise = root.path("noise").asBoolean(false);
            String name = root.path("name").asText(null);

            return Optional.of(ThreatInfo.builder()
                    .greynoiseClassification(classification)
                    .greynoiseIsScanner(noise)
                    .isp(name)
                    .build());
        } catch (Exception e) {
            log.debug("GreyNoise parse failed: {}", e.getMessage());
            return Optional.empty();
        }
    }
}
