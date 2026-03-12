package com.portscanner.service;

import com.portscanner.model.ThreatInfo;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class GreyNoiseClientTest {

    @Test
    void parses_malicious_classification() {
        String json = """
                {
                  "ip": "1.2.3.4",
                  "noise": true,
                  "riot": false,
                  "classification": "malicious",
                  "name": "Shodan.io",
                  "link": "https://viz.greynoise.io/ip/1.2.3.4",
                  "last_seen": "2026-03-11",
                  "message": "This IP is commonly included in scanners."
                }
                """;
        Optional<ThreatInfo> result = GreyNoiseClient.parseResponse(json);
        assertTrue(result.isPresent());
        assertEquals("malicious", result.get().getGreynoiseClassification());
        assertTrue(result.get().isGreynoiseIsScanner());
        assertEquals("Shodan.io", result.get().getIsp());
    }

    @Test
    void parses_benign_classification() {
        String json = """
                {
                  "ip": "8.8.8.8",
                  "noise": false,
                  "riot": true,
                  "classification": "benign",
                  "name": "Google Public DNS",
                  "link": "https://viz.greynoise.io/ip/8.8.8.8",
                  "last_seen": "2026-03-11",
                  "message": "This IP is a known benign service."
                }
                """;
        Optional<ThreatInfo> result = GreyNoiseClient.parseResponse(json);
        assertTrue(result.isPresent());
        assertEquals("benign", result.get().getGreynoiseClassification());
        assertFalse(result.get().isGreynoiseIsScanner());
    }

    @Test
    void returns_empty_for_invalid_json() {
        Optional<ThreatInfo> result = GreyNoiseClient.parseResponse("not json");
        assertTrue(result.isEmpty());
    }

    @Test
    void handles_unknown_classification() {
        String json = """
                {
                  "ip": "5.5.5.5",
                  "noise": false,
                  "classification": "unknown",
                  "name": null
                }
                """;
        Optional<ThreatInfo> result = GreyNoiseClient.parseResponse(json);
        assertTrue(result.isPresent());
        assertEquals("unknown", result.get().getGreynoiseClassification());
    }
}
