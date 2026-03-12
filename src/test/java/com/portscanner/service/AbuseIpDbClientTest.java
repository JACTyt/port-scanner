package com.portscanner.service;

import com.portscanner.model.ThreatInfo;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class AbuseIpDbClientTest {

    @Test
    void parses_valid_response() {
        String json = """
                {
                  "data": {
                    "ipAddress": "8.8.8.8",
                    "abuseConfidenceScore": 0,
                    "totalReports": 5,
                    "isp": "Google LLC",
                    "domain": "google.com"
                  }
                }
                """;
        Optional<ThreatInfo> result = AbuseIpDbClient.parseResponse(json);
        assertTrue(result.isPresent());
        assertEquals(0, result.get().getAbuseConfidenceScore());
        assertEquals(5, result.get().getAbuseReportCount());
        assertEquals("Google LLC", result.get().getIsp());
    }

    @Test
    void parses_high_risk_score() {
        String json = """
                {
                  "data": {
                    "ipAddress": "1.2.3.4",
                    "abuseConfidenceScore": 100,
                    "totalReports": 150,
                    "isp": "Bad ISP"
                  }
                }
                """;
        Optional<ThreatInfo> result = AbuseIpDbClient.parseResponse(json);
        assertTrue(result.isPresent());
        assertEquals(100, result.get().getAbuseConfidenceScore());
        assertEquals(150, result.get().getAbuseReportCount());
    }

    @Test
    void returns_empty_for_missing_data_field() {
        String json = """
                {
                  "errors": [{"status": 401, "detail": "Unauthorized"}]
                }
                """;
        Optional<ThreatInfo> result = AbuseIpDbClient.parseResponse(json);
        assertTrue(result.isEmpty());
    }

    @Test
    void returns_empty_for_invalid_json() {
        Optional<ThreatInfo> result = AbuseIpDbClient.parseResponse("not json");
        assertTrue(result.isEmpty());
    }
}
