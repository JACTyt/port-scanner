package com.portscanner.service;

import com.portscanner.model.GeoLocation;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class IpInfoClientTest {

    @Test
    void parses_full_response() {
        String json = """
                {
                  "ip": "8.8.8.8",
                  "hostname": "dns.google",
                  "city": "Mountain View",
                  "region": "California",
                  "country": "US",
                  "loc": "37.3861,-122.0839",
                  "org": "AS15169 Google LLC",
                  "postal": "94035",
                  "timezone": "America/Los_Angeles"
                }
                """;
        Optional<GeoLocation> result = IpInfoClient.parseResponse(json);
        assertTrue(result.isPresent());
        GeoLocation geo = result.get();
        assertEquals("8.8.8.8", geo.getIp());
        assertEquals("dns.google", geo.getHostname());
        assertEquals("Mountain View", geo.getCity());
        assertEquals("California", geo.getRegion());
        assertEquals("US", geo.getCountry());
        assertEquals("AS15169 Google LLC", geo.getOrg());
        assertEquals("America/Los_Angeles", geo.getTimezone());
    }

    @Test
    void parses_minimal_response() {
        String json = """
                {
                  "ip": "1.2.3.4",
                  "country": "DE"
                }
                """;
        Optional<GeoLocation> result = IpInfoClient.parseResponse(json);
        assertTrue(result.isPresent());
        assertEquals("1.2.3.4", result.get().getIp());
        assertEquals("DE", result.get().getCountry());
        assertNull(result.get().getCity());
    }

    @Test
    void returns_empty_for_invalid_json() {
        Optional<GeoLocation> result = IpInfoClient.parseResponse("not json");
        assertTrue(result.isEmpty());
    }

    @Test
    void returns_empty_for_null() {
        Optional<GeoLocation> result = IpInfoClient.parseResponse(null);
        assertTrue(result.isEmpty());
    }
}
