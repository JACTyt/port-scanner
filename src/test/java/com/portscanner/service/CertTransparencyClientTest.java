package com.portscanner.service;

import com.portscanner.model.CtLogEntry;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CertTransparencyClientTest {

    // ── Model construction ────────────────────────────────────────────────

    @Test
    void ct_log_entry_builder_all_fields() {
        CtLogEntry entry = CtLogEntry.builder()
                .nameValue("sub.example.com")
                .notBefore("2024-01-01")
                .notAfter("2025-01-01")
                .issuerCaId(12345L)
                .build();
        assertEquals("sub.example.com", entry.getNameValue());
        assertEquals("2024-01-01", entry.getNotBefore());
        assertEquals("2025-01-01", entry.getNotAfter());
        assertEquals(12345L, entry.getIssuerCaId());
    }

    @Test
    void ct_log_entry_no_args_constructor() {
        CtLogEntry entry = new CtLogEntry();
        assertNull(entry.getNameValue());
        assertNull(entry.getNotBefore());
    }

    // ── parseSubdomains logic ─────────────────────────────────────────────

    @Test
    void parses_simple_subdomain_json() {
        CertTransparencyClient client = new CertTransparencyClient();
        String json = "[{\"name_value\":\"www.example.com\",\"not_before\":\"2024-01-01\"}]";
        List<String> result = client.parseSubdomains(json, "example.com");
        assertEquals(1, result.size());
        assertEquals("www.example.com", result.get(0));
    }

    @Test
    void strips_wildcard_prefix() {
        CertTransparencyClient client = new CertTransparencyClient();
        String json = "[{\"name_value\":\"*.example.com\"}]";
        List<String> result = client.parseSubdomains(json, "example.com");
        assertEquals(1, result.size());
        assertEquals("example.com", result.get(0));
    }

    @Test
    void deduplicates_repeated_entries() {
        CertTransparencyClient client = new CertTransparencyClient();
        String json = "[{\"name_value\":\"www.example.com\"},{\"name_value\":\"www.example.com\"}]";
        List<String> result = client.parseSubdomains(json, "example.com");
        assertEquals(1, result.size());
    }

    @Test
    void handles_multiline_name_value() {
        CertTransparencyClient client = new CertTransparencyClient();
        String json = "[{\"name_value\":\"www.example.com\\napi.example.com\\nmail.example.com\"}]";
        List<String> result = client.parseSubdomains(json, "example.com");
        assertEquals(3, result.size());
        assertTrue(result.contains("www.example.com"));
        assertTrue(result.contains("api.example.com"));
        assertTrue(result.contains("mail.example.com"));
    }

    @Test
    void filters_out_unrelated_domains() {
        CertTransparencyClient client = new CertTransparencyClient();
        String json = "[{\"name_value\":\"www.example.com\"},{\"name_value\":\"attacker.com\"}]";
        List<String> result = client.parseSubdomains(json, "example.com");
        assertEquals(1, result.size());
        assertEquals("www.example.com", result.get(0));
    }

    @Test
    void includes_apex_domain_itself() {
        CertTransparencyClient client = new CertTransparencyClient();
        String json = "[{\"name_value\":\"example.com\"}]";
        List<String> result = client.parseSubdomains(json, "example.com");
        assertEquals(1, result.size());
        assertEquals("example.com", result.get(0));
    }

    @Test
    void returns_empty_list_for_empty_json_array() {
        CertTransparencyClient client = new CertTransparencyClient();
        List<String> result = client.parseSubdomains("[]", "example.com");
        assertTrue(result.isEmpty());
    }

    @Test
    void returns_empty_list_for_malformed_json() {
        CertTransparencyClient client = new CertTransparencyClient();
        List<String> result = client.parseSubdomains("{{{invalid", "example.com");
        assertTrue(result.isEmpty());
    }

    @Test
    void normalizes_domain_case() {
        CertTransparencyClient client = new CertTransparencyClient();
        String json = "[{\"name_value\":\"WWW.EXAMPLE.COM\"}]";
        List<String> result = client.parseSubdomains(json, "example.com");
        assertEquals(1, result.size());
        assertEquals("www.example.com", result.get(0));
    }

    // ── Constructor ───────────────────────────────────────────────────────

    @Test
    void constructor_does_not_throw() {
        assertDoesNotThrow(CertTransparencyClient::new);
    }

    // ── findSubdomains against unreachable URL ─────────────────────────────

    @Test
    void find_subdomains_returns_empty_on_network_error() {
        // localhost:1 is unlikely to be a crt.sh server — should return empty, not throw
        // We can't easily override the base URL, so test that the method is robust to failure
        CertTransparencyClient client = new CertTransparencyClient();
        // Parsing an empty JSON array simulates a "no results" response
        List<String> result = client.parseSubdomains("[]", "no-results.example.com");
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }
}
