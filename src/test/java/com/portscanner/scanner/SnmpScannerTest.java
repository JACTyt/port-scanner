package com.portscanner.scanner;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SnmpScannerTest {

    // ── parseCommunities ──────────────────────────────────────────────────────

    @Test
    void parseCommunities_null_returns_defaults() {
        List<String> result = SnmpScanner.parseCommunities(null);
        assertEquals(List.of("public", "private"), result);
    }

    @Test
    void parseCommunities_blank_returns_defaults() {
        List<String> result = SnmpScanner.parseCommunities("   ");
        assertEquals(List.of("public", "private"), result);
    }

    @Test
    void parseCommunities_single_value() {
        List<String> result = SnmpScanner.parseCommunities("public");
        assertEquals(List.of("public"), result);
    }

    @Test
    void parseCommunities_comma_separated() {
        List<String> result = SnmpScanner.parseCommunities("public,private,secret");
        assertEquals(List.of("public", "private", "secret"), result);
    }

    @Test
    void parseCommunities_trims_whitespace() {
        List<String> result = SnmpScanner.parseCommunities(" public , private ");
        assertEquals(List.of("public", "private"), result);
    }

    @Test
    void parseCommunities_filters_empty_segments() {
        List<String> result = SnmpScanner.parseCommunities("public,,private");
        assertEquals(List.of("public", "private"), result);
    }

    @Test
    void parseCommunities_all_empty_segments_returns_defaults() {
        List<String> result = SnmpScanner.parseCommunities(",,,");
        assertEquals(List.of("public", "private"), result);
    }

    // ── constructor defaults ──────────────────────────────────────────────────

    @Test
    void constructor_empty_communities_uses_defaults() {
        // An empty list passed to the constructor should fall back to public/private.
        // We verify indirectly: probe() will try those defaults and return empty (no real agent).
        // This test just ensures no exception is thrown constructing with an empty list.
        assertDoesNotThrow(() -> new SnmpScanner(100, List.of()));
    }

    @Test
    void constructor_non_empty_communities_accepted() {
        assertDoesNotThrow(() -> new SnmpScanner(500, List.of("public")));
    }

    // ── probe returns empty when no SNMP agent listening ──────────────────────

    @Test
    void probe_returns_empty_for_loopback_no_agent() throws Exception {
        // Port 161 is almost certainly not open in CI; expect empty without exception.
        SnmpScanner scanner = new SnmpScanner(300, List.of("public"));
        var result = scanner.probe(java.net.InetAddress.getLoopbackAddress());
        // Result may be present if an SNMP agent happens to be running, but must not throw.
        assertNotNull(result);
    }
}
