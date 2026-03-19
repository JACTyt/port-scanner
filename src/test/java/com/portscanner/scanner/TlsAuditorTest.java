package com.portscanner.scanner;

import com.portscanner.model.TlsAuditResult;
import com.portscanner.model.TlsVulnerability;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TlsAuditorTest {

    // ── Model construction ────────────────────────────────────────────────

    @Test
    void tls_vulnerability_builder_all_fields() {
        TlsVulnerability v = TlsVulnerability.builder()
                .name("Heartbleed")
                .cve("CVE-2014-0160")
                .severity("CRITICAL")
                .description("Memory disclosure via malformed heartbeat")
                .build();
        assertEquals("Heartbleed", v.getName());
        assertEquals("CVE-2014-0160", v.getCve());
        assertEquals("CRITICAL", v.getSeverity());
        assertNotNull(v.getDescription());
    }

    @Test
    void tls_audit_result_builder_all_fields() {
        TlsVulnerability v = TlsVulnerability.builder().name("BEAST").severity("MEDIUM").build();
        TlsAuditResult r = TlsAuditResult.builder()
                .supportedProtocols(List.of("TLSv1.2", "TLSv1.3"))
                .acceptedCiphers(List.of("TLS_AES_256_GCM_SHA384"))
                .weakCiphers(List.of("TLS_RSA_WITH_3DES_EDE_CBC_SHA"))
                .vulnerabilities(List.of(v))
                .build();
        assertEquals(2, r.getSupportedProtocols().size());
        assertEquals(1, r.getAcceptedCiphers().size());
        assertEquals(1, r.getWeakCiphers().size());
        assertEquals(1, r.getVulnerabilities().size());
        assertEquals("BEAST", r.getVulnerabilities().get(0).getName());
    }

    @Test
    void tls_audit_result_no_args_constructor() {
        TlsAuditResult r = new TlsAuditResult();
        assertNull(r.getSupportedProtocols());
        assertNull(r.getWeakCiphers());
        assertNull(r.getVulnerabilities());
    }

    @Test
    void tls_vulnerability_no_args_constructor() {
        TlsVulnerability v = new TlsVulnerability();
        assertNull(v.getName());
        assertNull(v.getCve());
        assertNull(v.getSeverity());
    }

    // ── Heartbleed probe against a non-TLS port ───────────────────────────

    @Test
    void heartbleed_probe_returns_false_for_non_tls_port() throws Exception {
        // Port 9 is typically "discard" — connection may refuse
        // Use loopback + discard port; probe should not throw and should return false
        boolean result = TlsAuditor.probeHeartbleed("localhost", 9, 200);
        assertFalse(result, "Non-TLS port should not be flagged as Heartbleed-vulnerable");
    }

    @Test
    void heartbleed_probe_returns_false_for_unreachable_host() {
        boolean result = TlsAuditor.probeHeartbleed("192.0.2.1", 443, 100);
        assertFalse(result);
    }

    // ── Protocol support detection ────────────────────────────────────────

    @Test
    void supports_protocol_returns_false_for_unreachable_host() {
        boolean result = TlsAuditor.supportsProtocol("192.0.2.1", 443, "TLSv1.2", 100);
        assertFalse(result);
    }

    @Test
    void supports_protocol_returns_false_for_non_tls_port() {
        boolean result = TlsAuditor.supportsProtocol("localhost", 9, "TLSv1.2", 200);
        assertFalse(result);
    }

    // ── audit() returns empty for non-TLS endpoints ───────────────────────

    @Test
    void audit_returns_empty_for_non_tls_endpoint() {
        // No TLS server running on port 1 — should return empty, not throw
        var result = TlsAuditor.audit("localhost", 1, 200);
        assertTrue(result.isEmpty());
    }

    // ── Vulnerability severity labels ─────────────────────────────────────

    @Test
    void vulnerability_severity_levels_are_valid_strings() {
        List<String> validSeverities = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO");
        TlsVulnerability v = TlsVulnerability.builder()
                .name("Test")
                .severity("CRITICAL")
                .build();
        assertTrue(validSeverities.contains(v.getSeverity()));
    }
}
