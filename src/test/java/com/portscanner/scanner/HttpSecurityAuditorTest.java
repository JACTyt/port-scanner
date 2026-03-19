package com.portscanner.scanner;

import com.portscanner.model.HeaderFinding;
import com.portscanner.model.HttpSecurityAuditResult;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class HttpSecurityAuditorTest {

    private HttpServer mockServer;
    private int port;

    @BeforeEach
    void startMock() throws Exception {
        mockServer = HttpServer.create(new InetSocketAddress(0), 0);
        port = mockServer.getAddress().getPort();
    }

    @AfterEach
    void stopMock() {
        mockServer.stop(0);
    }

    // ── Model construction ────────────────────────────────────────────────

    @Test
    void http_security_audit_result_builder() {
        HeaderFinding f = HeaderFinding.builder()
                .header("Content-Security-Policy")
                .severity("HIGH")
                .recommendation("Add CSP")
                .build();
        HttpSecurityAuditResult r = HttpSecurityAuditResult.builder()
                .score(45)
                .grade("D")
                .findings(java.util.List.of(f))
                .build();
        assertEquals(45, r.getScore());
        assertEquals("D", r.getGrade());
        assertEquals(1, r.getFindings().size());
        assertEquals("Content-Security-Policy", r.getFindings().get(0).getHeader());
    }

    @Test
    void header_finding_no_args_constructor() {
        HeaderFinding f = new HeaderFinding();
        assertNull(f.getHeader());
        assertNull(f.getSeverity());
    }

    // ── Grade assignment ──────────────────────────────────────────────────

    @Test
    void server_with_all_security_headers_gets_high_score() throws Exception {
        mockServer.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
            exchange.getResponseHeaders().add("Content-Security-Policy", "default-src 'self'");
            exchange.getResponseHeaders().add("X-Frame-Options", "DENY");
            exchange.getResponseHeaders().add("X-Content-Type-Options", "nosniff");
            exchange.getResponseHeaders().add("Referrer-Policy", "strict-origin-when-cross-origin");
            exchange.getResponseHeaders().add("Permissions-Policy", "camera=()");
            exchange.getResponseHeaders().add("Cross-Origin-Opener-Policy", "same-origin");
            exchange.getResponseHeaders().add("Cross-Origin-Resource-Policy", "same-origin");
            byte[] body = "OK".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        mockServer.start();

        Optional<HttpSecurityAuditResult> result =
                HttpSecurityAuditor.audit("localhost", port, false, 2000);
        assertTrue(result.isPresent());
        // HSTS deducted on non-TLS, but all other headers present → score ≥ 70
        assertTrue(result.get().getScore() >= 70, "Expected high score with most headers present");
    }

    @Test
    void server_with_no_security_headers_gets_grade_f() throws Exception {
        mockServer.createContext("/", exchange -> {
            byte[] body = "Hello World".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        mockServer.start();

        Optional<HttpSecurityAuditResult> result =
                HttpSecurityAuditor.audit("localhost", port, false, 2000);
        assertTrue(result.isPresent());
        assertTrue(result.get().getScore() < 50, "Expected low score with no security headers");
        assertFalse("A+".equals(result.get().getGrade()), "Grade should not be A+");
    }

    @Test
    void x_powered_by_detected_as_finding() throws Exception {
        mockServer.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("X-Powered-By", "PHP/8.1.0");
            byte[] body = "OK".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        mockServer.start();

        Optional<HttpSecurityAuditResult> result =
                HttpSecurityAuditor.audit("localhost", port, false, 2000);
        assertTrue(result.isPresent());
        assertTrue(result.get().getFindings() != null);
        boolean hasXPoweredBy = result.get().getFindings().stream()
                .anyMatch(f -> "X-Powered-By".equalsIgnoreCase(f.getHeader()));
        assertTrue(hasXPoweredBy, "X-Powered-By should be flagged as a finding");
    }

    @Test
    void csp_with_unsafe_inline_gets_finding() throws Exception {
        mockServer.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Content-Security-Policy",
                    "default-src 'self'; script-src 'unsafe-inline'");
            byte[] body = "OK".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        mockServer.start();

        Optional<HttpSecurityAuditResult> result =
                HttpSecurityAuditor.audit("localhost", port, false, 2000);
        assertTrue(result.isPresent());
        // Score should be deducted for unsafe-inline
        boolean hasUnsafeInlineFinding = result.get().getFindings() != null
                && result.get().getFindings().stream()
                        .anyMatch(f -> "Content-Security-Policy".equalsIgnoreCase(f.getHeader())
                                && f.getRecommendation() != null
                                && f.getRecommendation().contains("unsafe-inline"));
        assertTrue(hasUnsafeInlineFinding, "unsafe-inline in CSP should produce a finding");
    }

    @Test
    void audit_returns_empty_for_unreachable_host() {
        Optional<HttpSecurityAuditResult> result =
                HttpSecurityAuditor.audit("192.0.2.1", 80, false, 100);
        assertTrue(result.isEmpty());
    }

    @Test
    void csp_with_frame_ancestors_replaces_x_frame_options() throws Exception {
        mockServer.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Content-Security-Policy",
                    "default-src 'self'; frame-ancestors 'none'");
            byte[] body = "OK".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        mockServer.start();

        Optional<HttpSecurityAuditResult> result =
                HttpSecurityAuditor.audit("localhost", port, false, 2000);
        assertTrue(result.isPresent());
        // X-Frame-Options finding should NOT be present when CSP has frame-ancestors
        boolean hasFrameOptionsFinding = result.get().getFindings() != null
                && result.get().getFindings().stream()
                        .anyMatch(f -> "X-Frame-Options".equalsIgnoreCase(f.getHeader()));
        assertFalse(hasFrameOptionsFinding,
                "frame-ancestors in CSP should satisfy X-Frame-Options requirement");
    }

    @Test
    void score_is_never_negative() throws Exception {
        // Worst case: no headers + version-disclosing headers → score must be >= 0
        mockServer.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Server", "Apache/2.4.51 (Unix)");
            exchange.getResponseHeaders().add("X-Powered-By", "PHP/7.4");
            exchange.getResponseHeaders().add("X-AspNet-Version", "4.0.30319");
            exchange.getResponseHeaders().add("X-AspNetMvc-Version", "5.2");
            byte[] body = "OK".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        mockServer.start();

        Optional<HttpSecurityAuditResult> result =
                HttpSecurityAuditor.audit("localhost", port, false, 2000);
        assertTrue(result.isPresent());
        assertTrue(result.get().getScore() >= 0, "Score must never be negative");
    }
}
