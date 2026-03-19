package com.portscanner.scanner;

import com.portscanner.model.HeaderFinding;
import com.portscanner.model.HttpSecurityAuditResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * HTTP security header auditor — fetches HTTP response headers and scores them
 * using the OWASP Secure Headers Project methodology (100-point scale).
 * Equivalent to the Mozilla Observatory scanner.
 */
public class HttpSecurityAuditor {

    private static final Logger log = LoggerFactory.getLogger(HttpSecurityAuditor.class);

    public static Optional<HttpSecurityAuditResult> audit(String host, int port, boolean useTls, int timeoutMs) {
        Map<String, String> headers = fetchHeaders(host, port, useTls, timeoutMs);
        if (headers == null) return Optional.empty();

        int score = 100;
        List<HeaderFinding> findings = new ArrayList<>();

        // ── HSTS (-20 if missing on HTTPS) ──────────────────────────────────
        if (useTls) {
            if (!headers.containsKey("strict-transport-security")) {
                score -= 20;
                findings.add(HeaderFinding.builder()
                        .header("Strict-Transport-Security")
                        .severity("HIGH")
                        .recommendation("Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")
                        .build());
            } else {
                String hsts = headers.get("strict-transport-security");
                if (!hsts.contains("includeSubDomains")) {
                    findings.add(HeaderFinding.builder()
                            .header("Strict-Transport-Security")
                            .value(hsts)
                            .severity("LOW")
                            .recommendation("Add includeSubDomains directive to HSTS to protect subdomains")
                            .build());
                }
            }
        }

        // ── CSP (-25 if missing) ─────────────────────────────────────────────
        if (!headers.containsKey("content-security-policy")) {
            score -= 25;
            findings.add(HeaderFinding.builder()
                    .header("Content-Security-Policy")
                    .severity("HIGH")
                    .recommendation("Add Content-Security-Policy to prevent XSS and data injection attacks. "
                            + "Start with: Content-Security-Policy: default-src 'self'")
                    .build());
        } else {
            String csp = headers.get("content-security-policy");
            if (csp.contains("unsafe-inline") || csp.contains("unsafe-eval")) {
                score -= 10;
                findings.add(HeaderFinding.builder()
                        .header("Content-Security-Policy")
                        .value(csp.length() > 100 ? csp.substring(0, 97) + "..." : csp)
                        .severity("MEDIUM")
                        .recommendation("CSP contains 'unsafe-inline' or 'unsafe-eval' — these directives "
                                + "significantly weaken XSS protection. Use nonces or hashes instead.")
                        .build());
            }
        }

        // ── X-Frame-Options (-20 unless CSP has frame-ancestors) ─────────────
        boolean hasFrameAncestors = headers.containsKey("content-security-policy")
                && headers.get("content-security-policy").contains("frame-ancestors");
        if (!hasFrameAncestors && !headers.containsKey("x-frame-options")) {
            score -= 20;
            findings.add(HeaderFinding.builder()
                    .header("X-Frame-Options")
                    .severity("MEDIUM")
                    .recommendation("Add: X-Frame-Options: DENY  (or use Content-Security-Policy: frame-ancestors 'none')")
                    .build());
        }

        // ── X-Content-Type-Options (-10 if missing) ──────────────────────────
        if (!headers.containsKey("x-content-type-options")) {
            score -= 10;
            findings.add(HeaderFinding.builder()
                    .header("X-Content-Type-Options")
                    .severity("LOW")
                    .recommendation("Add: X-Content-Type-Options: nosniff — prevents MIME-type sniffing attacks")
                    .build());
        }

        // ── Referrer-Policy (-10 if missing) ────────────────────────────────
        if (!headers.containsKey("referrer-policy")) {
            score -= 10;
            findings.add(HeaderFinding.builder()
                    .header("Referrer-Policy")
                    .severity("LOW")
                    .recommendation("Add: Referrer-Policy: strict-origin-when-cross-origin — "
                            + "prevents referrer leakage to third-party sites")
                    .build());
        }

        // ── Permissions-Policy (-5 if missing) ──────────────────────────────
        if (!headers.containsKey("permissions-policy") && !headers.containsKey("feature-policy")) {
            score -= 5;
            findings.add(HeaderFinding.builder()
                    .header("Permissions-Policy")
                    .severity("INFO")
                    .recommendation("Add Permissions-Policy to restrict access to browser APIs "
                            + "(camera, microphone, geolocation). Example: Permissions-Policy: camera=(), microphone=()")
                    .build());
        }

        // ── COOP (-5 if missing) ────────────────────────────────────────────
        if (!headers.containsKey("cross-origin-opener-policy")) {
            score -= 5;
            findings.add(HeaderFinding.builder()
                    .header("Cross-Origin-Opener-Policy")
                    .severity("INFO")
                    .recommendation("Add: Cross-Origin-Opener-Policy: same-origin — "
                            + "isolates the browsing context to prevent Spectre-style attacks")
                    .build());
        }

        // ── CORP (-5 if missing) ────────────────────────────────────────────
        if (!headers.containsKey("cross-origin-resource-policy")) {
            score -= 5;
            findings.add(HeaderFinding.builder()
                    .header("Cross-Origin-Resource-Policy")
                    .severity("INFO")
                    .recommendation("Add: Cross-Origin-Resource-Policy: same-origin — "
                            + "prevents other origins from loading your resources")
                    .build());
        }

        // ── Information disclosure checks (don't deduct score) ───────────────
        String serverHeader = headers.get("server");
        if (serverHeader != null && serverHeader.matches(".*[0-9].*")) {
            findings.add(HeaderFinding.builder()
                    .header("Server")
                    .value(serverHeader)
                    .severity("INFO")
                    .recommendation("Server header discloses software version. "
                            + "Configure the server to omit or mask version information.")
                    .build());
        }

        String xPoweredBy = headers.get("x-powered-by");
        if (xPoweredBy != null) {
            score -= 5;
            findings.add(HeaderFinding.builder()
                    .header("X-Powered-By")
                    .value(xPoweredBy)
                    .severity("LOW")
                    .recommendation("Remove X-Powered-By header — it discloses technology stack "
                            + "and version information to potential attackers.")
                    .build());
        }

        String aspNetVersion = headers.get("x-aspnet-version");
        if (aspNetVersion != null) {
            score -= 5;
            findings.add(HeaderFinding.builder()
                    .header("X-AspNet-Version")
                    .value(aspNetVersion)
                    .severity("LOW")
                    .recommendation("Remove X-AspNet-Version header — set <httpRuntime enableVersionHeader=\"false\"/> in web.config")
                    .build());
        }

        String xAspNetMvcVersion = headers.get("x-aspnetmvc-version");
        if (xAspNetMvcVersion != null) {
            findings.add(HeaderFinding.builder()
                    .header("X-AspNetMvc-Version")
                    .value(xAspNetMvcVersion)
                    .severity("LOW")
                    .recommendation("Remove X-AspNetMvc-Version header")
                    .build());
        }

        score = Math.max(0, score);
        String grade = scoreToGrade(score);

        return Optional.of(HttpSecurityAuditResult.builder()
                .score(score)
                .grade(grade)
                .findings(findings.isEmpty() ? null : findings)
                .build());
    }

    /** Fetches HTTP response headers using a raw socket (supports both HTTP and HTTPS). */
    private static Map<String, String> fetchHeaders(String host, int port, boolean useTls, int timeoutMs) {
        try {
            Socket socket;
            if (useTls) {
                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                Socket plain = new Socket();
                plain.connect(new InetSocketAddress(host, port), timeoutMs);
                socket = factory.createSocket(plain, host, port, true);
            } else {
                socket = new Socket();
                socket.connect(new InetSocketAddress(host, port), timeoutMs);
            }

            try (Socket s = socket) {
                s.setSoTimeout(timeoutMs);
                String request = "GET / HTTP/1.1\r\nHost: " + host + "\r\n"
                        + "User-Agent: Mozilla/5.0 (compatible; PortScanner)\r\n"
                        + "Connection: close\r\n\r\n";
                OutputStream out = s.getOutputStream();
                out.write(request.getBytes(StandardCharsets.UTF_8));
                out.flush();

                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));

                // Skip status line
                reader.readLine();

                // Read headers (stop at blank line)
                Map<String, String> headers = new LinkedHashMap<>();
                String line;
                while ((line = reader.readLine()) != null && !line.isEmpty()) {
                    int colon = line.indexOf(':');
                    if (colon > 0) {
                        String key = line.substring(0, colon).trim().toLowerCase();
                        String value = line.substring(colon + 1).trim();
                        headers.put(key, value);
                    }
                }
                return headers;
            }
        } catch (Exception e) {
            log.debug("HTTP security audit header fetch failed for {}:{} — {}", host, port, e.getMessage());
            return null;
        }
    }

    private static String scoreToGrade(int score) {
        if (score >= 95) return "A+";
        if (score >= 85) return "A";
        if (score >= 70) return "B";
        if (score >= 55) return "C";
        if (score >= 30) return "D";
        return "F";
    }
}
