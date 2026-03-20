package com.portscanner.nuclei;

import com.portscanner.model.NucleiResult;
import com.portscanner.model.ScanResult;
import com.portscanner.nuclei.matcher.RegexMatcher;
import com.portscanner.nuclei.matcher.StatusMatcher;
import com.portscanner.nuclei.matcher.WordMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.net.URI;
import java.net.http.*;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Executes HTTP-type Nuclei templates against an open port and returns match results.
 */
public class NucleiRunner {

    private static final Logger log = LoggerFactory.getLogger(NucleiRunner.class);
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final HttpClient http;
    private final RegexMatcher regex = new RegexMatcher();
    private final WordMatcher word = new WordMatcher();
    private final StatusMatcher status = new StatusMatcher();

    public NucleiRunner() {
        this.http = buildTrustAllClient();
    }

    /**
     * Run all provided templates against the given open port result.
     *
     * @param host     target hostname or IP
     * @param result   open port result
     * @param templates list of loaded templates to run
     * @return list of matched NucleiResult entries (empty if none matched)
     */
    public List<NucleiResult> run(String host, ScanResult result, List<NucleiTemplate> templates) {
        List<NucleiResult> findings = new ArrayList<>();
        String protocol = result.getPort() == 443 || result.getPort() == 8443 ? "https" : "http";
        String baseUrl = protocol + "://" + host + ":" + result.getPort();

        for (NucleiTemplate template : templates) {
            if (template.getHttp() == null) continue;
            try {
                NucleiResult finding = executeTemplate(template, baseUrl);
                if (finding != null) findings.add(finding);
            } catch (Exception e) {
                log.debug("Template {} failed on port {}: {}", template.getId(), result.getPort(), e.getMessage());
            }
        }
        return findings;
    }

    private NucleiResult executeTemplate(NucleiTemplate template, String baseUrl) throws Exception {
        for (NucleiTemplate.HttpRequest req : template.getHttp()) {
            if (req.getPath() == null || req.getPath().isEmpty()) continue;
            String path = req.getPath().get(0).replace("{{BaseURL}}", baseUrl);
            String method = req.getMethod() != null ? req.getMethod().toUpperCase() : "GET";

            HttpRequest httpReq = HttpRequest.newBuilder()
                    .uri(URI.create(path))
                    .method(method, HttpRequest.BodyPublishers.noBody())
                    .timeout(TIMEOUT)
                    .build();

            HttpResponse<String> response;
            try {
                response = http.send(httpReq, HttpResponse.BodyHandlers.ofString());
            } catch (Exception e) {
                return null; // port not HTTP or unreachable
            }

            boolean allMatchersPass = evaluateMatchers(req, response);
            if (allMatchersPass) {
                return NucleiResult.builder()
                        .templateId(template.getId())
                        .name(template.getInfo() != null ? template.getInfo().getName() : template.getId())
                        .severity(template.getInfo() != null ? template.getInfo().getSeverity() : "info")
                        .matched(true)
                        .matchedAt(path)
                        .build();
            }
        }
        return null;
    }

    private boolean evaluateMatchers(NucleiTemplate.HttpRequest req, HttpResponse<String> response) {
        if (req.getMatchers() == null || req.getMatchers().isEmpty()) return true;
        boolean isAnd = "and".equalsIgnoreCase(req.getMatchersCondition());
        String body = response.body() != null ? response.body() : "";
        int code = response.statusCode();

        for (NucleiTemplate.Matcher m : req.getMatchers()) {
            boolean matched = switch (m.getType() != null ? m.getType() : "") {
                case "regex"  -> regex.matches(m, body, code);
                case "word"   -> word.matches(m, body);
                case "status" -> status.matches(m, code);
                default -> false;
            };
            if (isAnd && !matched) return false;
            if (!isAnd && matched) return true;
        }
        return isAnd; // all passed (and) or none passed (or)
    }

    /** Trust-all SSL client — necessary for scanning self-signed cert targets. */
    private static HttpClient buildTrustAllClient() {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, null);
            return HttpClient.newBuilder()
                    .sslContext(ctx)
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .connectTimeout(TIMEOUT)
                    .build();
        } catch (Exception e) {
            return HttpClient.newHttpClient();
        }
    }
}
