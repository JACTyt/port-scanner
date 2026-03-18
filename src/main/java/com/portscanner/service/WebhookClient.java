package com.portscanner.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

/**
 * Posts scan results to a webhook URL on scan completion.
 *
 * <p>Slack and Discord URLs are auto-detected and sent as Slack-compatible
 * attachment blocks. All other URLs receive the full {@link ScanReport} as JSON.
 */
public class WebhookClient {

    private static final Logger log = LoggerFactory.getLogger(WebhookClient.class);
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final HttpClient http;
    private final ObjectMapper mapper;

    public WebhookClient() {
        this.http = HttpClient.newBuilder()
                .connectTimeout(TIMEOUT)
                .build();
        this.mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    /**
     * Send a webhook notification for a completed scan.
     *
     * @param report the completed scan report
     * @param url    the destination webhook URL
     */
    public void send(ScanReport report, String url) {
        try {
            String body = isSlackOrDiscord(url)
                    ? buildSlackPayload(report)
                    : mapper.writeValueAsString(report);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(TIMEOUT)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .build();

            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() >= 200 && resp.statusCode() < 300) {
                log.info("Webhook delivered to {} (HTTP {})", url, resp.statusCode());
            } else {
                log.warn("Webhook returned HTTP {} from {}: {}", resp.statusCode(), url, resp.body());
            }
        } catch (Exception e) {
            log.error("Failed to deliver webhook to {}: {}", url, e.getMessage());
        }
    }

    // ── Payload builders ──────────────────────────────────────────────────────

    /**
     * Builds a Slack-compatible Block Kit attachment payload.
     * Discord also accepts this format when posted to its webhook URLs.
     */
    private static String buildSlackPayload(ScanReport report) {
        StringBuilder ports = new StringBuilder();
        List<ScanResult> open = report.getOpenPorts();
        if (open != null && !open.isEmpty()) {
            int limit = Math.min(open.size(), 20);
            for (int i = 0; i < limit; i++) {
                ScanResult r = open.get(i);
                ports.append(String.format("• *%d* — %s",
                        r.getPort(),
                        r.getServiceName() != null ? r.getServiceName() : "Unknown"));
                if (r.getBanner() != null && !r.getBanner().isBlank()) {
                    ports.append("  `").append(truncate(r.getBanner(), 60)).append("`");
                }
                ports.append("\\n");
            }
            if (open.size() > 20) {
                ports.append(String.format("… and %d more", open.size() - 20));
            }
        } else {
            ports.append("_No open ports found_");
        }

        String color = report.getOpenCount() > 0 ? "#36a64f" : "#cccccc";
        String title = String.format("Port scan complete — %s (%s)",
                report.getHost(),
                report.getResolvedIp() != null ? report.getResolvedIp() : "?");
        String summary = String.format("%d open  •  %d filtered  •  %d scanned  •  %.2fs",
                report.getOpenCount(),
                report.getFilteredCount(),
                report.getTotalScanned(),
                report.getDurationMs() / 1000.0);

        return String.format("""
                {
                  "attachments": [{
                    "color": "%s",
                    "title": "%s",
                    "text": "%s",
                    "fields": [{
                      "title": "Open Ports",
                      "value": "%s",
                      "short": false
                    }],
                    "footer": "port-scanner",
                    "ts": %d
                  }]
                }""",
                color, title, summary, ports,
                report.getScannedAt() != null
                        ? report.getScannedAt().toEpochSecond(java.time.ZoneOffset.UTC) : 0);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static boolean isSlackOrDiscord(String url) {
        return url != null && (url.contains("slack.com") || url.contains("discord.com"));
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
