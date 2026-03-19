package com.portscanner.report;

import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Exports a {@link ScanReport} as a GitHub-flavored Markdown document.
 * No external dependencies — pure string formatting.
 */
public class MarkdownExporter implements ReportExporter {

    private static final DateTimeFormatter DT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Override
    public void export(ScanReport report, Path outputPath) throws IOException {
        Files.writeString(outputPath, buildMarkdown(report), StandardCharsets.UTF_8);
    }

    private static String buildMarkdown(ScanReport report) {
        StringBuilder sb = new StringBuilder();

        // ── Title ─────────────────────────────────────────────────────────────
        sb.append("# Port Scan Report — ").append(report.getHost()).append("\n\n");

        // ── Metadata table ────────────────────────────────────────────────────
        sb.append("## Scan Info\n\n");
        sb.append("| Field | Value |\n");
        sb.append("|-------|-------|\n");
        sb.append("| **Host** | ").append(md(report.getHost())).append(" |\n");
        if (report.getResolvedIp() != null) {
            sb.append("| **Resolved IP** | `").append(report.getResolvedIp()).append("` |\n");
        }
        if (report.getScannedAt() != null) {
            sb.append("| **Scanned At** | ").append(report.getScannedAt().format(DT)).append(" |\n");
        }
        sb.append("| **Duration** | ").append(String.format("%.2fs", report.getDurationMs() / 1000.0)).append(" |\n");
        sb.append("| **Ports Scanned** | ").append(report.getTotalScanned()).append(" |\n");
        sb.append("| **Open** | ").append(report.getOpenCount()).append(" |\n");
        sb.append("| **Filtered** | ").append(report.getFilteredCount()).append(" |\n");

        if (report.getOsGuess() != null) {
            var os = report.getOsGuess();
            sb.append("| **OS Guess** | ").append(os.getOs())
              .append(" *(").append(os.getConfidence()).append(", ").append(os.getMethod()).append(")* |\n");
        }
        if (report.getGeoLocation() != null) {
            var g = report.getGeoLocation();
            sb.append("| **Location** | ")
              .append(nvl(g.getCity())).append(", ").append(nvl(g.getRegion()))
              .append(", ").append(nvl(g.getCountry())).append(" |\n");
        }
        if (report.getAsnInfo() != null) {
            var a = report.getAsnInfo();
            sb.append("| **ASN** | ").append(nvl(a.getAsn())).append(" ").append(nvl(a.getName())).append(" |\n");
        }
        sb.append("\n");

        // ── Threat info ───────────────────────────────────────────────────────
        if (report.getThreatInfo() != null) {
            var t = report.getThreatInfo();
            sb.append("## Threat Intelligence\n\n");
            if (t.getAbuseConfidenceScore() > 0) {
                sb.append("> **AbuseIPDB score:** ").append(t.getAbuseConfidenceScore())
                  .append("/100 (").append(t.getAbuseReportCount()).append(" reports)\n\n");
            }
            if (t.getGreynoiseClassification() != null) {
                sb.append("> **GreyNoise:** ").append(t.getGreynoiseClassification().toUpperCase()).append("\n\n");
            }
        }

        // ── Open ports table ──────────────────────────────────────────────────
        sb.append("## Open Ports\n\n");
        List<ScanResult> open = report.getOpenPorts();
        if (open == null || open.isEmpty()) {
            sb.append("*No open ports found.*\n\n");
        } else {
            sb.append("| Port | Service | Response | Banner / Version |\n");
            sb.append("|------|---------|----------|-----------------|\n");
            for (ScanResult r : open) {
                sb.append("| **").append(r.getPort()).append("** | ")
                  .append(nvl(r.getServiceName())).append(" | ")
                  .append(r.getResponseTimeMs()).append("ms | ");

                if (r.getVersion() != null) {
                    sb.append("`").append(md(r.getVersion())).append("`");
                } else if (r.getBanner() != null) {
                    sb.append("`").append(md(truncate(r.getBanner(), 80))).append("`");
                } else {
                    sb.append("—");
                }
                sb.append(" |\n");

                // TLS sub-row
                if (r.getTlsInfo() != null) {
                    var tls = r.getTlsInfo();
                    sb.append("| | | | 🔒 TLS: ").append(nvl(tls.getProtocol()))
                      .append(" · Expires: ").append(tls.getCertExpiry() != null ? tls.getCertExpiry().toString() : "N/A");
                    if (tls.isExpired())          sb.append(" ⚠️ **EXPIRED**");
                    if (tls.isExpiresSoon())      sb.append(" ⚠️ **EXPIRES SOON**");
                    if (tls.isDeprecatedProtocol()) sb.append(" ⚠️ **DEPRECATED PROTOCOL**");
                    sb.append(" |\n");
                }

                // CVEs sub-row
                if (r.getCves() != null && !r.getCves().isEmpty()) {
                    sb.append("| | | | ⚠️ CVEs: `")
                      .append(r.getCves().stream().map(c -> c.getId()).collect(java.util.stream.Collectors.joining("`, `"))).append("` |\n");
                }
            }
            sb.append("\n");
        }

        // ── Filtered ports ────────────────────────────────────────────────────
        if (report.getFilteredPorts() != null && !report.getFilteredPorts().isEmpty()) {
            sb.append("<details>\n<summary>Filtered ports (").append(report.getFilteredCount())
              .append(")</summary>\n\n");
            sb.append("| Port | Service |\n|------|--------|\n");
            for (ScanResult r : report.getFilteredPorts()) {
                sb.append("| ").append(r.getPort()).append(" | ").append(nvl(r.getServiceName())).append(" |\n");
            }
            sb.append("\n</details>\n\n");
        }

        // ── Subdomains ────────────────────────────────────────────────────────
        if (report.getSubdomains() != null && !report.getSubdomains().isEmpty()) {
            sb.append("## Discovered Subdomains\n\n");
            sb.append("| Subdomain | Addresses | CNAME |\n|-----------|-----------|-------|\n");
            for (var s : report.getSubdomains()) {
                String addrs = s.getAddresses() != null ? String.join(", ", s.getAddresses()) : "—";
                sb.append("| ").append(s.getSubdomain()).append(" | ").append(addrs)
                  .append(" | ").append(s.getCname() != null ? s.getCname() : "—").append(" |\n");
            }
            sb.append("\n");
        }

        // ── Traceroute ────────────────────────────────────────────────────────
        if (report.getTracerouteHops() != null && !report.getTracerouteHops().isEmpty()) {
            sb.append("## Traceroute\n\n");
            sb.append("| Hop | IP | Hostname | RTT |\n|----|-----|----------|-----|\n");
            for (var hop : report.getTracerouteHops()) {
                String rtt = "*".equals(hop.ip()) ? "*" :
                        (hop.rttMs() < 0 ? "*" : String.format("%.1f ms", hop.rttMs()));
                sb.append("| ").append(hop.hopNumber()).append(" | ")
                  .append(nvl(hop.ip())).append(" | ")
                  .append(hop.hostname() != null ? hop.hostname() : "—").append(" | ")
                  .append(rtt).append(" |\n");
            }
            sb.append("\n");
        }

        sb.append("---\n*Generated by port-scanner*\n");
        return sb.toString();
    }

    private static String nvl(String s) { return s != null ? s : "—"; }

    /** Escape pipe characters that would break Markdown tables. */
    private static String md(String s) { return s != null ? s.replace("|", "\\|").replace("`", "'") : ""; }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
