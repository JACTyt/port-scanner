package com.portscanner.report;

import com.portscanner.model.AsnInfo;
import com.portscanner.model.GeoLocation;
import com.portscanner.model.HttpInfo;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import com.portscanner.model.ThreatInfo;
import com.portscanner.model.TlsInfo;
import com.portscanner.model.TracerouteHop;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class HtmlExporter implements ReportExporter {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Override
    public void export(ScanReport report, Path outputPath) throws IOException {
        try (PrintWriter w = new PrintWriter(outputPath.toFile(), StandardCharsets.UTF_8)) {
            w.println("<!DOCTYPE html>");
            w.println("<html lang=\"en\">");
            w.println("<head><meta charset=\"UTF-8\">");
            w.println("<title>Port Scan Report - " + esc(report.getHost()) + "</title>");
            w.println("<style>");
            w.println("body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:20px;margin:0}");
            w.println("h1{color:#00d4ff;border-bottom:2px solid #00d4ff;padding-bottom:8px}");
            w.println("h2{margin-top:24px}");
            w.println(".meta{background:#16213e;padding:15px;border-radius:8px;margin-bottom:20px}");
            w.println(".meta p{margin:4px 0} .meta span{color:#00d4ff;font-weight:bold}");
            w.println("table{width:100%;border-collapse:collapse;margin-bottom:20px}");
            w.println("th{background:#0f3460;color:#00d4ff;padding:10px;text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:1px}");
            w.println("td{padding:8px 10px;border-bottom:1px solid #2a2a4a;font-size:13px}");
            w.println("tr:hover{background:#1e1e3f}");
            w.println(".open{color:#00ff88} .filtered{color:#ffaa00}");
            w.println(".badge-open{background:#00ff8822;color:#00ff88;padding:2px 8px;border-radius:4px;font-weight:bold}");
            w.println(".badge-filtered{background:#ffaa0022;color:#ffaa00;padding:2px 8px;border-radius:4px}");
            w.println(".cve{color:#ff6b6b;font-size:11px}");
            w.println(".nuclei{color:#cc88ff;font-size:11px;margin-top:4px}");
            w.println(".badge-nuclei{background:#44004422;color:#cc88ff;padding:2px 6px;border-radius:4px;font-size:10px}");
            w.println(".tls{color:#88ccff;font-size:11px;margin-top:4px}");
            w.println(".http{color:#aaffaa;font-size:11px;margin-top:4px}");
            w.println(".warn{color:#ff9944;font-size:11px}");
            w.println(".threat{background:#3d1a1a;border:1px solid #ff4444;padding:10px;border-radius:6px;margin-bottom:16px;color:#ff8888}");
            w.println("</style></head><body>");

            w.println("<h1>Port Scan Report</h1>");
            w.println("<div class=\"meta\">");
            w.printf("<p><span>Host:</span> %s &nbsp;&nbsp; <span>IP:</span> %s</p>%n", esc(report.getHost()), esc(report.getResolvedIp()));
            String scannedAt = report.getScannedAt() != null ? report.getScannedAt().format(FMT) : "N/A";
            w.printf("<p><span>Scanned:</span> %s &nbsp;&nbsp; <span>Duration:</span> %.2fs</p>%n", scannedAt, report.getDurationMs() / 1000.0);
            w.printf("<p><span>Ports Scanned:</span> %d &nbsp;&nbsp; <span class=\"open\">Open: %d</span> &nbsp;&nbsp; <span class=\"filtered\">Filtered: %d</span></p>%n",
                    report.getTotalScanned(), report.getOpenCount(), report.getFilteredCount());

            GeoLocation geo = report.getGeoLocation();
            if (geo != null) {
                String loc = List.of(nvl2(geo.getCity()), nvl2(geo.getRegion()), nvl2(geo.getCountry()))
                        .stream().filter(s -> !s.isEmpty()).collect(Collectors.joining(", "));
                w.printf("<p><span>Location:</span> %s &nbsp;&nbsp; <span>ISP:</span> %s &nbsp;&nbsp; <span>TZ:</span> %s</p>%n",
                        esc(loc), esc(nvl(geo.getOrg())), esc(nvl(geo.getTimezone())));
            }

            AsnInfo asn = report.getAsnInfo();
            if (asn != null) {
                w.printf("<p><span>ASN:</span> %s %s | %s | %s</p>%n",
                        esc(nvl(asn.getAsn())), esc(nvl(asn.getName())), esc(nvl(asn.getPrefix())), esc(nvl(asn.getCountry())));
            }
            w.println("</div>");

            // Threat warning
            ThreatInfo threat = report.getThreatInfo();
            if (threat != null) {
                if (threat.getAbuseConfidenceScore() > 25 || threat.getGreynoiseClassification() != null) {
                    w.println("<div class=\"threat\">");
                    if (threat.getAbuseConfidenceScore() > 0) {
                        w.printf("<b>AbuseIPDB:</b> Score %d/100 (%d reports) &mdash; %s<br/>%n",
                                threat.getAbuseConfidenceScore(), threat.getAbuseReportCount(),
                                threat.getAbuseConfidenceScore() > 25 ? "HIGH RISK" : "LOW RISK");
                    }
                    if (threat.getGreynoiseClassification() != null) {
                        String scannerInfo = threat.isGreynoiseIsScanner()
                                ? " (Scanner: " + esc(nvl(threat.getIsp())) + ")" : "";
                        w.printf("<b>GreyNoise:</b> %s%s<br/>%n",
                                esc(threat.getGreynoiseClassification().toUpperCase()), scannerInfo);
                    }
                    w.println("</div>");
                }
            }

            w.println("<h2 class=\"open\">Open Ports</h2>");
            List<ScanResult> open = report.getOpenPorts();
            if (open == null || open.isEmpty()) {
                w.println("<p>No open ports found.</p>");
            } else {
                w.println("<table><tr><th>Port</th><th>Service</th><th>Response</th><th>Banner / Details</th></tr>");
                for (ScanResult r : open) {
                    StringBuilder details = new StringBuilder();
                    details.append(esc(r.getBanner() != null ? r.getBanner() : "-"));
                    if (r.getCves() != null && !r.getCves().isEmpty()) {
                        String cveStr = r.getCves().stream().map(c -> c.getId()).collect(java.util.stream.Collectors.joining(", "));
                        details.append("<br><span class=\"cve\">CVEs: ").append(esc(cveStr)).append("</span>");
                    }
                    if (r.getNucleiFindings() != null && !r.getNucleiFindings().isEmpty()) {
                        details.append("<br><div class='nuclei'><b>Nuclei:</b>");
                        for (var f : r.getNucleiFindings()) {
                            details.append(" <span class='badge-nuclei'>")
                                   .append(esc(f.getTemplateId()))
                                   .append(" [").append(esc(f.getSeverity())).append("]</span>");
                        }
                        details.append("</div>");
                    }
                    if (r.getHostname() != null) {
                        details.append("<br><span class=\"tls\">rDNS: ").append(esc(r.getHostname())).append("</span>");
                    }
                    TlsInfo tls = r.getTlsInfo();
                    if (tls != null) {
                        details.append("<br><span class=\"tls\">TLS: ")
                                .append(esc(nvl(tls.getProtocol())))
                                .append(" | Expires: ").append(tls.getCertExpiry() != null ? tls.getCertExpiry() : "N/A")
                                .append(" | CN=").append(esc(extractCn(tls.getCertSubject())));
                        StringBuilder warns = new StringBuilder();
                        if (tls.isExpired()) warns.append(" [EXPIRED]");
                        if (tls.isExpiresSoon()) warns.append(" [EXPIRES SOON]");
                        if (tls.isDeprecatedProtocol()) warns.append(" [DEPRECATED]");
                        if (tls.isWeakCipher()) warns.append(" [WEAK CIPHER]");
                        if (tls.isSelfSigned()) warns.append(" [SELF-SIGNED]");
                        if (warns.length() > 0) {
                            details.append("<span class=\"warn\">").append(esc(warns.toString())).append("</span>");
                        }
                        details.append("</span>");
                    }
                    HttpInfo http = r.getHttpInfo();
                    if (http != null) {
                        details.append("<br><span class=\"http\">HTTP ").append(http.getStatusCode())
                                .append(" | Server: ").append(esc(nvl(http.getServerHeader())));
                        if (http.getSecurityHeaders() != null) {
                            List<String> missing = http.getSecurityHeaders().entrySet().stream()
                                    .filter(e -> !e.getValue()).map(Map.Entry::getKey).collect(Collectors.toList());
                            if (!missing.isEmpty()) {
                                details.append(" | <span class=\"warn\">Missing: ").append(esc(String.join(", ", missing))).append("</span>");
                            }
                        }
                        details.append("</span>");
                    }
                    w.printf("<tr><td><span class=\"badge-open\">%d</span></td><td>%s</td><td>%dms</td><td>%s</td></tr>%n",
                            r.getPort(),
                            esc(r.getServiceName() != null ? r.getServiceName() : "Unknown"),
                            r.getResponseTimeMs(),
                            details);
                }
                w.println("</table>");
            }

            w.println("<h2 class=\"filtered\">Filtered Ports</h2>");
            List<ScanResult> filtered = report.getFilteredPorts();
            if (filtered == null || filtered.isEmpty()) {
                w.println("<p>No filtered ports.</p>");
            } else {
                w.println("<table><tr><th>Port</th><th>Status</th></tr>");
                for (ScanResult r : filtered) {
                    w.printf("<tr><td>%d</td><td><span class=\"badge-filtered\">%s</span></td></tr>%n", r.getPort(), r.getStatus());
                }
                w.println("</table>");
            }

            // Traceroute section
            List<TracerouteHop> hops = report.getTracerouteHops();
            if (hops != null && !hops.isEmpty()) {
                w.println("<h2 style=\"color:#88ccff\">Traceroute</h2>");
                w.println("<table><tr><th>Hop</th><th>RTT</th><th>IP</th><th>Hostname</th></tr>");
                for (TracerouteHop hop : hops) {
                    if ("*".equals(hop.ip())) {
                        w.printf("<tr><td>%d</td><td>*</td><td>*</td><td>(timeout)</td></tr>%n", hop.hopNumber());
                    } else {
                        String rttStr = hop.rttMs() < 0 ? "*" : String.format("%.1fms", hop.rttMs());
                        String hostname = hop.hostname() != null && !hop.hostname().equals(hop.ip())
                                ? esc(hop.hostname()) : "-";
                        w.printf("<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>%n",
                                hop.hopNumber(), esc(rttStr), esc(hop.ip()), hostname);
                    }
                }
                w.println("</table>");
            }

            w.println("</body></html>");
        }
    }

    private String extractCn(String dn) {
        if (dn == null) return "-";
        for (String part : dn.split(",")) {
            String trimmed = part.trim();
            if (trimmed.startsWith("CN=")) return trimmed.substring(3);
        }
        return dn;
    }

    private String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private String nvl(String value) {
        return value != null ? value : "-";
    }

    private String nvl2(String value) {
        return value != null ? value : "";
    }
}
