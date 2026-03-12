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

public class TextExporter implements ReportExporter {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final String SEP = "============================================================";
    private static final String DASH = "------------------------------------------------------------";

    @Override
    public void export(ScanReport report, Path outputPath) throws IOException {
        try (PrintWriter w = new PrintWriter(outputPath.toFile(), StandardCharsets.UTF_8)) {
            w.println(SEP);
            w.println("PORT SCAN REPORT");
            w.println(SEP);
            w.printf("Host         : %s%n", report.getHost());
            w.printf("Resolved IP  : %s%n", report.getResolvedIp());
            w.printf("Scanned At   : %s%n", report.getScannedAt() != null ? report.getScannedAt().format(FORMATTER) : "N/A");
            w.printf("Duration     : %.2f seconds%n", report.getDurationMs() / 1000.0);
            w.printf("Ports Scanned: %d  |  Open: %d  |  Filtered: %d%n",
                    report.getTotalScanned(), report.getOpenCount(), report.getFilteredCount());

            // Geolocation block
            GeoLocation geo = report.getGeoLocation();
            if (geo != null) {
                String loc = List.of(nvl2(geo.getCity()), nvl2(geo.getRegion()), nvl2(geo.getCountry()))
                        .stream().filter(s -> !s.isEmpty()).collect(Collectors.joining(", "));
                w.printf("Location     : %s | ISP: %s | TZ: %s%n",
                        loc, nvl(geo.getOrg()), nvl(geo.getTimezone()));
            }

            // ASN block
            AsnInfo asn = report.getAsnInfo();
            if (asn != null) {
                w.printf("ASN          : %s %s | %s | %s%n",
                        nvl(asn.getAsn()), nvl(asn.getName()), nvl(asn.getPrefix()), nvl(asn.getCountry()));
            }

            // Threat info block
            ThreatInfo threat = report.getThreatInfo();
            if (threat != null) {
                if (threat.getAbuseConfidenceScore() > 0 || threat.getAbuseReportCount() > 0) {
                    String risk = threat.getAbuseConfidenceScore() > 25 ? "HIGH RISK" : "LOW RISK";
                    w.printf("!! THREAT    : AbuseIPDB score %d/100 (%d reports) -- %s%n",
                            threat.getAbuseConfidenceScore(), threat.getAbuseReportCount(), risk);
                }
                if (threat.getGreynoiseClassification() != null) {
                    String scannerInfo = threat.isGreynoiseIsScanner()
                            ? " (Scanner: " + nvl(threat.getIsp()) + ")" : "";
                    w.printf("GreyNoise    : %s%s%n",
                            threat.getGreynoiseClassification().toUpperCase(), scannerInfo);
                }
            }

            w.println(DASH);

            w.println("OPEN PORTS:");
            List<ScanResult> open = report.getOpenPorts();
            if (open == null || open.isEmpty()) {
                w.println("(none)");
            } else {
                w.printf("%-8s %-10s %-16s %-12s %s%n", "PORT", "STATE", "SERVICE", "RESPONSE", "BANNER");
                for (ScanResult r : open) {
                    String hostPart = r.getHostname() != null ? " (" + r.getHostname() + ")" : "";
                    w.printf("%-8d %-10s %-16s %-12s %s%s%n",
                            r.getPort(),
                            r.getStatus(),
                            nvl(r.getServiceName()),
                            r.getResponseTimeMs() + "ms",
                            nvl(r.getBanner()),
                            hostPart);
                    // TLS info sub-row
                    TlsInfo tls = r.getTlsInfo();
                    if (tls != null) {
                        StringBuilder tlsLine = new StringBuilder("  +-- TLS: ")
                                .append(nvl(tls.getProtocol()))
                                .append(" | Expires: ").append(tls.getCertExpiry() != null ? tls.getCertExpiry() : "N/A")
                                .append(" | CN=").append(extractCn(tls.getCertSubject()));
                        if (tls.isExpired()) tlsLine.append(" [EXPIRED]");
                        if (tls.isExpiresSoon()) tlsLine.append(" [EXPIRES SOON]");
                        if (tls.isDeprecatedProtocol()) tlsLine.append(" [DEPRECATED PROTOCOL]");
                        if (tls.isWeakCipher()) tlsLine.append(" [WEAK CIPHER]");
                        if (tls.isSelfSigned()) tlsLine.append(" [SELF-SIGNED]");
                        w.println(tlsLine);
                    }
                    // HTTP info sub-row
                    HttpInfo http = r.getHttpInfo();
                    if (http != null) {
                        StringBuilder httpLine = new StringBuilder("  +-- HTTP ")
                                .append(http.getStatusCode())
                                .append(" | Server: ").append(nvl(http.getServerHeader()));
                        // Missing security headers
                        if (http.getSecurityHeaders() != null) {
                            List<String> missing = http.getSecurityHeaders().entrySet().stream()
                                    .filter(e -> !e.getValue())
                                    .map(Map.Entry::getKey)
                                    .collect(Collectors.toList());
                            if (!missing.isEmpty()) {
                                httpLine.append(" | Missing: ").append(String.join(", ", missing));
                            }
                        }
                        w.println(httpLine);
                    }
                }
            }

            w.println(DASH);
            w.println("FILTERED PORTS:");
            List<ScanResult> filtered = report.getFilteredPorts();
            if (filtered == null || filtered.isEmpty()) {
                w.println("(none)");
            } else {
                w.printf("%-8s %-10s%n", "PORT", "STATE");
                for (ScanResult r : filtered) {
                    w.printf("%-8d %-10s%n", r.getPort(), r.getStatus());
                }
            }

            // Traceroute section
            List<TracerouteHop> hops = report.getTracerouteHops();
            if (hops != null && !hops.isEmpty()) {
                w.println(DASH);
                w.println("TRACEROUTE:");
                w.printf("%-6s %-10s %-18s %s%n", "HOP", "RTT", "IP", "HOSTNAME");
                for (TracerouteHop hop : hops) {
                    if ("*".equals(hop.ip())) {
                        w.printf("%-6d %-10s %-18s %s%n", hop.hopNumber(), "*", "*", "(timeout)");
                    } else {
                        String rttStr = hop.rttMs() < 0 ? "*" : String.format("%.1fms", hop.rttMs());
                        String hostname = hop.hostname() != null && !hop.hostname().equals(hop.ip())
                                ? hop.hostname() : "-";
                        w.printf("%-6d %-10s %-18s %s%n", hop.hopNumber(), rttStr, hop.ip(), hostname);
                    }
                }
            }

            w.println(SEP);
        }
    }

    private String extractCn(String dn) {
        if (dn == null) return "-";
        // Extract CN= value from DN
        for (String part : dn.split(",")) {
            String trimmed = part.trim();
            if (trimmed.startsWith("CN=")) {
                return trimmed.substring(3);
            }
        }
        return dn;
    }

    private String nvl(String value) {
        return value != null ? value : "-";
    }

    private String nvl2(String value) {
        return value != null ? value : "";
    }
}
