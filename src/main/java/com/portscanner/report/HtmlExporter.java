package com.portscanner.report;

import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.List;

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
            w.println("</style></head><body>");

            w.println("<h1>Port Scan Report</h1>");
            w.println("<div class=\"meta\">");
            w.printf("<p><span>Host:</span> %s &nbsp;&nbsp; <span>IP:</span> %s</p>%n", esc(report.getHost()), esc(report.getResolvedIp()));
            String scannedAt = report.getScannedAt() != null ? report.getScannedAt().format(FMT) : "N/A";
            w.printf("<p><span>Scanned:</span> %s &nbsp;&nbsp; <span>Duration:</span> %.2fs</p>%n", scannedAt, report.getDurationMs() / 1000.0);
            w.printf("<p><span>Ports Scanned:</span> %d &nbsp;&nbsp; <span class=\"open\">Open: %d</span> &nbsp;&nbsp; <span class=\"filtered\">Filtered: %d</span></p>%n",
                    report.getTotalScanned(), report.getOpenCount(), report.getFilteredCount());
            w.println("</div>");

            w.println("<h2 class=\"open\">Open Ports</h2>");
            List<ScanResult> open = report.getOpenPorts();
            if (open == null || open.isEmpty()) {
                w.println("<p>No open ports found.</p>");
            } else {
                w.println("<table><tr><th>Port</th><th>Service</th><th>Response</th><th>Banner / CVEs</th></tr>");
                for (ScanResult r : open) {
                    String bannerCell = esc(r.getBanner() != null ? r.getBanner() : "-");
                    if (r.getCves() != null && !r.getCves().isEmpty()) {
                        bannerCell += "<br><span class=\"cve\">CVEs: " + esc(String.join(", ", r.getCves())) + "</span>";
                    }
                    w.printf("<tr><td><span class=\"badge-open\">%d</span></td><td>%s</td><td>%dms</td><td>%s</td></tr>%n",
                            r.getPort(),
                            esc(r.getServiceName() != null ? r.getServiceName() : "Unknown"),
                            r.getResponseTimeMs(),
                            bannerCell);
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

            w.println("</body></html>");
        }
    }

    private String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
