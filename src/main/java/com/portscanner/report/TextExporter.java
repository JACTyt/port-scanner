package com.portscanner.report;

import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.List;

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
            w.println(DASH);

            w.println("OPEN PORTS:");
            List<ScanResult> open = report.getOpenPorts();
            if (open == null || open.isEmpty()) {
                w.println("(none)");
            } else {
                w.printf("%-8s %-10s %-16s %-12s %s%n", "PORT", "STATE", "SERVICE", "RESPONSE", "BANNER");
                for (ScanResult r : open) {
                    w.printf("%-8d %-10s %-16s %-12s %s%n",
                            r.getPort(),
                            r.getStatus(),
                            nvl(r.getServiceName()),
                            r.getResponseTimeMs() + "ms",
                            nvl(r.getBanner()));
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

            w.println(SEP);
        }
    }

    private String nvl(String value) {
        return value != null ? value : "-";
    }
}
