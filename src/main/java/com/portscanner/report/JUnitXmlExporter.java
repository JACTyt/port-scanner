package com.portscanner.report;

import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Exports a {@link ScanReport} as JUnit XML.
 *
 * <p>Each open port is a {@code <testcase>}. Ports listed in the
 * {@code failOnPorts} blocklist produce a {@code <failure>} element, which causes
 * Jenkins, GitLab CI, CircleCI, Azure DevOps, and GitHub Actions to show a red build status
 * without any custom parsing or SARIF support required.
 *
 * <p>When no {@code failOnPorts} are configured all test cases pass (green), making this
 * format useful for tracking open ports over time even without a policy gate.
 */
public class JUnitXmlExporter implements ReportExporter {

    private final List<Integer> failOnPorts;

    public JUnitXmlExporter() {
        this(List.of());
    }

    /**
     * @param failOnPorts port numbers that should produce {@code <failure>} elements
     */
    public JUnitXmlExporter(List<Integer> failOnPorts) {
        this.failOnPorts = failOnPorts != null ? failOnPorts : List.of();
    }

    @Override
    public void export(ScanReport report, Path outputPath) throws IOException {
        List<ScanResult> open = report.getOpenPorts() != null ? report.getOpenPorts() : List.of();
        String host = report.getHost() != null ? report.getHost() : "unknown";
        String timestamp = report.getScannedAt() != null
                ? report.getScannedAt().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
                : LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        long failures = open.stream().filter(r -> failOnPorts.contains(r.getPort())).count();

        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(outputPath, StandardCharsets.UTF_8))) {
            pw.println("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            pw.printf("<testsuite name=\"port-scanner\" hostname=\"%s\" tests=\"%d\""
                            + " failures=\"%d\" errors=\"0\" skipped=\"0\""
                            + " timestamp=\"%s\" time=\"%.3f\">%n",
                    esc(host), open.size(), failures,
                    esc(timestamp), report.getDurationMs() / 1000.0);

            for (ScanResult r : open) {
                String name = String.format("port-%d-%s", r.getPort(),
                        r.getServiceName() != null
                                ? r.getServiceName().replaceAll("[^A-Za-z0-9_.-]", "_")
                                : "unknown");

                pw.printf("  <testcase classname=\"%s\" name=\"%s\" time=\"%.3f\">%n",
                        esc(host), esc(name), r.getResponseTimeMs() / 1000.0);

                if (failOnPorts.contains(r.getPort())) {
                    String msg = String.format("Port %d (%s) is open — blocked by policy",
                            r.getPort(), r.getServiceName() != null ? r.getServiceName() : "unknown");
                    String body = buildFailureBody(r);
                    pw.printf("    <failure message=\"%s\">%s</failure>%n", esc(msg), esc(body));
                }

                pw.println("  </testcase>");
            }

            pw.println("</testsuite>");
        }
    }

    private static String buildFailureBody(ScanResult r) {
        StringBuilder sb = new StringBuilder();
        if (r.getBanner() != null) sb.append("Banner: ").append(r.getBanner()).append("\n");
        if (r.getVersion() != null) sb.append("Version: ").append(r.getVersion()).append("\n");
        if (r.getCves() != null && !r.getCves().isEmpty()) {
            sb.append("CVEs: ").append(String.join(", ", r.getCves())).append("\n");
        }
        return sb.toString().trim();
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }
}
