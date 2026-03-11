package com.portscanner.report;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class HtmlExporterTest {

    @TempDir
    Path tempDir;

    private final HtmlExporter exporter = new HtmlExporter();

    private ScanReport report(List<ScanResult> open, List<ScanResult> filtered) {
        return ScanReport.builder()
                .host("example.com").resolvedIp("93.184.216.34")
                .scannedAt(LocalDateTime.now())
                .durationMs(1000).totalScanned(100)
                .openCount(open != null ? open.size() : 0)
                .filteredCount(filtered != null ? filtered.size() : 0)
                .openPorts(open).filteredPorts(filtered)
                .build();
    }

    private String export(ScanReport r) throws IOException {
        Path out = tempDir.resolve("scan.html");
        exporter.export(r, out);
        return Files.readString(out);
    }

    @Test
    void output_is_valid_html_document() throws IOException {
        String html = export(report(List.of(), List.of()));
        assertTrue(html.contains("<!DOCTYPE html>"));
        assertTrue(html.contains("<html"));
        assertTrue(html.contains("</html>"));
    }

    @Test
    void title_contains_host_name() throws IOException {
        String html = export(report(List.of(), List.of()));
        assertTrue(html.contains("Port Scan Report - example.com"));
    }

    @Test
    void html_special_chars_in_banner_are_escaped() throws IOException {
        ScanResult r = ScanResult.builder()
                .port(80).status(PortStatus.OPEN).serviceName("HTTP").responseTimeMs(5)
                .banner("<script>alert('xss')</script>").build();
        String html = export(report(List.of(r), List.of()));
        assertFalse(html.contains("<script>alert"), "Unescaped <script> tag found in output");
        assertTrue(html.contains("&lt;script&gt;"));
    }

    @Test
    void ampersand_in_host_is_escaped() throws IOException {
        ScanReport r = ScanReport.builder()
                .host("foo&bar").resolvedIp("1.2.3.4")
                .scannedAt(LocalDateTime.now()).durationMs(0)
                .totalScanned(0).openCount(0).filteredCount(0)
                .openPorts(List.of()).filteredPorts(List.of()).build();
        String html = export(r);
        assertTrue(html.contains("foo&amp;bar"));
        assertFalse(html.contains("foo&bar<"), "Unescaped & before tag char found");
    }

    @Test
    void double_quote_in_banner_is_escaped() throws IOException {
        ScanResult r = ScanResult.builder()
                .port(80).status(PortStatus.OPEN).serviceName("HTTP").responseTimeMs(5)
                .banner("Server: \"nginx\"").build();
        String html = export(report(List.of(r), List.of()));
        assertTrue(html.contains("&quot;nginx&quot;"));
    }

    @Test
    void shows_no_open_ports_message_when_empty() throws IOException {
        String html = export(report(List.of(), List.of()));
        assertTrue(html.contains("No open ports found."));
    }

    @Test
    void lists_open_port_in_table() throws IOException {
        ScanResult r = ScanResult.builder()
                .port(443).status(PortStatus.OPEN).serviceName("HTTPS").responseTimeMs(9).build();
        String html = export(report(List.of(r), List.of()));
        assertTrue(html.contains("443"));
        assertTrue(html.contains("HTTPS"));
    }

    @Test
    void cves_are_displayed_when_present() throws IOException {
        ScanResult r = ScanResult.builder()
                .port(80).status(PortStatus.OPEN).serviceName("HTTP").responseTimeMs(5)
                .cves(List.of("CVE-2024-1234", "CVE-2024-5678")).build();
        String html = export(report(List.of(r), List.of()));
        assertTrue(html.contains("CVE-2024-1234"));
        assertTrue(html.contains("CVE-2024-5678"));
    }

    @Test
    void filtered_ports_section_is_present() throws IOException {
        ScanResult r = ScanResult.builder().port(8080).status(PortStatus.FILTERED).build();
        String html = export(report(List.of(), List.of(r)));
        assertTrue(html.contains("8080"));
        assertTrue(html.contains("FILTERED"));
    }
}
