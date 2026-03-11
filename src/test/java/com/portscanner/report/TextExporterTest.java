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

class TextExporterTest {

    @TempDir
    Path tempDir;

    private final TextExporter exporter = new TextExporter();

    private ScanReport report(List<ScanResult> open, List<ScanResult> filtered) {
        return ScanReport.builder()
                .host("example.com").resolvedIp("93.184.216.34")
                .scannedAt(LocalDateTime.of(2025, 3, 11, 12, 0, 0))
                .durationMs(2500).totalScanned(100)
                .openCount(open != null ? open.size() : 0)
                .filteredCount(filtered != null ? filtered.size() : 0)
                .openPorts(open).filteredPorts(filtered)
                .build();
    }

    private String exportToString(ScanReport r) throws IOException {
        Path out = tempDir.resolve("scan.txt");
        exporter.export(r, out);
        return Files.readString(out);
    }

    @Test
    void contains_host_and_ip() throws IOException {
        String content = exportToString(report(List.of(), List.of()));
        assertTrue(content.contains("example.com"));
        assertTrue(content.contains("93.184.216.34"));
    }

    @Test
    void contains_scanned_at_timestamp() throws IOException {
        String content = exportToString(report(List.of(), List.of()));
        assertTrue(content.contains("2025-03-11 12:00:00"));
    }

    @Test
    void contains_open_port_count() throws IOException {
        ScanResult open = ScanResult.builder().port(80).status(PortStatus.OPEN).serviceName("HTTP").responseTimeMs(10).build();
        String content = exportToString(report(List.of(open), List.of()));
        assertTrue(content.contains("Open: 1"));
    }

    @Test
    void open_port_row_includes_service_and_banner() throws IOException {
        ScanResult r = ScanResult.builder()
                .port(443).status(PortStatus.OPEN).serviceName("HTTPS").responseTimeMs(8).banner("TLSv1.3").build();
        String content = exportToString(report(List.of(r), List.of()));
        assertTrue(content.contains("443"));
        assertTrue(content.contains("HTTPS"));
        assertTrue(content.contains("TLSv1.3"));
    }

    @Test
    void shows_none_when_no_open_ports() throws IOException {
        String content = exportToString(report(List.of(), List.of()));
        assertTrue(content.contains("(none)"));
    }

    @Test
    void filtered_ports_section_includes_port_number() throws IOException {
        ScanResult r = ScanResult.builder().port(22).status(PortStatus.FILTERED).build();
        String content = exportToString(report(List.of(), List.of(r)));
        assertTrue(content.contains("22"));
        assertTrue(content.contains("FILTERED"));
    }

    @Test
    void null_banner_rendered_as_dash() throws IOException {
        ScanResult r = ScanResult.builder().port(80).status(PortStatus.OPEN).serviceName("HTTP").responseTimeMs(5).build();
        String content = exportToString(report(List.of(r), List.of()));
        // The banner column should show "-"
        assertTrue(content.contains("-"));
    }

    @Test
    void report_contains_separator_lines() throws IOException {
        String content = exportToString(report(List.of(), List.of()));
        assertTrue(content.contains("============================================================"));
        assertTrue(content.contains("------------------------------------------------------------"));
    }
}
