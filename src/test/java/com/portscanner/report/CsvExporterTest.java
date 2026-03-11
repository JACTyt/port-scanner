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

class CsvExporterTest {

    @TempDir
    Path tempDir;

    private final CsvExporter exporter = new CsvExporter();

    private ScanReport report(List<ScanResult> open, List<ScanResult> filtered) {
        return ScanReport.builder()
                .host("localhost").resolvedIp("127.0.0.1")
                .scannedAt(LocalDateTime.now()).durationMs(100)
                .totalScanned(1024)
                .openCount(open != null ? open.size() : 0)
                .filteredCount(filtered != null ? filtered.size() : 0)
                .openPorts(open).filteredPorts(filtered)
                .build();
    }

    private List<String> exportAndRead(ScanReport report) throws IOException {
        Path out = tempDir.resolve("scan.csv");
        exporter.export(report, out);
        return Files.readAllLines(out);
    }

    @Test
    void first_line_is_header() throws IOException {
        List<String> lines = exportAndRead(report(List.of(), List.of()));
        assertEquals("PORT,STATUS,SERVICE,RESPONSE_MS,BANNER", lines.get(0));
    }

    @Test
    void exports_open_port_row() throws IOException {
        ScanResult r = ScanResult.builder()
                .port(80).status(PortStatus.OPEN).serviceName("HTTP").responseTimeMs(12).banner("Apache").build();
        List<String> lines = exportAndRead(report(List.of(r), List.of()));
        assertEquals(2, lines.size());
        assertTrue(lines.get(1).startsWith("80,OPEN,HTTP,12,Apache"));
    }

    @Test
    void exports_filtered_port_row() throws IOException {
        ScanResult r = ScanResult.builder().port(443).status(PortStatus.FILTERED).build();
        List<String> lines = exportAndRead(report(List.of(), List.of(r)));
        assertEquals(2, lines.size());
        assertTrue(lines.get(1).startsWith("443,FILTERED,,0,"));
    }

    @Test
    void null_banner_becomes_empty_string() throws IOException {
        ScanResult r = ScanResult.builder()
                .port(22).status(PortStatus.OPEN).serviceName("SSH").responseTimeMs(5).build();
        List<String> lines = exportAndRead(report(List.of(r), List.of()));
        // Last field (banner) should be empty
        assertTrue(lines.get(1).endsWith(","));
    }

    @Test
    void banner_with_comma_is_quoted() throws IOException {
        ScanResult r = ScanResult.builder()
                .port(80).status(PortStatus.OPEN).serviceName("HTTP").responseTimeMs(5)
                .banner("Server: Apache, v2.4").build();
        List<String> lines = exportAndRead(report(List.of(r), List.of()));
        assertTrue(lines.get(1).contains("\"Server: Apache, v2.4\""));
    }

    @Test
    void banner_with_double_quotes_is_escaped() throws IOException {
        ScanResult r = ScanResult.builder()
                .port(80).status(PortStatus.OPEN).serviceName("HTTP").responseTimeMs(5)
                .banner("say \"hello\"").build();
        List<String> lines = exportAndRead(report(List.of(r), List.of()));
        assertTrue(lines.get(1).contains("\"say \"\"hello\"\"\""));
    }

    @Test
    void both_open_and_filtered_ports_are_exported() throws IOException {
        ScanResult open = ScanResult.builder().port(80).status(PortStatus.OPEN).serviceName("HTTP").responseTimeMs(5).build();
        ScanResult filtered = ScanResult.builder().port(8080).status(PortStatus.FILTERED).build();
        List<String> lines = exportAndRead(report(List.of(open), List.of(filtered)));
        assertEquals(3, lines.size()); // header + 2 data rows
    }

    @Test
    void empty_report_produces_only_header() throws IOException {
        List<String> lines = exportAndRead(report(List.of(), List.of()));
        assertEquals(1, lines.size());
    }
}
