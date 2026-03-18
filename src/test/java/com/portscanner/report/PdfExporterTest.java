package com.portscanner.report;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PdfExporterTest {

    private final PdfExporter exporter = new PdfExporter();

    @Test
    void createsNonEmptyPdfFile(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("report.pdf");
        exporter.export(report(), out);
        assertTrue(Files.exists(out), "PDF file should be created");
        assertTrue(Files.size(out) > 1024, "PDF file should be non-trivial in size");
    }

    @Test
    void pdfStartsWithPdfMagicBytes(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("magic.pdf");
        exporter.export(report(), out);
        byte[] header = Files.readAllBytes(out);
        // PDF files start with %PDF
        assertEquals('%', header[0]);
        assertEquals('P', header[1]);
        assertEquals('D', header[2]);
        assertEquals('F', header[3]);
    }

    @Test
    void worksWithEmptyOpenPortsList(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("empty.pdf");
        ScanReport r = ScanReport.builder()
                .host("test").scannedAt(LocalDateTime.now())
                .openCount(0).filteredCount(0).totalScanned(100)
                .openPorts(List.of()).filteredPorts(List.of()).build();
        assertDoesNotThrow(() -> exporter.export(r, out));
        assertTrue(Files.exists(out));
    }

    @Test
    void worksWithMultipleOpenPorts(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("multi.pdf");
        List<ScanResult> ports = List.of(
                ScanResult.builder().port(22).status(PortStatus.OPEN).serviceName("SSH").build(),
                ScanResult.builder().port(80).status(PortStatus.OPEN).serviceName("HTTP").build(),
                ScanResult.builder().port(443).status(PortStatus.OPEN).serviceName("HTTPS").build()
        );
        ScanReport r = ScanReport.builder()
                .host("localhost").resolvedIp("127.0.0.1")
                .scannedAt(LocalDateTime.now()).durationMs(200)
                .totalScanned(1024).openCount(3).filteredCount(0)
                .openPorts(ports).filteredPorts(List.of()).build();
        assertDoesNotThrow(() -> exporter.export(r, out));
        assertTrue(Files.size(out) > 1024);
    }

    // ── Helper ─────────────────────────────────────────────────────────────────

    private static ScanReport report() {
        return ScanReport.builder()
                .host("localhost").resolvedIp("127.0.0.1")
                .scannedAt(LocalDateTime.now()).durationMs(150)
                .totalScanned(1024).openCount(1).filteredCount(0)
                .openPorts(List.of(
                        ScanResult.builder().port(80).status(PortStatus.OPEN)
                                .serviceName("HTTP").responseTimeMs(10).build()))
                .filteredPorts(List.of()).build();
    }
}
