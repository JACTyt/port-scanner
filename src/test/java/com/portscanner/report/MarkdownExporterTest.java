package com.portscanner.report;

import com.portscanner.model.OsGuess;
import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import com.portscanner.model.TlsInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MarkdownExporterTest {

    private final MarkdownExporter exporter = new MarkdownExporter();

    @Test
    void outputContainsTitleWithHost(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("report.md");
        exporter.export(report(), out);
        String md = Files.readString(out);
        assertTrue(md.contains("# Port Scan Report"), "Should contain H1 title");
        assertTrue(md.contains("localhost"), "Should contain host name");
    }

    @Test
    void outputContainsOpenPortsTable(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("report.md");
        exporter.export(report(), out);
        String md = Files.readString(out);
        assertTrue(md.contains("## Open Ports"), "Should contain Open Ports section");
        assertTrue(md.contains("80"), "Should contain port 80");
        assertTrue(md.contains("HTTP"), "Should contain service name");
    }

    @Test
    void noOpenPortsShowsNoOpenMessage(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("empty.md");
        ScanReport r = ScanReport.builder()
                .host("test").scannedAt(LocalDateTime.now())
                .openCount(0).filteredCount(0).totalScanned(100)
                .openPorts(List.of()).filteredPorts(List.of()).build();
        exporter.export(r, out);
        String md = Files.readString(out);
        assertTrue(md.contains("No open ports"), "Should indicate no open ports");
    }

    @Test
    void tlsInfoAppearsInOutput(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("tls.md");
        ScanResult r = ScanResult.builder()
                .port(443).status(PortStatus.OPEN).serviceName("HTTPS")
                .tlsInfo(TlsInfo.builder().protocol("TLSv1.3").certExpiry(java.time.LocalDate.of(2026,1,1)).build())
                .build();
        exporter.export(reportWith(List.of(r)), out);
        String md = Files.readString(out);
        assertTrue(md.contains("TLS"), "Should contain TLS info");
        assertTrue(md.contains("TLSv1.3"), "Should contain protocol");
    }

    @Test
    void osGuessAppearsInMetadata(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("os.md");
        ScanReport rep = report().toBuilder()
                .osGuess(OsGuess.builder().os("Linux (Ubuntu)").confidence("high").method("SSH banner").build())
                .build();
        exporter.export(rep, out);
        String md = Files.readString(out);
        assertTrue(md.contains("Linux (Ubuntu)"), "Should contain OS guess");
        assertTrue(md.contains("high"), "Should contain confidence");
    }

    @Test
    void filteredPortsInCollapsibleSection(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("filtered.md");
        ScanResult filtered = ScanResult.builder()
                .port(22).status(PortStatus.FILTERED).serviceName("SSH").build();
        ScanReport rep = report().toBuilder()
                .filteredCount(1).filteredPorts(List.of(filtered)).build();
        exporter.export(rep, out);
        String md = Files.readString(out);
        assertTrue(md.contains("<details>"), "Should use collapsible section for filtered ports");
        assertTrue(md.contains("22"), "Should contain filtered port number");
    }

    @Test
    void generatesValidMarkdownFooter(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("footer.md");
        exporter.export(report(), out);
        String md = Files.readString(out);
        assertTrue(md.contains("port-scanner"), "Should contain footer credit");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ScanReport report() {
        return reportWith(List.of(
                ScanResult.builder().port(80).status(PortStatus.OPEN)
                        .serviceName("HTTP").responseTimeMs(12).build()));
    }

    private static ScanReport reportWith(List<ScanResult> ports) {
        return ScanReport.builder()
                .host("localhost").resolvedIp("127.0.0.1")
                .scannedAt(LocalDateTime.now()).durationMs(500)
                .totalScanned(1024).openCount(ports.size()).filteredCount(0)
                .openPorts(ports).filteredPorts(List.of())
                .build();
    }
}
