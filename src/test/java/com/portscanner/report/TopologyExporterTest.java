package com.portscanner.report;

import com.portscanner.model.MultiHostReport;
import com.portscanner.model.OsGuess;
import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import com.portscanner.model.SubnetReport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TopologyExporterTest {

    private final TopologyExporter exporter = new TopologyExporter();

    // ── Graphviz DOT ──────────────────────────────────────────────────────────

    @Test
    void dotSingleReportContainsScannerNode(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("topo.dot");
        exporter.export(report("192.168.1.1", List.of(port(80, "HTTP"))), out);
        String dot = Files.readString(out);
        assertTrue(dot.contains("scanner"), "Should contain scanner node");
        assertTrue(dot.contains("digraph"), "Should be a digraph");
    }

    @Test
    void dotContainsHostNode(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("host.dot");
        exporter.export(report("myhost", List.of(port(22, "SSH"))), out);
        String dot = Files.readString(out);
        assertTrue(dot.contains("myhost"), "Should contain host label");
    }

    @Test
    void dotContainsPortNodes(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("ports.dot");
        exporter.export(report("h1", List.of(port(443, "HTTPS"), port(80, "HTTP"))), out);
        String dot = Files.readString(out);
        assertTrue(dot.contains("443"), "Should contain port 443");
        assertTrue(dot.contains("80"),  "Should contain port 80");
    }

    @Test
    void dotSubnetReportExportsMultipleHosts(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("subnet.dot");
        SubnetReport sub = SubnetReport.builder()
                .subnet("10.0.0.0/24").scannedAt(LocalDateTime.now())
                .hostsScanned(2).hostsWithOpenPorts(2)
                .hostReports(List.of(
                        report("10.0.0.1", List.of(port(22, "SSH"))),
                        report("10.0.0.2", List.of(port(80, "HTTP")))))
                .build();
        exporter.export(sub, out);
        String dot = Files.readString(out);
        assertTrue(dot.contains("10_0_0_1") || dot.contains("10.0.0.1"));
        assertTrue(dot.contains("10_0_0_2") || dot.contains("10.0.0.2"));
    }

    @Test
    void dotMultiHostExports(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("multi.dot");
        MultiHostReport multi = MultiHostReport.builder()
                .scannedAt(LocalDateTime.now()).durationMs(500)
                .totalHosts(2).hostsWithOpenPorts(2)
                .results(List.of(
                        report("host-a", List.of(port(80, "HTTP"))),
                        report("host-b", List.of(port(443, "HTTPS")))))
                .build();
        exporter.export(multi, out);
        String dot = Files.readString(out);
        assertTrue(dot.contains("host_a") || dot.contains("host-a"));
        assertTrue(dot.contains("host_b") || dot.contains("host-b"));
    }

    // ── Mermaid ───────────────────────────────────────────────────────────────

    @Test
    void mermaidSingleReportContainsGraphLR(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("topo.mmd");
        exporter.export(report("myhost", List.of(port(80, "HTTP"))), out);
        String mmd = Files.readString(out);
        assertTrue(mmd.contains("graph LR"), "Mermaid output should start with 'graph LR'");
        assertTrue(mmd.contains("scanner"), "Should contain scanner node");
    }

    @Test
    void mermaidContainsHostAndPort(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("hp.mmd");
        exporter.export(report("srv1", List.of(port(22, "SSH"))), out);
        String mmd = Files.readString(out);
        assertTrue(mmd.contains("srv1"),  "Should contain host");
        assertTrue(mmd.contains("22"),    "Should contain port");
        assertTrue(mmd.contains("SSH"),   "Should contain service");
    }

    @Test
    void osGuessColorAppliedInMermaid(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("os.mmd");
        ScanReport rep = report("win-host", List.of(port(3389, "RDP"))).toBuilder()
                .osGuess(OsGuess.builder().os("Windows").confidence("medium").method("RDP").build())
                .build();
        exporter.export(rep, out);
        String mmd = Files.readString(out);
        assertTrue(mmd.contains("ffcccc"), "Windows hosts should have red-ish fill");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ScanReport report(String host, List<ScanResult> ports) {
        return ScanReport.builder()
                .host(host).resolvedIp("1.2.3.4")
                .scannedAt(LocalDateTime.now()).durationMs(100)
                .totalScanned(1024).openCount(ports.size()).filteredCount(0)
                .openPorts(ports).filteredPorts(List.of()).build();
    }

    private static ScanResult port(int p, String svc) {
        return ScanResult.builder().port(p).status(PortStatus.OPEN).serviceName(svc).build();
    }
}
