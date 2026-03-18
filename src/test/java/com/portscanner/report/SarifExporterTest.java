package com.portscanner.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

class SarifExporterTest {

    @TempDir
    Path tempDir;

    private ScanReport buildReport() {
        ScanResult r80 = ScanResult.builder()
                .port(80).status(PortStatus.OPEN).serviceName("HTTP")
                .responseTimeMs(12).banner("Apache/2.4").build();
        ScanResult r22 = ScanResult.builder()
                .port(22).status(PortStatus.OPEN).serviceName("SSH")
                .responseTimeMs(5).cves(List.of("CVE-2023-38408", "CVE-2021-41617")).build();
        return ScanReport.builder()
                .host("example.com")
                .resolvedIp("93.184.216.34")
                .scannedAt(LocalDateTime.of(2026, 3, 19, 10, 0, 0))
                .durationMs(2500)
                .totalScanned(1024)
                .openCount(2)
                .filteredCount(0)
                .openPorts(List.of(r80, r22))
                .filteredPorts(List.of())
                .build();
    }

    @Test
    void produces_valid_json() throws Exception {
        Path out = tempDir.resolve("scan.sarif");
        new SarifExporter().export(buildReport(), out);
        assertTrue(Files.exists(out));
        ObjectMapper m = new ObjectMapper();
        JsonNode root = m.readTree(out.toFile());
        assertNotNull(root);
    }

    @Test
    void sarif_version_is_2_1_0() throws Exception {
        Path out = tempDir.resolve("scan.sarif");
        new SarifExporter().export(buildReport(), out);
        JsonNode root = new ObjectMapper().readTree(out.toFile());
        assertEquals("2.1.0", root.get("version").asText());
    }

    @Test
    void schema_field_present() throws Exception {
        Path out = tempDir.resolve("scan.sarif");
        new SarifExporter().export(buildReport(), out);
        JsonNode root = new ObjectMapper().readTree(out.toFile());
        assertTrue(root.has("$schema"));
        assertTrue(root.get("$schema").asText().contains("sarif-schema-2.1.0"));
    }

    @Test
    void tool_driver_name_is_port_scanner() throws Exception {
        Path out = tempDir.resolve("scan.sarif");
        new SarifExporter().export(buildReport(), out);
        JsonNode root = new ObjectMapper().readTree(out.toFile());
        String name = root.at("/runs/0/tool/driver/name").asText();
        assertEquals("port-scanner", name);
    }

    @Test
    void open_ports_produce_results() throws Exception {
        Path out = tempDir.resolve("scan.sarif");
        new SarifExporter().export(buildReport(), out);
        JsonNode root = new ObjectMapper().readTree(out.toFile());
        JsonNode results = root.at("/runs/0/results");
        // 2 open ports + 2 CVEs = at least 4 results
        assertTrue(results.size() >= 4);
    }

    @Test
    void cve_results_have_error_level() throws Exception {
        Path out = tempDir.resolve("scan.sarif");
        new SarifExporter().export(buildReport(), out);
        JsonNode root = new ObjectMapper().readTree(out.toFile());
        JsonNode results = root.at("/runs/0/results");
        boolean foundCveError = false;
        for (JsonNode result : results) {
            if ("error".equals(result.get("level").asText())
                    && result.get("ruleId").asText().startsWith("CVE-")) {
                foundCveError = true;
                break;
            }
        }
        assertTrue(foundCveError, "Expected at least one CVE result with level=error");
    }

    @Test
    void cves_appear_in_driver_rules() throws Exception {
        Path out = tempDir.resolve("scan.sarif");
        new SarifExporter().export(buildReport(), out);
        JsonNode root = new ObjectMapper().readTree(out.toFile());
        JsonNode rules = root.at("/runs/0/tool/driver/rules");
        boolean found = false;
        for (JsonNode rule : rules) {
            if ("CVE-2023-38408".equals(rule.get("id").asText())) {
                found = true;
                break;
            }
        }
        assertTrue(found, "Expected CVE-2023-38408 in driver rules");
    }

    @Test
    void artifact_location_contains_host_and_port() throws Exception {
        Path out = tempDir.resolve("scan.sarif");
        new SarifExporter().export(buildReport(), out);
        JsonNode root = new ObjectMapper().readTree(out.toFile());
        JsonNode results = root.at("/runs/0/results");
        boolean found = false;
        for (JsonNode result : results) {
            String uri = result.at("/locations/0/physicalLocation/artifactLocation/uri").asText();
            if (uri.contains(":80") || uri.contains(":22")) {
                found = true;
                break;
            }
        }
        assertTrue(found, "Expected tcp://host:port URI in locations");
    }

    @Test
    void empty_open_ports_produces_minimal_sarif() throws Exception {
        ScanReport report = ScanReport.builder()
                .host("localhost").resolvedIp("127.0.0.1")
                .openCount(0).filteredCount(0).totalScanned(100)
                .durationMs(500).openPorts(List.of()).filteredPorts(List.of())
                .build();
        Path out = tempDir.resolve("empty.sarif");
        new SarifExporter().export(report, out);
        JsonNode root = new ObjectMapper().readTree(out.toFile());
        assertEquals("2.1.0", root.get("version").asText());
        assertEquals(0, root.at("/runs/0/results").size());
    }

    @Test
    void sarif_extension_selects_sarif_exporter() {
        assertInstanceOf(SarifExporter.class, ExporterFactory.getExporter("out.sarif", null));
    }

    @Test
    void format_sarif_selects_sarif_exporter() {
        assertInstanceOf(SarifExporter.class, ExporterFactory.getExporter("out.txt", "sarif", null));
    }
}
