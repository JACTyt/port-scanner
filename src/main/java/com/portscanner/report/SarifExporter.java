package com.portscanner.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Exports a {@link ScanReport} as SARIF 2.1.0 JSON.
 *
 * <p>SARIF (Static Analysis Results Interchange Format) is the OASIS standard used by
 * GitHub's Security tab, DefectDojo, Azure DevOps, and VS Code. Upload the output via
 * the {@code github/codeql-action/upload-sarif} GitHub Action to surface findings directly
 * in the repository's Security &gt; Code Scanning tab.
 *
 * <p>Mapping:
 * <ul>
 *   <li>Each open port → one {@code result} with {@code level=note}</li>
 *   <li>Each CVE on a port → one additional {@code result} with {@code level=error}</li>
 *   <li>Each unique CVE → one {@code rule} in {@code driver.rules[]}</li>
 * </ul>
 */
public class SarifExporter implements ReportExporter {

    private static final String SARIF_SCHEMA =
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
    private static final String OPEN_PORT_RULE_ID = "OPEN_PORT";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public void export(ScanReport report, Path outputPath) throws IOException {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("$schema", SARIF_SCHEMA);
        root.put("version", "2.1.0");

        ArrayNode runs = root.putArray("runs");
        ObjectNode run = runs.addObject();

        List<ScanResult> open = report.getOpenPorts() != null ? report.getOpenPorts() : List.of();
        String host = report.getHost() != null ? report.getHost() : "unknown";
        String ip   = report.getResolvedIp() != null ? report.getResolvedIp() : host;

        // ── Tool descriptor ────────────────────────────────────────────────
        ObjectNode tool   = run.putObject("tool");
        ObjectNode driver = tool.putObject("driver");
        driver.put("name", "port-scanner");
        driver.put("version", "2.0");
        driver.put("informationUri", "https://github.com/user/port-scanner");

        // ── Rules (base + one per unique CVE) ──────────────────────────────
        Set<String> cveIds = new LinkedHashSet<>();
        for (ScanResult r : open) {
            if (r.getCves() != null) r.getCves().forEach(c -> cveIds.add(c.getId()));
        }

        ArrayNode rules = driver.putArray("rules");

        ObjectNode baseRule = rules.addObject();
        baseRule.put("id", OPEN_PORT_RULE_ID);
        baseRule.putObject("shortDescription").put("text", "Open TCP port");
        baseRule.putObject("fullDescription").put("text",
                "A TCP port is open and accepting connections on the scanned host.");
        baseRule.putObject("defaultConfiguration").put("level", "note");

        for (String cveId : cveIds) {
            ObjectNode cveRule = rules.addObject();
            cveRule.put("id", cveId);
            cveRule.putObject("shortDescription").put("text", "Known vulnerability: " + cveId);
            cveRule.put("helpUri", "https://nvd.nist.gov/vuln/detail/" + cveId);
            cveRule.putObject("defaultConfiguration").put("level", "error");
        }

        // ── Results ────────────────────────────────────────────────────────
        ArrayNode results = run.putArray("results");

        for (ScanResult r : open) {
            // One note per open port
            ObjectNode portResult = results.addObject();
            portResult.put("ruleId", OPEN_PORT_RULE_ID);
            portResult.put("level", "note");
            portResult.putObject("message").put("text", String.format(
                    "Port %d/%s is open on %s (%s)",
                    r.getPort(),
                    r.getServiceName() != null ? r.getServiceName() : "unknown",
                    host, ip));

            String uri = String.format("tcp://%s:%d", ip, r.getPort());
            portResult.putArray("locations").addObject()
                    .putObject("physicalLocation")
                    .putObject("artifactLocation").put("uri", uri);

            ObjectNode props = portResult.putObject("properties");
            props.put("port", r.getPort());
            if (r.getServiceName() != null) props.put("service", r.getServiceName());
            if (r.getVersion()     != null) props.put("version", r.getVersion());
            if (r.getBanner()      != null) props.put("banner",  r.getBanner());

            // One error per CVE on this port
            if (r.getCves() != null) {
                for (var cve : r.getCves()) {
                    String cveId = cve.getId();
                    ObjectNode cveResult = results.addObject();
                    cveResult.put("ruleId", cveId);
                    cveResult.put("level", "error");
                    cveResult.putObject("message").put("text", String.format(
                            "Port %d/%s on %s is associated with %s",
                            r.getPort(), nvl(r.getServiceName()), host, cveId));
                    cveResult.putArray("locations").addObject()
                            .putObject("physicalLocation")
                            .putObject("artifactLocation").put("uri", uri);
                    ObjectNode cveProps = cveResult.putObject("properties");
                    cveProps.put("nvdUrl", "https://nvd.nist.gov/vuln/detail/" + cveId);
                    if (cve.getCvssV3() != null) cveProps.put("cvssV3", cve.getCvssV3());
                    if (cve.getSeverity() != null) cveProps.put("severity", cve.getSeverity());
                }
            }
        }

        // ── Invocation metadata ────────────────────────────────────────────
        ObjectNode inv = run.putArray("invocations").addObject();
        inv.put("executionSuccessful", true);
        if (report.getScannedAt() != null) {
            inv.put("startTimeUtc",
                    report.getScannedAt().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME) + "Z");
        }

        Files.writeString(outputPath,
                MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root),
                StandardCharsets.UTF_8);
    }

    private static String nvl(String s) { return s != null ? s : "unknown"; }
}
