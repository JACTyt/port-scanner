package com.portscanner.report;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JUnitXmlExporterTest {

    @TempDir
    Path tempDir;

    private ScanReport buildReport() {
        ScanResult r22  = ScanResult.builder().port(22).status(PortStatus.OPEN)
                .serviceName("SSH").responseTimeMs(5).build();
        ScanResult r23  = ScanResult.builder().port(23).status(PortStatus.OPEN)
                .serviceName("Telnet").responseTimeMs(8).banner("+OK").build();
        ScanResult r80  = ScanResult.builder().port(80).status(PortStatus.OPEN)
                .serviceName("HTTP").responseTimeMs(10).build();
        return ScanReport.builder()
                .host("192.168.1.1")
                .resolvedIp("192.168.1.1")
                .scannedAt(LocalDateTime.of(2026, 3, 19, 9, 0, 0))
                .durationMs(1200)
                .totalScanned(1024)
                .openCount(3)
                .filteredCount(0)
                .openPorts(List.of(r22, r23, r80))
                .filteredPorts(List.of())
                .build();
    }

    @Test
    void produces_valid_xml() throws Exception {
        Path out = tempDir.resolve("result.xml");
        new JUnitXmlExporter().export(buildReport(), out);
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(out.toFile());
        assertEquals("testsuite", doc.getDocumentElement().getTagName());
    }

    @Test
    void testcase_count_matches_open_ports() throws Exception {
        Path out = tempDir.resolve("result.xml");
        new JUnitXmlExporter().export(buildReport(), out);
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(out.toFile());
        NodeList cases = doc.getElementsByTagName("testcase");
        assertEquals(3, cases.getLength());
    }

    @Test
    void no_failures_by_default() throws Exception {
        Path out = tempDir.resolve("result.xml");
        new JUnitXmlExporter().export(buildReport(), out);
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(out.toFile());
        assertEquals(0, doc.getElementsByTagName("failure").getLength());
        assertEquals("0", doc.getDocumentElement().getAttribute("failures"));
    }

    @Test
    void blocked_port_produces_failure_element() throws Exception {
        Path out = tempDir.resolve("result.xml");
        new JUnitXmlExporter(List.of(23)).export(buildReport(), out);
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(out.toFile());
        assertEquals(1, doc.getElementsByTagName("failure").getLength());
        assertEquals("1", doc.getDocumentElement().getAttribute("failures"));
    }

    @Test
    void multiple_blocked_ports_produce_multiple_failures() throws Exception {
        Path out = tempDir.resolve("result.xml");
        new JUnitXmlExporter(List.of(22, 23)).export(buildReport(), out);
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(out.toFile());
        assertEquals(2, doc.getElementsByTagName("failure").getLength());
    }

    @Test
    void non_open_blocked_port_produces_no_failure() throws Exception {
        Path out = tempDir.resolve("result.xml");
        // Port 9999 is not in the open list
        new JUnitXmlExporter(List.of(9999)).export(buildReport(), out);
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(out.toFile());
        assertEquals(0, doc.getElementsByTagName("failure").getLength());
    }

    @Test
    void testsuite_has_hostname_attribute() throws Exception {
        Path out = tempDir.resolve("result.xml");
        new JUnitXmlExporter().export(buildReport(), out);
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(out.toFile());
        assertEquals("192.168.1.1", doc.getDocumentElement().getAttribute("hostname"));
    }

    @Test
    void empty_open_ports_produces_empty_testsuite() throws Exception {
        ScanReport report = ScanReport.builder()
                .host("localhost").resolvedIp("127.0.0.1")
                .durationMs(100).openCount(0).filteredCount(0).totalScanned(100)
                .openPorts(List.of()).filteredPorts(List.of()).build();
        Path out = tempDir.resolve("empty.xml");
        new JUnitXmlExporter(List.of(23)).export(report, out);
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(out.toFile());
        assertEquals(0, doc.getElementsByTagName("testcase").getLength());
        assertEquals("0", doc.getDocumentElement().getAttribute("failures"));
    }

    @Test
    void junit_format_selects_junit_exporter() {
        assertInstanceOf(JUnitXmlExporter.class, ExporterFactory.getExporter("out.txt", "junit", null));
    }

    @Test
    void junit_xml_format_selects_junit_exporter() {
        assertInstanceOf(JUnitXmlExporter.class, ExporterFactory.getExporter("out.txt", "junit-xml", null));
    }
}
