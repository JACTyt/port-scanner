package com.portscanner.report;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class NmapXmlExporterTest {

    @TempDir
    Path tempDir;

    private ScanReport buildReport() {
        ScanResult r80 = ScanResult.builder()
                .port(80).status(PortStatus.OPEN).serviceName("HTTP").responseTimeMs(12).banner("Apache/2.4").build();
        ScanResult r443 = ScanResult.builder()
                .port(443).status(PortStatus.OPEN).serviceName("HTTPS").responseTimeMs(8).build();
        return ScanReport.builder()
                .host("example.com")
                .resolvedIp("93.184.216.34")
                .scannedAt(LocalDateTime.of(2026, 3, 12, 10, 0, 0))
                .durationMs(3500)
                .totalScanned(1024)
                .openCount(2)
                .filteredCount(0)
                .openPorts(List.of(r80, r443))
                .filteredPorts(List.of())
                .build();
    }

    @Test
    void produces_valid_xml_with_nmaprun_root() throws Exception {
        Path out = tempDir.resolve("scan.nmap");
        new NmapXmlExporter().export(buildReport(), out);

        DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = db.parse(out.toFile());
        assertEquals("nmaprun", doc.getDocumentElement().getTagName());
    }

    @Test
    void nmaprun_has_required_attributes() throws Exception {
        Path out = tempDir.resolve("scan.nmap");
        new NmapXmlExporter().export(buildReport(), out);

        DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = db.parse(out.toFile());
        var root = doc.getDocumentElement();
        assertEquals("portscanner", root.getAttribute("scanner"));
        assertEquals("1.05", root.getAttribute("xmloutputversion"));
    }

    @Test
    void contains_host_address() throws Exception {
        Path out = tempDir.resolve("scan.nmap");
        new NmapXmlExporter().export(buildReport(), out);

        DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = db.parse(out.toFile());
        NodeList addresses = doc.getElementsByTagName("address");
        assertTrue(addresses.getLength() > 0);
        assertEquals("93.184.216.34", addresses.item(0).getAttributes().getNamedItem("addr").getNodeValue());
    }

    @Test
    void contains_open_ports() throws Exception {
        Path out = tempDir.resolve("scan.nmap");
        new NmapXmlExporter().export(buildReport(), out);

        DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = db.parse(out.toFile());
        NodeList ports = doc.getElementsByTagName("port");
        assertEquals(2, ports.getLength());
    }

    @Test
    void contains_runstats() throws Exception {
        Path out = tempDir.resolve("scan.nmap");
        new NmapXmlExporter().export(buildReport(), out);

        DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = db.parse(out.toFile());
        NodeList runstats = doc.getElementsByTagName("runstats");
        assertEquals(1, runstats.getLength());
    }

    @Test
    void nmap_extension_selects_nmap_exporter() {
        var exporter = ExporterFactory.getExporter("output.nmap", null);
        assertInstanceOf(NmapXmlExporter.class, exporter);
    }

    @Test
    void format_override_selects_nmap_exporter() {
        var exporter = ExporterFactory.getExporter("output.txt", "nmap-xml", null);
        assertInstanceOf(NmapXmlExporter.class, exporter);
    }
}
