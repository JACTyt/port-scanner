package com.portscanner.report;

import com.portscanner.model.*;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.FileInputStream;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class XlsxExporterTest {

    @TempDir Path tmp;

    private ScanReport buildReport() {
        CveEntry cve = CveEntry.builder()
                .id("CVE-2021-41773")
                .cvssV3(9.8)
                .severity("CRITICAL")
                .description("Apache path traversal")
                .build();
        ScanResult port80 = ScanResult.builder()
                .port(80).status(PortStatus.OPEN)
                .serviceName("HTTP").banner("Apache/2.4.49")
                .cves(List.of(cve)).build();
        ScanResult port443 = ScanResult.builder()
                .port(443).status(PortStatus.OPEN)
                .serviceName("HTTPS")
                .tlsInfo(TlsInfo.builder()
                        .certSubject("CN=example.com")
                        .certIssuer("Let's Encrypt")
                        .build())
                .build();
        SnmpInfo snmp = SnmpInfo.builder()
                .sysName("router1").sysLocation("datacenter").build();
        ScanResult port161 = ScanResult.builder()
                .port(161).status(PortStatus.OPEN)
                .serviceName("SNMP").snmpInfo(snmp).build();
        return ScanReport.builder()
                .host("example.com").resolvedIp("93.184.216.34")
                .scannedAt(LocalDateTime.now())
                .durationMs(1234)
                .openPorts(List.of(port80, port443, port161))
                .tracerouteHops(List.of(new TracerouteHop(1, "192.168.1.1", "gateway", 1.2)))
                .build();
    }

    @Test
    void xlsx_hasExpectedSheets() throws Exception {
        Path out = tmp.resolve("report.xlsx");
        new XlsxExporter().export(buildReport(), out);

        try (FileInputStream fis = new FileInputStream(out.toFile());
             Workbook wb = new XSSFWorkbook(fis)) {
            assertNotNull(wb.getSheet("Summary"));
            assertNotNull(wb.getSheet("Open Ports"));
            assertNotNull(wb.getSheet("CVEs"));
            assertNotNull(wb.getSheet("TLS Findings"));
            assertNotNull(wb.getSheet("SNMP"));
            assertNotNull(wb.getSheet("Traceroute"));
        }
    }

    @Test
    void openPorts_sheet_hasHeaderAndDataRows() throws Exception {
        Path out = tmp.resolve("report.xlsx");
        new XlsxExporter().export(buildReport(), out);

        try (FileInputStream fis = new FileInputStream(out.toFile());
             Workbook wb = new XSSFWorkbook(fis)) {
            Sheet sheet = wb.getSheet("Open Ports");
            Row header = sheet.getRow(0);
            assertEquals("Port", header.getCell(0).getStringCellValue());
            assertEquals("Service", header.getCell(2).getStringCellValue());
            Row row1 = sheet.getRow(1);
            assertEquals(80.0, row1.getCell(0).getNumericCellValue(), 0.01);
        }
    }

    @Test
    void cves_sheet_hasCvssScore() throws Exception {
        Path out = tmp.resolve("report.xlsx");
        new XlsxExporter().export(buildReport(), out);

        try (FileInputStream fis = new FileInputStream(out.toFile());
             Workbook wb = new XSSFWorkbook(fis)) {
            Sheet cves = wb.getSheet("CVEs");
            Row row = cves.getRow(1);
            assertNotNull(row);
            assertTrue(row.getCell(1).getStringCellValue().startsWith("CVE-"));
            assertEquals(9.8, row.getCell(2).getNumericCellValue(), 0.01);
        }
    }

    @Test
    void snmp_sheet_hasData() throws Exception {
        Path out = tmp.resolve("report.xlsx");
        new XlsxExporter().export(buildReport(), out);

        try (FileInputStream fis = new FileInputStream(out.toFile());
             Workbook wb = new XSSFWorkbook(fis)) {
            Sheet snmp = wb.getSheet("SNMP");
            Row row = snmp.getRow(1);
            assertNotNull(row);
            assertEquals(161.0, row.getCell(0).getNumericCellValue(), 0.01);
            assertEquals("router1", row.getCell(2).getStringCellValue());
        }
    }

    @Test
    void traceroute_sheet_hasHops() throws Exception {
        Path out = tmp.resolve("report.xlsx");
        new XlsxExporter().export(buildReport(), out);

        try (FileInputStream fis = new FileInputStream(out.toFile());
             Workbook wb = new XSSFWorkbook(fis)) {
            Sheet tr = wb.getSheet("Traceroute");
            Row row = tr.getRow(1);
            assertNotNull(row);
            assertEquals(1.0, row.getCell(0).getNumericCellValue(), 0.01);
            assertEquals("192.168.1.1", row.getCell(1).getStringCellValue());
        }
    }
}
