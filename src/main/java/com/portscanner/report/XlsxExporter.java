package com.portscanner.report;

import com.portscanner.model.*;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.ss.util.CellRangeAddress;
import org.apache.poi.xssf.usermodel.*;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class XlsxExporter implements ReportExporter {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Override
    public void export(ScanReport report, Path outputPath) throws IOException {
        try (XSSFWorkbook wb = new XSSFWorkbook()) {
            CellStyle headerStyle = createHeaderStyle(wb);
            CellStyle criticalStyle = createCriticalStyle(wb);
            CellStyle highStyle = createHighStyle(wb);

            writeSummarySheet(wb, report, headerStyle);
            writeOpenPortsSheet(wb, report, headerStyle, criticalStyle);
            writeCvesSheet(wb, report, headerStyle, criticalStyle, highStyle);
            writeTlsSheet(wb, report, headerStyle);
            writeSnmpSheet(wb, report, headerStyle);
            writeTracerouteSheet(wb, report, headerStyle);

            try (FileOutputStream fos = new FileOutputStream(outputPath.toFile())) {
                wb.write(fos);
            }
        }
    }

    private void writeSummarySheet(XSSFWorkbook wb, ScanReport report, CellStyle headerStyle) {
        Sheet s = wb.createSheet("Summary");
        int r = 0;
        addLabelValue(s, r++, "Host", report.getHost());
        addLabelValue(s, r++, "Resolved IP", report.getResolvedIp());
        addLabelValue(s, r++, "Scanned At", report.getScannedAt() != null ? report.getScannedAt().format(FMT) : "");
        addLabelValue(s, r++, "Duration (ms)", String.valueOf(report.getDurationMs()));
        addLabelValue(s, r++, "Open Ports", String.valueOf(report.getOpenCount()));
        addLabelValue(s, r++, "Filtered Ports", String.valueOf(report.getFilteredCount()));
        addLabelValue(s, r++, "Total Scanned", String.valueOf(report.getTotalScanned()));
        if (report.getOsGuess() != null) {
            addLabelValue(s, r, "OS Guess", report.getOsGuess().getOs() + " (" + report.getOsGuess().getConfidence() + "%)");
        }
        s.setColumnWidth(0, 6000);
        s.setColumnWidth(1, 12000);
    }

    private void writeOpenPortsSheet(XSSFWorkbook wb, ScanReport report, CellStyle headerStyle, CellStyle criticalStyle) {
        Sheet s = wb.createSheet("Open Ports");
        String[] cols = {"Port", "Protocol", "Service", "Version", "Banner", "CVEs", "CVSS Max"};
        writeHeader(s, cols, headerStyle);
        s.setAutoFilter(new CellRangeAddress(0, 0, 0, cols.length - 1));

        List<ScanResult> ports = report.getOpenPorts();
        if (ports == null) return;
        int r = 1;
        for (ScanResult res : ports) {
            Row row = s.createRow(r++);
            row.createCell(0).setCellValue(res.getPort());
            row.createCell(1).setCellValue("TCP");
            row.createCell(2).setCellValue(nvl(res.getServiceName()));
            row.createCell(3).setCellValue(nvl(res.getVersion()));
            row.createCell(4).setCellValue(nvl(res.getBanner()));

            double maxCvss = 0;
            if (res.getCves() != null && !res.getCves().isEmpty()) {
                String cveIds = res.getCves().stream()
                        .map(CveEntry::getId).reduce((a, b) -> a + ", " + b).orElse("");
                row.createCell(5).setCellValue(cveIds);
                maxCvss = res.getCves().stream()
                        .mapToDouble(c -> c.getCvssV3() != null ? c.getCvssV3() : 0)
                        .max().orElse(0);
                if (maxCvss >= 9.0) applyCellStyleToRow(row, criticalStyle);
            }
            row.createCell(6).setCellValue(maxCvss);
        }
        autoSizeColumns(s, cols.length);
    }

    private void writeCvesSheet(XSSFWorkbook wb, ScanReport report,
                                 CellStyle headerStyle, CellStyle criticalStyle, CellStyle highStyle) {
        Sheet s = wb.createSheet("CVEs");
        String[] cols = {"Port", "CVE ID", "CVSS", "Severity", "Description"};
        writeHeader(s, cols, headerStyle);
        s.setAutoFilter(new CellRangeAddress(0, 0, 0, cols.length - 1));

        List<ScanResult> ports = report.getOpenPorts();
        if (ports == null) return;
        int r = 1;
        for (ScanResult res : ports) {
            if (res.getCves() == null) continue;
            for (CveEntry cve : res.getCves()) {
                Row row = s.createRow(r++);
                row.createCell(0).setCellValue(res.getPort());
                row.createCell(1).setCellValue(nvl(cve.getId()));
                row.createCell(2).setCellValue(cve.getCvssV3() != null ? cve.getCvssV3() : 0);
                row.createCell(3).setCellValue(nvl(cve.getSeverity()));
                row.createCell(4).setCellValue(nvl(cve.getDescription()));
                if (cve.getCvssV3() != null) {
                    if (cve.getCvssV3() >= 9.0) applyCellStyleToRow(row, criticalStyle);
                    else if (cve.getCvssV3() >= 7.0) applyCellStyleToRow(row, highStyle);
                }
            }
        }
        autoSizeColumns(s, cols.length);
    }

    private void writeTlsSheet(XSSFWorkbook wb, ScanReport report, CellStyle headerStyle) {
        Sheet s = wb.createSheet("TLS Findings");
        String[] cols = {"Port", "Subject", "Expires", "SANs", "Issuer"};
        writeHeader(s, cols, headerStyle);
        s.setAutoFilter(new CellRangeAddress(0, 0, 0, cols.length - 1));

        List<ScanResult> ports = report.getOpenPorts();
        if (ports == null) return;
        int r = 1;
        for (ScanResult res : ports) {
            if (res.getTlsInfo() == null) continue;
            TlsInfo tls = res.getTlsInfo();
            Row row = s.createRow(r++);
            row.createCell(0).setCellValue(res.getPort());
            row.createCell(1).setCellValue(nvl(tls.getCertSubject()));
            row.createCell(2).setCellValue(tls.getCertExpiry() != null ? tls.getCertExpiry().toString() : "");
            row.createCell(3).setCellValue(tls.getSubjectAltNames() != null ? String.join(", ", tls.getSubjectAltNames()) : "");
            row.createCell(4).setCellValue(nvl(tls.getCertIssuer()));
        }
        autoSizeColumns(s, cols.length);
    }

    private void writeSnmpSheet(XSSFWorkbook wb, ScanReport report, CellStyle headerStyle) {
        Sheet s = wb.createSheet("SNMP");
        String[] cols = {"Port", "sysDescr", "sysName", "sysLocation", "sysContact"};
        writeHeader(s, cols, headerStyle);
        s.setAutoFilter(new CellRangeAddress(0, 0, 0, cols.length - 1));

        List<ScanResult> ports = report.getOpenPorts();
        if (ports == null) return;
        int r = 1;
        for (ScanResult res : ports) {
            if (res.getSnmpInfo() == null) continue;
            SnmpInfo snmp = res.getSnmpInfo();
            Row row = s.createRow(r++);
            row.createCell(0).setCellValue(res.getPort());
            row.createCell(1).setCellValue(nvl(snmp.getSysDescr()));
            row.createCell(2).setCellValue(nvl(snmp.getSysName()));
            row.createCell(3).setCellValue(nvl(snmp.getSysLocation()));
            row.createCell(4).setCellValue(nvl(snmp.getSysContact()));
        }
        autoSizeColumns(s, cols.length);
    }

    private void writeTracerouteSheet(XSSFWorkbook wb, ScanReport report, CellStyle headerStyle) {
        Sheet s = wb.createSheet("Traceroute");
        String[] cols = {"Hop", "IP", "Hostname", "RTT (ms)"};
        writeHeader(s, cols, headerStyle);
        s.setAutoFilter(new CellRangeAddress(0, 0, 0, cols.length - 1));

        List<TracerouteHop> hops = report.getTracerouteHops();
        if (hops == null) return;
        int r = 1;
        for (TracerouteHop hop : hops) {
            Row row = s.createRow(r++);
            row.createCell(0).setCellValue(hop.hopNumber());
            row.createCell(1).setCellValue(nvl(hop.ip()));
            row.createCell(2).setCellValue(nvl(hop.hostname()));
            row.createCell(3).setCellValue(hop.rttMs());
        }
        autoSizeColumns(s, cols.length);
    }

    private void writeHeader(Sheet s, String[] cols, CellStyle style) {
        Row header = s.createRow(0);
        for (int i = 0; i < cols.length; i++) {
            Cell c = header.createCell(i);
            c.setCellValue(cols[i]);
            c.setCellStyle(style);
        }
        s.createFreezePane(0, 1);
    }

    private void addLabelValue(Sheet s, int row, String label, String value) {
        Row r = s.createRow(row);
        r.createCell(0).setCellValue(label);
        r.createCell(1).setCellValue(value != null ? value : "");
    }

    private void autoSizeColumns(Sheet s, int count) {
        for (int i = 0; i < count; i++) s.autoSizeColumn(i);
    }

    private CellStyle createHeaderStyle(XSSFWorkbook wb) {
        CellStyle style = wb.createCellStyle();
        XSSFFont font = wb.createFont();
        font.setBold(true);
        style.setFont(font);
        style.setFillForegroundColor(IndexedColors.GREY_25_PERCENT.getIndex());
        style.setFillPattern(FillPatternType.SOLID_FOREGROUND);
        return style;
    }

    private CellStyle createCriticalStyle(XSSFWorkbook wb) {
        CellStyle style = wb.createCellStyle();
        style.setFillForegroundColor(IndexedColors.RED.getIndex());
        style.setFillPattern(FillPatternType.SOLID_FOREGROUND);
        return style;
    }

    private CellStyle createHighStyle(XSSFWorkbook wb) {
        CellStyle style = wb.createCellStyle();
        style.setFillForegroundColor(IndexedColors.ORANGE.getIndex());
        style.setFillPattern(FillPatternType.SOLID_FOREGROUND);
        return style;
    }

    private void applyCellStyleToRow(Row row, CellStyle style) {
        for (Cell cell : row) {
            cell.setCellStyle(style);
        }
    }

    private String nvl(String s) { return s != null ? s : ""; }
}
