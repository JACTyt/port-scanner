package com.portscanner.report;

import com.lowagie.text.Chunk;
import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;

import java.awt.Color;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Exports a {@link ScanReport} as a PDF document using OpenPDF.
 */
public class PdfExporter implements ReportExporter {

    private static final DateTimeFormatter DT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final Font TITLE_FONT   = new Font(Font.HELVETICA, 18, Font.BOLD, new Color(30, 90, 160));
    private static final Font H2_FONT      = new Font(Font.HELVETICA, 13, Font.BOLD, new Color(30, 90, 160));
    private static final Font LABEL_FONT   = new Font(Font.HELVETICA, 10, Font.BOLD, Color.DARK_GRAY);
    private static final Font NORMAL_FONT  = new Font(Font.HELVETICA, 10, Font.NORMAL, Color.BLACK);
    private static final Font MONO_FONT    = new Font(Font.COURIER,    9, Font.NORMAL, new Color(60, 60, 60));
    private static final Font WARN_FONT    = new Font(Font.HELVETICA, 10, Font.BOLD,   new Color(180, 30, 30));
    private static final Font PORT_FONT    = new Font(Font.HELVETICA, 10, Font.BOLD,   new Color(0, 120, 0));

    @Override
    public void export(ScanReport report, Path outputPath) throws IOException {
        Document doc = new Document(PageSize.A4, 40, 40, 50, 50);
        try {
            PdfWriter.getInstance(doc, new FileOutputStream(outputPath.toFile()));
            doc.open();
            addContent(doc, report);
        } catch (DocumentException e) {
            throw new IOException("PDF generation failed: " + e.getMessage(), e);
        } finally {
            doc.close();
        }
    }

    private static void addContent(Document doc, ScanReport report) throws DocumentException {
        // ── Title ──────────────────────────────────────────────────────────────
        doc.add(new Paragraph("Port Scan Report", TITLE_FONT));
        doc.add(new Paragraph(report.getHost()
                + (report.getResolvedIp() != null ? "  (" + report.getResolvedIp() + ")" : ""),
                new Font(Font.HELVETICA, 12, Font.NORMAL, Color.GRAY)));
        doc.add(Chunk.NEWLINE);

        // ── Metadata table ─────────────────────────────────────────────────────
        doc.add(new Paragraph("Scan Summary", H2_FONT));
        doc.add(Chunk.NEWLINE);

        PdfPTable meta = new PdfPTable(2);
        meta.setWidthPercentage(60);
        meta.setWidths(new float[]{35, 65});
        meta.setHorizontalAlignment(Element.ALIGN_LEFT);

        addMetaRow(meta, "Host",     report.getHost());
        if (report.getResolvedIp() != null)
            addMetaRow(meta, "Resolved IP", report.getResolvedIp());
        if (report.getScannedAt() != null)
            addMetaRow(meta, "Scanned At", report.getScannedAt().format(DT));
        addMetaRow(meta, "Duration", String.format("%.2f s", report.getDurationMs() / 1000.0));
        addMetaRow(meta, "Ports Scanned", String.valueOf(report.getTotalScanned()));
        addMetaRow(meta, "Open",     String.valueOf(report.getOpenCount()));
        addMetaRow(meta, "Filtered", String.valueOf(report.getFilteredCount()));

        if (report.getOsGuess() != null) {
            var os = report.getOsGuess();
            addMetaRow(meta, "OS Guess",
                    os.getOs() + " (" + os.getConfidence() + " confidence, " + os.getMethod() + ")");
        }
        if (report.getGeoLocation() != null) {
            var g = report.getGeoLocation();
            addMetaRow(meta, "Location",
                    nvl(g.getCity()) + ", " + nvl(g.getRegion()) + ", " + nvl(g.getCountry()));
        }
        if (report.getAsnInfo() != null) {
            var a = report.getAsnInfo();
            addMetaRow(meta, "ASN", nvl(a.getAsn()) + " " + nvl(a.getName()));
        }
        doc.add(meta);
        doc.add(Chunk.NEWLINE);

        // ── Threat info ────────────────────────────────────────────────────────
        if (report.getThreatInfo() != null) {
            var t = report.getThreatInfo();
            doc.add(new Paragraph("Threat Intelligence", H2_FONT));
            doc.add(Chunk.NEWLINE);
            if (t.getAbuseConfidenceScore() > 0) {
                Paragraph p = new Paragraph("AbuseIPDB score: " + t.getAbuseConfidenceScore()
                        + "/100 (" + t.getAbuseReportCount() + " reports)", WARN_FONT);
                doc.add(p);
            }
            if (t.getGreynoiseClassification() != null) {
                doc.add(new Paragraph("GreyNoise: " + t.getGreynoiseClassification().toUpperCase(), WARN_FONT));
            }
            doc.add(Chunk.NEWLINE);
        }

        // ── Open ports table ───────────────────────────────────────────────────
        doc.add(new Paragraph("Open Ports", H2_FONT));
        doc.add(Chunk.NEWLINE);

        List<ScanResult> open = report.getOpenPorts();
        if (open == null || open.isEmpty()) {
            doc.add(new Paragraph("No open ports found.", NORMAL_FONT));
        } else {
            PdfPTable table = new PdfPTable(4);
            table.setWidthPercentage(100);
            table.setWidths(new float[]{12, 22, 15, 51});

            addHeaderCell(table, "PORT");
            addHeaderCell(table, "SERVICE");
            addHeaderCell(table, "RESPONSE");
            addHeaderCell(table, "BANNER / VERSION");

            for (ScanResult r : open) {
                addCell(table, String.valueOf(r.getPort()), PORT_FONT);
                addCell(table, nvl(r.getServiceName()), NORMAL_FONT);
                addCell(table, r.getResponseTimeMs() + "ms", NORMAL_FONT);

                String bannerText = r.getVersion() != null ? r.getVersion()
                        : (r.getBanner() != null ? truncate(r.getBanner(), 80) : "—");
                addCell(table, bannerText, MONO_FONT);

                // CVE row
                if (r.getCves() != null && !r.getCves().isEmpty()) {
                    String cveStr = r.getCves().stream().map(c -> c.getId()).collect(java.util.stream.Collectors.joining(", "));
                    PdfPCell cveCell = new PdfPCell(new Phrase(
                            "CVEs: " + cveStr, WARN_FONT));
                    cveCell.setColspan(4);
                    cveCell.setPadding(4);
                    cveCell.setBackgroundColor(new Color(255, 245, 245));
                    table.addCell(cveCell);
                }

                // TLS row
                if (r.getTlsInfo() != null) {
                    var tls = r.getTlsInfo();
                    StringBuilder tlsText = new StringBuilder("TLS: ")
                            .append(nvl(tls.getProtocol()))
                            .append("  ·  Expires: ").append(tls.getCertExpiry() != null ? tls.getCertExpiry().toString() : "N/A");
                    if (tls.isExpired())            tlsText.append("  [EXPIRED]");
                    if (tls.isExpiresSoon())        tlsText.append("  [EXPIRES SOON]");
                    if (tls.isDeprecatedProtocol()) tlsText.append("  [DEPRECATED PROTOCOL]");
                    PdfPCell tlsCell = new PdfPCell(new Phrase(tlsText.toString(), MONO_FONT));
                    tlsCell.setColspan(4);
                    tlsCell.setPadding(4);
                    tlsCell.setBackgroundColor(new Color(240, 248, 255));
                    table.addCell(tlsCell);
                }
            }
            doc.add(table);
        }

        doc.add(Chunk.NEWLINE);
        doc.add(new Paragraph("Generated by port-scanner",
                new Font(Font.HELVETICA, 8, Font.ITALIC, Color.GRAY)));
    }

    // ── Table helpers ─────────────────────────────────────────────────────────

    private static void addMetaRow(PdfPTable t, String label, String value) {
        PdfPCell lc = new PdfPCell(new Phrase(label, LABEL_FONT));
        lc.setBorder(Rectangle.NO_BORDER);
        lc.setPadding(4);
        PdfPCell vc = new PdfPCell(new Phrase(value, NORMAL_FONT));
        vc.setBorder(Rectangle.NO_BORDER);
        vc.setPadding(4);
        t.addCell(lc);
        t.addCell(vc);
    }

    private static void addHeaderCell(PdfPTable t, String text) {
        PdfPCell c = new PdfPCell(new Phrase(text, LABEL_FONT));
        c.setBackgroundColor(new Color(220, 230, 245));
        c.setPadding(5);
        t.addCell(c);
    }

    private static void addCell(PdfPTable t, String text, Font font) {
        PdfPCell c = new PdfPCell(new Phrase(text, font));
        c.setPadding(4);
        t.addCell(c);
    }

    private static String nvl(String s) { return s != null ? s : "—"; }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
