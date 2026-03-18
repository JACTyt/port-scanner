package com.portscanner.report;

import com.fasterxml.jackson.databind.ObjectMapper;

public class ExporterFactory {

    public static ReportExporter getExporter(String outputFile, ObjectMapper objectMapper) {
        return getExporter(outputFile, null, objectMapper);
    }

    public static ReportExporter getExporter(String outputFile, String format, ObjectMapper objectMapper) {
        // --format flag takes precedence over file extension
        if (format != null && !format.isBlank()) {
            switch (format.toLowerCase()) {
                case "json":     return new JsonExporter(objectMapper);
                case "csv":      return new CsvExporter();
                case "html":     return new HtmlExporter();
                case "xml":      return new XmlExporter();
                case "txt":
                case "text":     return new TextExporter();
                case "nmap-xml":
                case "nmap":     return new NmapXmlExporter();
                case "md":
                case "markdown": return new MarkdownExporter();
                case "pdf":      return new PdfExporter();
            }
        }

        // Fall back to file extension
        String lower = outputFile != null ? outputFile.toLowerCase() : "";
        if (lower.endsWith(".json")) {
            return new JsonExporter(objectMapper);
        } else if (lower.endsWith(".csv")) {
            return new CsvExporter();
        } else if (lower.endsWith(".html") || lower.endsWith(".htm")) {
            return new HtmlExporter();
        } else if (lower.endsWith(".xml")) {
            return new XmlExporter();
        } else if (lower.endsWith(".nmap")) {
            return new NmapXmlExporter();
        } else if (lower.endsWith(".md")) {
            return new MarkdownExporter();
        } else if (lower.endsWith(".pdf")) {
            return new PdfExporter();
        } else {
            return new TextExporter();
        }
    }
}
