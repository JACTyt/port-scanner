package com.portscanner.report;

import com.fasterxml.jackson.databind.ObjectMapper;

public class ExporterFactory {

    public static ReportExporter getExporter(String outputFile, ObjectMapper objectMapper) {
        String lower = outputFile.toLowerCase();
        if (lower.endsWith(".json")) {
            return new JsonExporter(objectMapper);
        } else if (lower.endsWith(".csv")) {
            return new CsvExporter();
        } else if (lower.endsWith(".html") || lower.endsWith(".htm")) {
            return new HtmlExporter();
        } else if (lower.endsWith(".xml")) {
            return new XmlExporter();
        } else {
            return new TextExporter();
        }
    }
}
