package com.portscanner.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class ExporterFactoryTest {

    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    @Test
    void json_extension_returns_JsonExporter() {
        assertInstanceOf(JsonExporter.class, ExporterFactory.getExporter("report.json", objectMapper));
    }

    @Test
    void csv_extension_returns_CsvExporter() {
        assertInstanceOf(CsvExporter.class, ExporterFactory.getExporter("report.csv", objectMapper));
    }

    @Test
    void html_extension_returns_HtmlExporter() {
        assertInstanceOf(HtmlExporter.class, ExporterFactory.getExporter("report.html", objectMapper));
    }

    @Test
    void htm_extension_returns_HtmlExporter() {
        assertInstanceOf(HtmlExporter.class, ExporterFactory.getExporter("report.htm", objectMapper));
    }

    @Test
    void xml_extension_returns_XmlExporter() {
        assertInstanceOf(XmlExporter.class, ExporterFactory.getExporter("report.xml", objectMapper));
    }

    @Test
    void txt_extension_returns_TextExporter() {
        assertInstanceOf(TextExporter.class, ExporterFactory.getExporter("report.txt", objectMapper));
    }

    @Test
    void no_extension_returns_TextExporter() {
        assertInstanceOf(TextExporter.class, ExporterFactory.getExporter("report", objectMapper));
    }

    @Test
    void extension_matching_is_case_insensitive() {
        assertInstanceOf(JsonExporter.class, ExporterFactory.getExporter("REPORT.JSON", objectMapper));
        assertInstanceOf(CsvExporter.class,  ExporterFactory.getExporter("REPORT.CSV",  objectMapper));
        assertInstanceOf(HtmlExporter.class, ExporterFactory.getExporter("REPORT.HTML", objectMapper));
        assertInstanceOf(XmlExporter.class,  ExporterFactory.getExporter("REPORT.XML",  objectMapper));
    }

    @Test
    void xlsx_byExtension() {
        assertInstanceOf(XlsxExporter.class,
            ExporterFactory.getExporter("report.xlsx", null, objectMapper));
    }

    @Test
    void xlsx_byFormat() {
        assertInstanceOf(XlsxExporter.class,
            ExporterFactory.getExporter(null, "xlsx", objectMapper));
    }
}
