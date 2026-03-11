package com.portscanner.report;

import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.portscanner.model.ScanReport;

import java.io.IOException;
import java.nio.file.Path;

public class XmlExporter implements ReportExporter {

    @Override
    public void export(ScanReport report, Path outputPath) throws IOException {
        XmlMapper xmlMapper = new XmlMapper();
        xmlMapper.registerModule(new JavaTimeModule());
        xmlMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        xmlMapper.enable(SerializationFeature.INDENT_OUTPUT);
        xmlMapper.writerWithDefaultPrettyPrinter().writeValue(outputPath.toFile(), report);
    }
}
