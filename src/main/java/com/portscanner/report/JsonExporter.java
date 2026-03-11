package com.portscanner.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.portscanner.model.ScanReport;

import java.io.IOException;
import java.nio.file.Path;

public class JsonExporter implements ReportExporter {

    private final ObjectMapper objectMapper;

    public JsonExporter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void export(ScanReport report, Path outputPath) throws IOException {
        objectMapper.writerWithDefaultPrettyPrinter().writeValue(outputPath.toFile(), report);
    }
}
