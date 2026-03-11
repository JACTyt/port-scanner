package com.portscanner.report;

import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class CsvExporter implements ReportExporter {

    @Override
    public void export(ScanReport report, Path outputPath) throws IOException {
        try (PrintWriter writer = new PrintWriter(outputPath.toFile(), StandardCharsets.UTF_8)) {
            writer.println("PORT,STATUS,SERVICE,RESPONSE_MS,BANNER");

            List<ScanResult> all = new ArrayList<>();
            if (report.getOpenPorts() != null) all.addAll(report.getOpenPorts());
            if (report.getFilteredPorts() != null) all.addAll(report.getFilteredPorts());

            for (ScanResult r : all) {
                writer.printf("%d,%s,%s,%d,%s%n",
                        r.getPort(),
                        r.getStatus(),
                        r.getServiceName() != null ? r.getServiceName() : "",
                        r.getResponseTimeMs(),
                        escapeCsv(r.getBanner()));
            }
        }
    }

    private String escapeCsv(String value) {
        if (value == null) return "";
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }
}
