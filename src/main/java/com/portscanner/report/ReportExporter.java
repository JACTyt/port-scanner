package com.portscanner.report;

import com.portscanner.model.ScanReport;

import java.io.IOException;
import java.nio.file.Path;

public interface ReportExporter {
    void export(ScanReport report, Path outputPath) throws IOException;
}
