package com.portscanner.report;

import com.portscanner.model.ScanResult;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class DiffReport {
    private String host;
    private String previousFile;
    private String currentFile;
    private List<ScanResult> newOpenPorts;
    private List<ScanResult> closedPorts;
    private List<ScanResult> unchangedOpenPorts;
}
