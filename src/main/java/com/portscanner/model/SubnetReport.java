package com.portscanner.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SubnetReport {
    private String subnet;
    private LocalDateTime scannedAt;
    private long durationMs;
    private int hostsScanned;
    private int hostsWithOpenPorts;
    private List<ScanReport> hostReports;
}
