package com.portscanner.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Aggregated report produced by a {@code --hosts-file} multi-target scan.
 * Contains one {@link ScanReport} per individual host that was scanned
 * (CIDR ranges are expanded into per-host reports).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class MultiHostReport {

    private LocalDateTime scannedAt;
    private long durationMs;
    private int totalHosts;
    private int hostsWithOpenPorts;

    /** Per-host scan results, one entry per host (CIDR results are flattened). */
    private List<ScanReport> results;
}
