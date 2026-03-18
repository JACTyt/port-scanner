package com.portscanner.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;


@Data
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScanReport {
    private String host;
    private String resolvedIp;
    private LocalDateTime scannedAt;
    private long durationMs;
    private int totalScanned;
    private int openCount;
    private int filteredCount;
    private List<ScanResult> openPorts;
    private List<ScanResult> filteredPorts;
    private AsnInfo asnInfo;
    private ThreatInfo threatInfo;
    private GeoLocation geoLocation;
    private List<TracerouteHop> tracerouteHops;
    private List<SubdomainResult> subdomains;
    private OsGuess osGuess;
}
