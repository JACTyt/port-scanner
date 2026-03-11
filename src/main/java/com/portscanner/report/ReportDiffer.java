package com.portscanner.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

public class ReportDiffer {

    private final ObjectMapper objectMapper;

    public ReportDiffer() {
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    public ScanReport loadReport(Path path) throws IOException {
        return objectMapper.readValue(path.toFile(), ScanReport.class);
    }

    public DiffReport diff(ScanReport previous, ScanReport current, String previousFile, String currentFile) {
        Set<Integer> prevOpen = portSet(previous.getOpenPorts());
        Set<Integer> currOpen = portSet(current.getOpenPorts());
        Map<Integer, ScanResult> currMap = portMap(current.getOpenPorts());
        Map<Integer, ScanResult> prevMap = portMap(previous.getOpenPorts());

        List<ScanResult> newOpen = currOpen.stream()
                .filter(p -> !prevOpen.contains(p))
                .map(currMap::get).collect(Collectors.toList());

        List<ScanResult> closed = prevOpen.stream()
                .filter(p -> !currOpen.contains(p))
                .map(prevMap::get).collect(Collectors.toList());

        List<ScanResult> unchanged = currOpen.stream()
                .filter(prevOpen::contains)
                .map(currMap::get).collect(Collectors.toList());

        return DiffReport.builder()
                .host(current.getHost())
                .previousFile(previousFile)
                .currentFile(currentFile)
                .newOpenPorts(newOpen)
                .closedPorts(closed)
                .unchangedOpenPorts(unchanged)
                .build();
    }

    public void printDiff(DiffReport diff) {
        System.out.printf("%nDiff for host: %s%n", diff.getHost());
        System.out.printf("Previous: %s  →  Current: %s%n", diff.getPreviousFile(), diff.getCurrentFile());
        System.out.println("------------------------------------------------------------");

        System.out.printf("NEW OPEN (%d):%n", diff.getNewOpenPorts().size());
        diff.getNewOpenPorts().forEach(r ->
                System.out.printf("  + %-6d  %s%n", r.getPort(), nvl(r.getServiceName())));

        System.out.printf("CLOSED (%d):%n", diff.getClosedPorts().size());
        diff.getClosedPorts().forEach(r ->
                System.out.printf("  - %-6d  %s%n", r.getPort(), nvl(r.getServiceName())));

        System.out.printf("UNCHANGED (%d):%n", diff.getUnchangedOpenPorts().size());
        diff.getUnchangedOpenPorts().forEach(r ->
                System.out.printf("    %-6d  %s%n", r.getPort(), nvl(r.getServiceName())));
        System.out.println();
    }

    private Set<Integer> portSet(List<ScanResult> ports) {
        if (ports == null) return Set.of();
        return ports.stream().map(ScanResult::getPort).collect(Collectors.toSet());
    }

    private Map<Integer, ScanResult> portMap(List<ScanResult> ports) {
        if (ports == null) return Map.of();
        return ports.stream().collect(Collectors.toMap(ScanResult::getPort, r -> r));
    }

    private String nvl(String s) { return s != null ? s : "Unknown"; }
}
