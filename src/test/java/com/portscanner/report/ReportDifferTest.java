package com.portscanner.report;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ReportDifferTest {

    private final ReportDiffer differ = new ReportDiffer();

    private ScanResult open(int port, String service) {
        return ScanResult.builder()
                .port(port).status(PortStatus.OPEN).serviceName(service).responseTimeMs(10).build();
    }

    private ScanReport report(List<ScanResult> open) {
        return ScanReport.builder()
                .host("localhost").resolvedIp("127.0.0.1")
                .scannedAt(LocalDateTime.now()).durationMs(100)
                .totalScanned(1024)
                .openCount(open != null ? open.size() : 0)
                .filteredCount(0)
                .openPorts(open).filteredPorts(List.of())
                .build();
    }

    @Test
    void new_port_in_current_appears_in_newOpenPorts() {
        ScanReport prev = report(List.of(open(80, "HTTP")));
        ScanReport curr = report(List.of(open(80, "HTTP"), open(443, "HTTPS")));
        DiffReport diff = differ.diff(prev, curr, "prev.json", "curr.json");
        assertEquals(1, diff.getNewOpenPorts().size());
        assertEquals(443, diff.getNewOpenPorts().get(0).getPort());
    }

    @Test
    void port_missing_in_current_appears_in_closedPorts() {
        ScanReport prev = report(List.of(open(80, "HTTP"), open(22, "SSH")));
        ScanReport curr = report(List.of(open(80, "HTTP")));
        DiffReport diff = differ.diff(prev, curr, "prev.json", "curr.json");
        assertEquals(1, diff.getClosedPorts().size());
        assertEquals(22, diff.getClosedPorts().get(0).getPort());
    }

    @Test
    void port_in_both_scans_appears_in_unchanged() {
        ScanReport prev = report(List.of(open(80, "HTTP")));
        ScanReport curr = report(List.of(open(80, "HTTP")));
        DiffReport diff = differ.diff(prev, curr, "prev.json", "curr.json");
        assertEquals(1, diff.getUnchangedOpenPorts().size());
        assertEquals(0, diff.getNewOpenPorts().size());
        assertEquals(0, diff.getClosedPorts().size());
    }

    @Test
    void empty_previous_makes_all_current_ports_new() {
        ScanReport prev = report(List.of());
        ScanReport curr = report(List.of(open(80, "HTTP"), open(443, "HTTPS")));
        DiffReport diff = differ.diff(prev, curr, "prev.json", "curr.json");
        assertEquals(2, diff.getNewOpenPorts().size());
        assertEquals(0, diff.getUnchangedOpenPorts().size());
        assertEquals(0, diff.getClosedPorts().size());
    }

    @Test
    void null_openPorts_in_previous_handled_gracefully() {
        ScanReport prev = report(null);
        ScanReport curr = report(List.of(open(80, "HTTP")));
        DiffReport diff = differ.diff(prev, curr, "prev.json", "curr.json");
        assertEquals(1, diff.getNewOpenPorts().size());
        assertEquals(0, diff.getClosedPorts().size());
    }

    @Test
    void null_openPorts_in_current_handled_gracefully() {
        ScanReport prev = report(List.of(open(80, "HTTP")));
        ScanReport curr = report(null);
        DiffReport diff = differ.diff(prev, curr, "prev.json", "curr.json");
        assertEquals(0, diff.getNewOpenPorts().size());
        assertEquals(1, diff.getClosedPorts().size());
    }

    @Test
    void diff_metadata_is_set_correctly() {
        ScanReport prev = report(List.of());
        ScanReport curr = report(List.of());
        DiffReport diff = differ.diff(prev, curr, "old.json", "new.json");
        assertEquals("localhost", diff.getHost());
        assertEquals("old.json", diff.getPreviousFile());
        assertEquals("new.json", diff.getCurrentFile());
    }

    @Test
    void completely_different_ports_produces_all_new_and_all_closed() {
        ScanReport prev = report(List.of(open(21, "FTP"), open(23, "Telnet")));
        ScanReport curr = report(List.of(open(80, "HTTP"), open(443, "HTTPS")));
        DiffReport diff = differ.diff(prev, curr, "p", "c");
        assertEquals(2, diff.getNewOpenPorts().size());
        assertEquals(2, diff.getClosedPorts().size());
        assertEquals(0, diff.getUnchangedOpenPorts().size());
    }

    @Test
    void both_scans_empty_produces_empty_diff() {
        ScanReport prev = report(List.of());
        ScanReport curr = report(List.of());
        DiffReport diff = differ.diff(prev, curr, "p", "c");
        assertEquals(0, diff.getNewOpenPorts().size());
        assertEquals(0, diff.getClosedPorts().size());
        assertEquals(0, diff.getUnchangedOpenPorts().size());
    }
}
