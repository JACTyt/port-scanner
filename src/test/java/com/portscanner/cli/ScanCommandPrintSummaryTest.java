package com.portscanner.cli;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for ScanCommand.printSummary() — verifies BUG-01 fix:
 * filtered ports are shown only when showAll=true.
 */
class ScanCommandPrintSummaryTest {

    private final PrintStream originalOut = System.out;
    private ByteArrayOutputStream captured;

    @BeforeEach
    void redirectStdout() {
        captured = new ByteArrayOutputStream();
        System.setOut(new PrintStream(captured));
        // Disable ANSI so output is plain text, easier to assert
        System.setProperty("picocli.ansi", "false");
    }

    @AfterEach
    void restoreStdout() {
        System.setOut(originalOut);
        System.clearProperty("picocli.ansi");
    }

    // ── helpers ────────────────────────────────────────────────────────────

    private void invokePrintSummary(ScanReport report, boolean showAll) throws Exception {
        ScanCommand cmd = new ScanCommand();
        Method m = ScanCommand.class.getDeclaredMethod("printSummary", ScanReport.class, boolean.class);
        m.setAccessible(true);
        m.invoke(cmd, report, showAll);
    }

    private ScanReport buildReport(List<ScanResult> open, List<ScanResult> filtered) {
        return ScanReport.builder()
                .host("localhost")
                .resolvedIp("127.0.0.1")
                .scannedAt(LocalDateTime.now())
                .durationMs(250)
                .totalScanned(open.size() + filtered.size())
                .openCount(open.size())
                .filteredCount(filtered.size())
                .openPorts(open)
                .filteredPorts(filtered)
                .build();
    }

    private ScanResult openResult(int port) {
        return ScanResult.builder()
                .port(port)
                .status(PortStatus.OPEN)
                .serviceName("HTTP")
                .responseTimeMs(5)
                .build();
    }

    private ScanResult filteredResult(int port) {
        return ScanResult.builder()
                .port(port)
                .status(PortStatus.FILTERED)
                .serviceName("Unknown")
                .responseTimeMs(200)
                .build();
    }

    // ── tests ──────────────────────────────────────────────────────────────

    @Test
    void showAll_false_does_not_print_filtered_ports() throws Exception {
        ScanReport report = buildReport(
                List.of(openResult(80)),
                List.of(filteredResult(8080), filteredResult(8443))
        );

        invokePrintSummary(report, false);

        String output = captured.toString();
        assertFalse(output.contains("8080"), "Port 8080 (filtered) should not appear when showAll=false");
        assertFalse(output.contains("8443"), "Port 8443 (filtered) should not appear when showAll=false");
        assertFalse(output.contains("FILTERED"), "FILTERED label should not appear when showAll=false");
    }

    @Test
    void showAll_true_prints_filtered_ports() throws Exception {
        ScanReport report = buildReport(
                List.of(openResult(80)),
                List.of(filteredResult(8080), filteredResult(8443))
        );

        invokePrintSummary(report, true);

        String output = captured.toString();
        assertTrue(output.contains("8080"), "Port 8080 (filtered) should appear when showAll=true");
        assertTrue(output.contains("8443"), "Port 8443 (filtered) should appear when showAll=true");
        assertTrue(output.contains("FILTERED"), "FILTERED label should appear when showAll=true");
    }

    @Test
    void showAll_true_still_prints_open_ports() throws Exception {
        ScanReport report = buildReport(
                List.of(openResult(80), openResult(443)),
                List.of(filteredResult(8080))
        );

        invokePrintSummary(report, true);

        String output = captured.toString();
        assertTrue(output.contains("80"), "Open port 80 must appear");
        assertTrue(output.contains("443"), "Open port 443 must appear");
    }

    @Test
    void showAll_true_with_no_filtered_ports_does_not_throw() throws Exception {
        ScanReport report = buildReport(List.of(openResult(22)), List.of());

        assertDoesNotThrow(() -> invokePrintSummary(report, true));
        String output = captured.toString();
        assertFalse(output.contains("FILTERED"));
    }

    @Test
    void showAll_false_with_no_open_ports_prints_no_open_message() throws Exception {
        ScanReport report = buildReport(List.of(), List.of(filteredResult(80)));

        invokePrintSummary(report, false);

        String output = captured.toString();
        assertTrue(output.contains("No open ports found"), "Should print 'no open ports' message");
        assertFalse(output.contains("80"), "Filtered port 80 should not appear when showAll=false");
    }
}
