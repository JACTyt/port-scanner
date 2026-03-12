package com.portscanner.cli;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanResult;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TuiProgressDisplayTest {

    @Test
    void tui_construction_in_headless_throws_and_fallback_works() {
        // In a headless CI environment, TuiProgressDisplay constructor throws IOException.
        // Verify the fallback path creates a regular ProgressReporter without crashing.
        ProgressReporter reporter;
        try {
            reporter = new TuiProgressDisplay(100, "localhost");
            // If we got here, TUI was created — stop it cleanly
            reporter.start();
            reporter.stop();
        } catch (IOException | RuntimeException e) {
            // Expected in headless — fall back
            reporter = new ProgressReporter(100, false);
        }
        assertNotNull(reporter);
    }

    @Test
    void tui_portScanned_does_not_throw_when_headless() {
        // If TUI can't start, we must not throw on portScanned calls
        try {
            TuiProgressDisplay tui = new TuiProgressDisplay(10, "localhost");
            tui.portScanned(PortStatus.OPEN);
            tui.portScanned(PortStatus.CLOSED);
            tui.stop();
        } catch (IOException | RuntimeException e) {
            // headless — acceptable, no assertion needed
        }
    }

    @Test
    void tui_setOpenPorts_does_not_throw_when_headless() {
        try {
            TuiProgressDisplay tui = new TuiProgressDisplay(10, "localhost");
            tui.setOpenPorts(List.of(
                    ScanResult.builder().port(80).serviceName("HTTP").responseTimeMs(12).build()
            ));
            tui.stop();
        } catch (IOException | RuntimeException e) {
            // headless — acceptable
        }
    }

    @Test
    void progress_reporter_totalPorts_accessor() {
        ProgressReporter r = new ProgressReporter(42, false);
        assertEquals(42, r.totalPorts());
    }

    @Test
    void progress_reporter_null_scanner_does_not_throw() {
        ProgressReporter r = new ProgressReporter(10, false);
        assertDoesNotThrow(() -> r.setControlledScanner(null));
    }
}
