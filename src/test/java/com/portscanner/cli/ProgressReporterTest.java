package com.portscanner.cli;

import com.portscanner.model.PortStatus;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for ProgressReporter — verifies TASK-04 behaviour:
 * disabled reporter is a no-op; enabled reporter tracks counts correctly.
 */
class ProgressReporterTest {

    // ── disabled (enabled=false) ──────────────────────────────────────────

    @Test
    void disabled_start_does_not_throw() {
        ProgressReporter r = new ProgressReporter(100, false);
        assertDoesNotThrow(r::start);
    }

    @Test
    void disabled_stop_does_not_throw() {
        ProgressReporter r = new ProgressReporter(100, false);
        assertDoesNotThrow(r::stop);
    }

    @Test
    void disabled_portScanned_does_not_throw() {
        ProgressReporter r = new ProgressReporter(100, false);
        assertDoesNotThrow(() -> {
            r.portScanned(PortStatus.OPEN);
            r.portScanned(PortStatus.CLOSED);
            r.portScanned(PortStatus.FILTERED);
        });
    }

    @Test
    void disabled_does_not_increment_counters() throws Exception {
        ProgressReporter r = new ProgressReporter(10, false);
        r.portScanned(PortStatus.OPEN);
        r.portScanned(PortStatus.OPEN);

        assertEquals(0, getScanned(r), "disabled reporter must not increment scanned counter");
        assertEquals(0, getOpenCount(r), "disabled reporter must not increment open counter");
    }

    // ── enabled ───────────────────────────────────────────────────────────

    @Test
    void enabled_portScanned_increments_scanned_counter() throws Exception {
        ProgressReporter r = new ProgressReporter(10, true);
        r.portScanned(PortStatus.CLOSED);
        r.portScanned(PortStatus.FILTERED);
        r.portScanned(PortStatus.OPEN);

        assertEquals(3, getScanned(r));
    }

    @Test
    void enabled_only_open_increments_open_counter() throws Exception {
        ProgressReporter r = new ProgressReporter(10, true);
        r.portScanned(PortStatus.OPEN);
        r.portScanned(PortStatus.OPEN);
        r.portScanned(PortStatus.CLOSED);
        r.portScanned(PortStatus.FILTERED);

        assertEquals(2, getOpenCount(r));
        assertEquals(4, getScanned(r));
    }

    @Test
    void enabled_start_and_stop_do_not_throw() {
        ProgressReporter r = new ProgressReporter(5, true);
        assertDoesNotThrow(() -> {
            r.start();
            r.portScanned(PortStatus.OPEN);
            r.stop();
        });
    }

    @Test
    void zero_total_ports_does_not_throw_on_start_stop() {
        ProgressReporter r = new ProgressReporter(0, true);
        assertDoesNotThrow(() -> {
            r.start();
            r.stop();
        });
    }

    // ── helpers ────────────────────────────────────────────────────────────

    private int getScanned(ProgressReporter r) throws Exception {
        Field f = ProgressReporter.class.getDeclaredField("scanned");
        f.setAccessible(true);
        return ((java.util.concurrent.atomic.AtomicInteger) f.get(r)).get();
    }

    private int getOpenCount(ProgressReporter r) throws Exception {
        Field f = ProgressReporter.class.getDeclaredField("openCount");
        f.setAccessible(true);
        return ((java.util.concurrent.atomic.AtomicInteger) f.get(r)).get();
    }
}
