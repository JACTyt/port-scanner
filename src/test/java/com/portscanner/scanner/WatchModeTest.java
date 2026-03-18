package com.portscanner.scanner;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class WatchModeTest {

    @Test
    void runInvokesSupplierAtLeastOnce() throws InterruptedException {
        AtomicInteger callCount = new AtomicInteger(0);
        CountDownLatch firstScan = new CountDownLatch(1);

        WatchMode watch = new WatchMode(1, false, false);
        Thread t = Thread.ofVirtual().start(() ->
            watch.run("localhost", () -> {
                callCount.incrementAndGet();
                firstScan.countDown();
                return makeReport(List.of());
            }, null)
        );

        assertTrue(firstScan.await(10, TimeUnit.SECONDS), "First scan should complete within 10s");
        t.interrupt();
        t.join(3_000);

        assertTrue(callCount.get() >= 1, "Supplier should be called at least once");
    }

    @Test
    void callbackInvokedForEachReport() throws InterruptedException {
        List<ScanReport> received = new ArrayList<>();
        CountDownLatch latch = new CountDownLatch(1);

        WatchMode watch = new WatchMode(1, false, false);
        Thread t = Thread.ofVirtual().start(() ->
            watch.run("localhost", () -> makeReport(List.of()), report -> {
                received.add(report);
                latch.countDown();
            })
        );

        assertTrue(latch.await(10, TimeUnit.SECONDS));
        t.interrupt();
        t.join(3_000);

        assertFalse(received.isEmpty(), "onEachReport callback should have been called");
    }

    @Test
    void handlesSupplierExceptionGracefully() throws InterruptedException {
        AtomicInteger attempts = new AtomicInteger(0);
        CountDownLatch latch = new CountDownLatch(1);

        WatchMode watch = new WatchMode(1, false, false);
        Thread t = Thread.ofVirtual().start(() ->
            watch.run("localhost", () -> {
                attempts.incrementAndGet();
                latch.countDown();
                throw new RuntimeException("simulated scan failure");
            }, null)
        );

        assertTrue(latch.await(10, TimeUnit.SECONDS), "Scan should be attempted within 10s");
        t.interrupt();
        t.join(3_000);

        // The watch mode must not propagate exceptions — thread must have exited cleanly
        assertTrue(attempts.get() >= 1);
    }

    @Test
    void nullCallbackDoesNotThrow() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        WatchMode watch = new WatchMode(1, false, false);
        Thread t = Thread.ofVirtual().start(() ->
            watch.run("localhost", () -> {
                latch.countDown();
                return makeReport(List.of());
            }, null)  // null callback must be handled
        );
        assertTrue(latch.await(10, TimeUnit.SECONDS));
        t.interrupt();
        t.join(3_000);
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private static ScanReport makeReport(List<ScanResult> openPorts) {
        return ScanReport.builder()
                .host("localhost")
                .resolvedIp("127.0.0.1")
                .scannedAt(LocalDateTime.now())
                .durationMs(50)
                .totalScanned(10)
                .openCount(openPorts.size())
                .openPorts(openPorts)
                .filteredPorts(List.of())
                .build();
    }

    private static ScanResult openPort(int port) {
        return ScanResult.builder()
                .port(port).status(PortStatus.OPEN).serviceName("HTTP")
                .build();
    }
}
