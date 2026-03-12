package com.portscanner.cli;

import com.portscanner.model.PortStatus;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Renders a live ANSI progress bar to stderr during scanning.
 * Disabled automatically when output is piped or --no-color is set.
 *
 * <pre>
 * [============>       ] 512/1024 (50%) | 12 OPEN | 341 p/s | ETA: 1s
 * </pre>
 */
public class ProgressReporter {

    private static final int BAR_WIDTH = 20;

    private final int totalPorts;
    private final boolean enabled;
    private final AtomicInteger scanned = new AtomicInteger(0);
    private final AtomicInteger openCount = new AtomicInteger(0);
    private final AtomicLong startTimeMs = new AtomicLong(0);

    private ScheduledExecutorService scheduler;
    private ScheduledFuture<?> tickTask;

    /**
     * @param totalPorts total number of ports being scanned
     * @param enabled    false → all methods are no-ops (piped output or --no-color)
     */
    public ProgressReporter(int totalPorts, boolean enabled) {
        this.totalPorts = totalPorts;
        this.enabled = enabled;
    }

    /**
     * Called by PortScanner after each port result is collected.
     */
    public void portScanned(PortStatus status) {
        if (!enabled) return;
        scanned.incrementAndGet();
        if (status == PortStatus.OPEN) openCount.incrementAndGet();
    }

    /**
     * Starts the background tick that redraws the progress bar every 100ms.
     */
    public void start() {
        if (!enabled) return;
        startTimeMs.set(System.currentTimeMillis());
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "progress-reporter");
            t.setDaemon(true);
            return t;
        });
        tickTask = scheduler.scheduleAtFixedRate(this::tick, 0, 100, TimeUnit.MILLISECONDS);
    }

    /**
     * Stops the scheduler and prints a final newline to leave the terminal clean.
     */
    public void stop() {
        if (!enabled) return;
        if (tickTask != null) tickTask.cancel(false);
        if (scheduler != null) {
            scheduler.shutdown();
            try { scheduler.awaitTermination(200, TimeUnit.MILLISECONDS); } catch (InterruptedException ignored) {}
        }
        tick(); // final render
        System.err.println(); // move to next line
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    private void tick() {
        int done = scanned.get();
        int open = openCount.get();
        long elapsed = System.currentTimeMillis() - startTimeMs.get();

        double rate = elapsed > 0 ? (done * 1000.0 / elapsed) : 0;
        int remaining = totalPorts - done;
        long etaSec = (rate > 0) ? (long) (remaining / rate) : 0;

        String bar = buildBar(done, totalPorts);
        int pct = totalPorts > 0 ? (done * 100 / totalPorts) : 0;

        String line = String.format("\r[%s] %d/%d (%d%%) | %d OPEN | %d p/s | ETA: %ds   ",
                bar, done, totalPorts, pct, open, (int) rate, etaSec);
        System.err.print(line);
    }

    private String buildBar(int done, int total) {
        if (total <= 0) return " ".repeat(BAR_WIDTH);
        int filled = (int) ((double) done / total * BAR_WIDTH);
        filled = Math.min(filled, BAR_WIDTH);

        StringBuilder sb = new StringBuilder(BAR_WIDTH);
        for (int i = 0; i < filled; i++) sb.append('=');
        if (filled < BAR_WIDTH) {
            sb.append('>');
            for (int i = filled + 1; i < BAR_WIDTH; i++) sb.append(' ');
        }
        return sb.toString();
    }
}
