package com.portscanner.cli;

import com.portscanner.model.PortStatus;
import com.portscanner.scanner.PortScanner;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.jline.utils.AttributedString;
import org.jline.utils.NonBlockingReader;
import org.jline.utils.Status;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Renders a live progress indicator during scanning.
 *
 * <ul>
 *   <li>When a real terminal is available: uses JLine3 for a persistent sticky status line at the
 *       bottom, with keyboard controls (P=pause, Q=quit, +/- thread count).</li>
 *   <li>Fallback (CI / piped output): uses a simple {@code \r} progress bar on stderr.</li>
 *   <li>When {@code enabled=false}: all methods are no-ops.</li>
 * </ul>
 *
 * <pre>
 * [============>       ] 512/1024 (50%) | 12 OPEN | 341 p/s | ETA: 1s  [P]ause [Q]uit [+/-] threads
 * </pre>
 */
public class ProgressReporter {

    private static final int BAR_WIDTH = 20;

    private final int totalPorts;
    private final boolean enabled;
    private final AtomicInteger scanned  = new AtomicInteger(0);
    private final AtomicInteger openCount = new AtomicInteger(0);
    private final AtomicLong startTimeMs = new AtomicLong(0);

    private ScheduledExecutorService scheduler;
    private ScheduledFuture<?> tickTask;

    // JLine3 components — null when unavailable
    private Terminal jlineTerminal;
    private Status   jlineStatus;
    private Thread   keyReaderThread;
    private volatile boolean jlinePaused = false;

    private final boolean useJLine;

    // Optional scanner reference for keyboard control
    private volatile PortScanner controlledScanner;

    /** Returns the total port count this reporter was constructed with. */
    protected int totalPorts() { return totalPorts; }

    /**
     * @param totalPorts total number of ports being scanned
     * @param enabled    false → all methods are no-ops (piped output or --no-color)
     */
    public ProgressReporter(int totalPorts, boolean enabled) {
        this.totalPorts = totalPorts;
        this.enabled = enabled;

        boolean jlineAvailable = false;
        if (enabled) {
            // Build the JLine3 terminal on a separate thread with a 2-second timeout.
            // TerminalBuilder.builder().system(true) can block indefinitely in Maven's
            // surefire environment (no real TTY attached), so we must guard against it.
            ExecutorService probe = Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "jline-probe");
                t.setDaemon(true);
                return t;
            });
            try {
                Future<Terminal> future = probe.submit(
                        () -> TerminalBuilder.builder().system(true).dumb(false).build());
                Terminal t = future.get(2, TimeUnit.SECONDS);
                Status s = Status.getStatus(t);
                if (s != null) {
                    this.jlineTerminal = t;
                    this.jlineStatus   = s;
                    jlineAvailable = true;
                } else {
                    t.close();
                }
            } catch (Exception ignored) {
                // No real terminal available — fall back to \r progress bar
            } finally {
                probe.shutdownNow();
            }
        }
        this.useJLine = jlineAvailable;
    }

    /**
     * Optionally link a PortScanner to enable keyboard-driven pause/resume/cancel/threads.
     * Must be called before {@link #start()}.
     */
    public void setControlledScanner(PortScanner scanner) {
        this.controlledScanner = scanner;
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
     * Starts the background tick that redraws the progress indicator every 100ms.
     * If a real terminal is available and a scanner is linked, also starts the key-reader thread.
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
        if (useJLine && controlledScanner != null) {
            startKeyReader();
        }
    }

    /**
     * Stops the scheduler and cleans up. Prints a final newline (or clears the status bar).
     */
    public void stop() {
        if (!enabled) return;
        if (keyReaderThread != null) keyReaderThread.interrupt();
        if (tickTask != null) tickTask.cancel(false);
        if (scheduler != null) {
            scheduler.shutdown();
            try { scheduler.awaitTermination(200, TimeUnit.MILLISECONDS); } catch (InterruptedException ignored) {}
        }
        tick(); // final render
        if (useJLine) {
            if (jlineStatus != null) {
                jlineStatus.update(List.of());
                jlineStatus.reset();
            }
            try {
                if (jlineTerminal != null) {
                    jlineTerminal.flush();
                    jlineTerminal.close();
                }
            } catch (IOException ignored) {}
        } else {
            System.err.println(); // move to next line after \r bar
        }
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    private void startKeyReader() {
        keyReaderThread = new Thread(() -> {
            NonBlockingReader reader = jlineTerminal.reader();
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    int ch = reader.read(100);
                    if (ch == NonBlockingReader.READ_EXPIRED) continue;
                    if (ch < 0) break;
                    switch (Character.toLowerCase((char) ch)) {
                        case 'p' -> {
                            if (jlinePaused) { controlledScanner.resume();  jlinePaused = false; }
                            else             { controlledScanner.pause();    jlinePaused = true;  }
                        }
                        case 'q' -> { controlledScanner.cancel(); return; }
                        case '+' -> controlledScanner.increaseThreads(10);
                        case '-' -> controlledScanner.decreaseThreads(10);
                    }
                } catch (IOException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }, "key-reader");
        keyReaderThread.setDaemon(true);
        keyReaderThread.start();
    }

    private void tick() {
        if (useJLine) {
            tickJLine();
        } else {
            tickSimple();
        }
    }

    private void tickJLine() {
        String statusText = buildStatusLine(true);
        if (jlineStatus != null) {
            jlineStatus.update(List.of(new AttributedString(statusText)));
            jlineTerminal.flush();
        }
    }

    private void tickSimple() {
        System.err.print("\r" + buildStatusLine(false) + "   ");
    }

    private String buildStatusLine(boolean withControls) {
        int done     = scanned.get();
        int open     = openCount.get();
        long elapsed = System.currentTimeMillis() - startTimeMs.get();

        double rate    = elapsed > 0 ? (done * 1000.0 / elapsed) : 0;
        int remaining  = totalPorts - done;
        long etaSec    = (rate > 0) ? (long) (remaining / rate) : 0;

        String bar = buildBar(done, totalPorts);
        int pct    = totalPorts > 0 ? (done * 100 / totalPorts) : 0;

        String controls = withControls ? "  [P]ause [Q]uit [+/-] threads" : "";
        return String.format("[%s] %d/%d (%d%%) | %d OPEN | %d p/s | ETA: %ds%s",
                bar, done, totalPorts, pct, open, (int) rate, etaSec, controls);
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
