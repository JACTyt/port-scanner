package com.portscanner.scanner;

import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import com.portscanner.report.DiffReport;
import com.portscanner.report.ReportDiffer;
import com.portscanner.db.ScanHistoryDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Continuously re-scans a host on a fixed interval, printing only diffs after the
 * first scan. Runs until Ctrl+C.
 *
 * <p>Usage:
 * <pre>
 *   WatchMode watch = new WatchMode(intervalMinutes, alertOnChange, saveHistory);
 *   watch.run(host, scanSupplier, onEachReport);
 * </pre>
 * {@code scanSupplier} is called once per interval and must return the fresh {@link ScanReport}.
 * {@code onEachReport} is an optional callback (may be null) invoked after each completed scan
 * — use it to persist or export the report from the caller's context.
 */
public class WatchMode {

    private static final Logger log = LoggerFactory.getLogger(WatchMode.class);
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final int intervalMinutes;
    private final boolean alertOnChange;
    private final boolean saveHistory;

    public WatchMode(int intervalMinutes, boolean alertOnChange, boolean saveHistory) {
        this.intervalMinutes = Math.max(1, intervalMinutes);
        this.alertOnChange   = alertOnChange;
        this.saveHistory     = saveHistory;
    }

    /**
     * Start the watch loop. Blocks until the process is interrupted (Ctrl+C).
     *
     * @param host         display name used in console output
     * @param scanSupplier called once per interval; must return a {@link ScanReport}
     * @param onEachReport optional consumer called with each report after diff printing
     *                     (pass {@code null} to skip)
     */
    public void run(String host, Supplier<ScanReport> scanSupplier, Consumer<ScanReport> onEachReport) {
        AtomicInteger scanCount  = new AtomicInteger(0);
        AtomicReference<ScanReport> previous = new AtomicReference<>(null);
        long startMs = System.currentTimeMillis();
        ReportDiffer differ = new ReportDiffer();

        // Summary on shutdown (Ctrl+C)
        Runtime.getRuntime().addShutdownHook(Thread.ofVirtual().unstarted(() -> {
            long elapsed = (System.currentTimeMillis() - startMs) / 1000;
            System.out.printf("%n[Watch] Stopped. %d scan(s) completed in %ds.%n",
                    scanCount.get(), elapsed);
        }));

        // Platform thread required — virtual threads are not suitable as ScheduledExecutorService pool threads
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "watch-scheduler");
            t.setDaemon(true); // daemon so JVM can exit on interrupt
            return t;
        });

        Runnable task = () -> {
            int n = scanCount.incrementAndGet();
            System.out.printf("%n[%s] Watch scan #%d — %s%n", LocalDateTime.now().format(TS), n, host);
            try {
                ScanReport report = scanSupplier.get();
                ScanReport prev   = previous.get();

                if (prev == null) {
                    // First scan: print full open port list
                    printFullSummary(report);
                } else {
                    DiffReport diff = differ.diff(prev, report, "previous", "current");
                    boolean hasChanges = !diff.getNewOpenPorts().isEmpty() || !diff.getClosedPorts().isEmpty();
                    if (!hasChanges) {
                        System.out.printf("[Watch] No changes — %d open port(s).%n", report.getOpenCount());
                    } else {
                        differ.printDiff(diff);
                        if (alertOnChange) {
                            System.out.printf("[Watch] !! ALERT: port change detected on %s%n", host);
                        }
                    }
                }

                previous.set(report);

                if (saveHistory) {
                    try {
                        new ScanHistoryDao().save(report);
                    } catch (Exception e) {
                        log.warn("Failed to save watch scan to history: {}", e.getMessage());
                    }
                }

                if (onEachReport != null) {
                    try {
                        onEachReport.accept(report);
                    } catch (Exception e) {
                        log.warn("onEachReport callback failed: {}", e.getMessage());
                    }
                }

            } catch (Exception e) {
                System.err.printf("[Watch] Scan #%d failed: %s%n", n, e.getMessage());
                log.error("Watch scan #{} failed", n, e);
            }
        };

        System.out.printf("[Watch] Monitoring %s — scanning every %d minute(s). Press Ctrl+C to stop.%n",
                host, intervalMinutes);
        scheduler.scheduleAtFixedRate(task, 0, intervalMinutes, TimeUnit.MINUTES);

        // Block the calling thread until interrupted (Ctrl+C or test thread interrupt)
        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            scheduler.shutdownNow();
        }
    }

    private static void printFullSummary(ScanReport report) {
        System.out.printf("[Watch] First scan complete — %d open port(s):%n", report.getOpenCount());
        if (report.getOpenPorts() != null) {
            for (ScanResult r : report.getOpenPorts()) {
                System.out.printf("  %-6d %s%n",
                        r.getPort(),
                        r.getServiceName() != null ? r.getServiceName() : "Unknown");
            }
        }
        if (report.getOpenCount() == 0) {
            System.out.println("  (none)");
        }
    }
}
