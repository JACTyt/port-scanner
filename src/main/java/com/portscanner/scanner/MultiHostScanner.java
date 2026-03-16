package com.portscanner.scanner;

import com.portscanner.model.MultiHostReport;
import com.portscanner.model.ScanReport;
import com.portscanner.model.SubnetReport;
import com.portscanner.service.ServiceMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Scans multiple hosts read from a file (one host or CIDR per line).
 *
 * <p>File format:
 * <pre>
 * # comment lines and blank lines are ignored
 * 192.168.1.10
 * webserver.internal
 * 10.0.0.0/24   # CIDR ranges are supported
 * </pre>
 *
 * <p>Up to {@code hostParallelism} hosts are scanned concurrently.
 * Each individual host scan uses the configured thread count.
 */
public class MultiHostScanner {

    private static final Logger log = LoggerFactory.getLogger(MultiHostScanner.class);

    private final int threads;
    private final int timeoutMs;
    private final boolean grabBanner;
    private final ServiceMapper serviceMapper;
    private final boolean useProbes;

    public MultiHostScanner(int threads, int timeoutMs, boolean grabBanner,
                            ServiceMapper serviceMapper, boolean useProbes) {
        this.threads = threads;
        this.timeoutMs = timeoutMs;
        this.grabBanner = grabBanner;
        this.serviceMapper = serviceMapper;
        this.useProbes = useProbes;
    }

    /**
     * Reads hosts from {@code hostsFile} and scans them.
     *
     * @param hostsFile      path to the hosts file
     * @param ports          ports to scan on each host
     * @param hostParallelism max concurrent host scans
     * @return aggregated report
     */
    public MultiHostReport scan(Path hostsFile, int[] ports, int hostParallelism) throws IOException {
        List<String> entries = parseHostsFile(hostsFile);

        if (entries.isEmpty()) {
            System.err.println("Warning: hosts file is empty or contains no valid entries.");
            return MultiHostReport.builder()
                    .scannedAt(LocalDateTime.now())
                    .durationMs(0).totalHosts(0).hostsWithOpenPorts(0)
                    .results(List.of())
                    .build();
        }

        int total = entries.size();
        System.out.printf("Multi-host scan: %d target(s), host-parallelism=%d%n", total, hostParallelism);

        LocalDateTime scannedAt = LocalDateTime.now();
        long start = System.currentTimeMillis();

        List<ScanReport> results = new CopyOnWriteArrayList<>();
        AtomicInteger completed = new AtomicInteger(0);
        AtomicInteger withOpen  = new AtomicInteger(0);

        ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
        Semaphore hostLimit = new Semaphore(Math.max(1, hostParallelism));
        List<Future<?>> futures = new ArrayList<>();

        for (String entry : entries) {
            futures.add(executor.submit(() -> {
                hostLimit.acquireUninterruptibly();
                int idx = completed.incrementAndGet();
                System.out.printf("[%d/%d] Scanning %s ...%n", idx, total, entry);
                try {
                    if (isCidr(entry)) {
                        CidrScanner cidrScanner = new CidrScanner(threads, timeoutMs, grabBanner, serviceMapper);
                        SubnetReport subnet = cidrScanner.scan(entry, ports);
                        if (subnet.getHostReports() != null) {
                            for (ScanReport r : subnet.getHostReports()) {
                                results.add(r);
                                if (r.getOpenCount() > 0) withOpen.incrementAndGet();
                            }
                        }
                        System.out.printf("[%d/%d] %s — %d hosts, %d with open ports%n",
                                idx, total, entry,
                                subnet.getHostsScanned(), subnet.getHostsWithOpenPorts());
                    } else {
                        InetAddress addr = InetAddress.getByName(entry);
                        PortScanner scanner = new PortScanner(threads, timeoutMs, grabBanner,
                                serviceMapper, useProbes, 0);
                        ScanReport report = scanner.scan(entry, addr, ports);
                        results.add(report);
                        if (report.getOpenCount() > 0) withOpen.incrementAndGet();
                        System.out.printf("[%d/%d] %s — %d open port(s)%n",
                                idx, total, entry, report.getOpenCount());
                    }
                } catch (Exception e) {
                    log.warn("Failed to scan {}: {}", entry, e.getMessage());
                    System.out.printf("[%d/%d] %s — ERROR: %s%n", idx, total, entry, e.getMessage());
                } finally {
                    hostLimit.release();
                }
                return null;
            }));
        }

        executor.shutdown();
        for (Future<?> f : futures) {
            try { f.get(); } catch (Exception ignored) {}
        }

        long durationMs = System.currentTimeMillis() - start;
        return MultiHostReport.builder()
                .scannedAt(scannedAt)
                .durationMs(durationMs)
                .totalHosts(total)
                .hostsWithOpenPorts(withOpen.get())
                .results(new ArrayList<>(results))
                .build();
    }

    /**
     * Parses a hosts file, stripping inline comments ({@code #}) and blank lines.
     */
    public static List<String> parseHostsFile(Path file) throws IOException {
        List<String> result = new ArrayList<>();
        for (String line : Files.readAllLines(file)) {
            int commentIdx = line.indexOf('#');
            String stripped = (commentIdx >= 0 ? line.substring(0, commentIdx) : line).strip();
            if (!stripped.isEmpty()) result.add(stripped);
        }
        return result;
    }

    /** Returns true if the entry looks like a CIDR range (contains '/'). */
    static boolean isCidr(String entry) {
        return entry.contains("/");
    }
}
