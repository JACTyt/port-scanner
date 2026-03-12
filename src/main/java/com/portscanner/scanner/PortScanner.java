package com.portscanner.scanner;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import com.portscanner.service.ServiceMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.portscanner.cli.ProgressReporter;

import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class PortScanner {

    private static final Logger log = LoggerFactory.getLogger(PortScanner.class);

    private final int threadCount;
    private final int timeoutMs;
    private final boolean grabBanner;
    private final ServiceMapper serviceMapper;
    private final BannerGrabber bannerGrabber;
    private final RateLimiter rateLimiter;
    private final int ratePerSecond;
    private final Proxy proxy;
    private final Semaphore concurrencyLimit;
    private final AtomicBoolean paused    = new AtomicBoolean(false);
    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    public PortScanner(int threadCount, int timeoutMs, boolean grabBanner, ServiceMapper serviceMapper) {
        this(threadCount, timeoutMs, grabBanner, serviceMapper, false, 0, Proxy.NO_PROXY);
    }

    public PortScanner(int threadCount, int timeoutMs, boolean grabBanner, ServiceMapper serviceMapper, boolean useProbes, int ratePerSecond) {
        this(threadCount, timeoutMs, grabBanner, serviceMapper, useProbes, ratePerSecond, Proxy.NO_PROXY);
    }

    public PortScanner(int threadCount, int timeoutMs, boolean grabBanner, ServiceMapper serviceMapper, boolean useProbes, int ratePerSecond, Proxy proxy) {
        this.threadCount = threadCount;
        this.timeoutMs = timeoutMs;
        this.grabBanner = grabBanner;
        this.serviceMapper = serviceMapper;
        this.proxy = proxy != null ? proxy : Proxy.NO_PROXY;
        this.bannerGrabber = new BannerGrabber(useProbes, this.proxy);
        this.rateLimiter = ratePerSecond > 0 ? new RateLimiter(ratePerSecond) : null;
        this.ratePerSecond = ratePerSecond;
        this.concurrencyLimit = new Semaphore(Math.min(threadCount, 1000));
    }

    // ── Keyboard control methods (used by JLine3 ProgressReporter) ────────────

    /** Pauses scanning — each port task will spin-wait until resumed. */
    public void pause()  { paused.set(true); }

    /** Resumes a paused scan. */
    public void resume() { paused.set(false); }

    /** Cancels the scan — in-flight tasks return FILTERED immediately. */
    public void cancel() { cancelled.set(true); }

    /** Increases effective thread concurrency by releasing N extra semaphore permits. */
    public void increaseThreads(int n) { concurrencyLimit.release(n); }

    /** Decreases effective thread concurrency by quietly acquiring up to N permits. */
    public void decreaseThreads(int n) { concurrencyLimit.tryAcquire(n); }

    public ScanResult scanPort(String host, int port) {
        if (cancelled.get()) {
            return ScanResult.builder().port(port).status(PortStatus.FILTERED).responseTimeMs(0).build();
        }
        while (paused.get() && !cancelled.get()) {
            try { Thread.sleep(50); } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
        }
        long start = System.currentTimeMillis();
        try (Socket socket = new Socket(proxy)) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            long responseTime = System.currentTimeMillis() - start;

            String serviceName = serviceMapper.getService(port);
            String banner = grabBanner ? bannerGrabber.grabBanner(host, port, timeoutMs) : null;

            return ScanResult.builder()
                    .port(port)
                    .status(PortStatus.OPEN)
                    .serviceName(serviceName)
                    .banner(banner)
                    .responseTimeMs(responseTime)
                    .build();

        } catch (ConnectException e) {
            return ScanResult.builder().port(port).status(PortStatus.CLOSED).build();
        } catch (SocketTimeoutException e) {
            return ScanResult.builder().port(port).status(PortStatus.FILTERED).build();
        } catch (IOException e) {
            return ScanResult.builder().port(port).status(PortStatus.ERROR).build();
        }
    }

    public ScanReport scan(String host, InetAddress resolvedAddress, int[] ports) {
        return scan(host, resolvedAddress, ports, null);
    }

    public ScanReport scan(String host, InetAddress resolvedAddress, int[] ports, ProgressReporter reporter) {
        LocalDateTime scannedAt = LocalDateTime.now();
        long startTime = System.currentTimeMillis();

        // Shuffle port order when rate limiting is active (stealth mode)
        List<Integer> portList = new ArrayList<>(ports.length);
        for (int p : ports) portList.add(p);
        if (rateLimiter != null) Collections.shuffle(portList);

        ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
        int total = portList.size();

        long maxQueueDelayMs = 0L;
        if (rateLimiter != null && ratePerSecond > 0) {
            maxQueueDelayMs = Math.min((long) portList.size() * 1000L / ratePerSecond, 60_000L);
        }
        final long futureTimeout = timeoutMs + 500L + maxQueueDelayMs;

        // Submit all port scans as CompletableFutures (TASK-05)
        List<CompletableFuture<ScanResult>> futures = new ArrayList<>(portList.size());
        for (int port : portList) {
            if (rateLimiter != null) rateLimiter.acquire();
            futures.add(CompletableFuture
                .supplyAsync(() -> {
                    try {
                        concurrencyLimit.acquire();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new RuntimeException(e);
                    }
                    try {
                        return scanPort(host, port);
                    } finally {
                        concurrencyLimit.release();
                    }
                }, executor)
                .orTimeout(futureTimeout, TimeUnit.MILLISECONDS)
                .exceptionally(ex -> ScanResult.builder()
                    .port(port).status(PortStatus.FILTERED)
                    .responseTimeMs(timeoutMs).build()));
        }

        // Wait for all futures then collect results
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        List<ScanResult> openPorts = new ArrayList<>();
        List<ScanResult> filteredPorts = new ArrayList<>();

        for (CompletableFuture<ScanResult> future : futures) {
            ScanResult result = future.join();
            if (result.getStatus() == PortStatus.OPEN) {
                openPorts.add(result);
            } else if (result.getStatus() == PortStatus.FILTERED) {
                filteredPorts.add(result);
            }
            if (reporter != null) reporter.portScanned(result.getStatus());
        }

        executor.shutdown();

        long durationMs = System.currentTimeMillis() - startTime;
        log.info("Scan complete: {} ports scanned, {} open, {} filtered", total, openPorts.size(), filteredPorts.size());

        return ScanReport.builder()
                .host(host)
                .resolvedIp(resolvedAddress.getHostAddress())
                .scannedAt(scannedAt)
                .durationMs(durationMs)
                .totalScanned(total)
                .openCount(openPorts.size())
                .filteredCount(filteredPorts.size())
                .openPorts(openPorts)
                .filteredPorts(filteredPorts)
                .build();
    }
}
