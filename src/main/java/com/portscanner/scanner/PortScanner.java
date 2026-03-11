package com.portscanner.scanner;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import com.portscanner.service.ServiceMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class PortScanner {

    private static final Logger log = LoggerFactory.getLogger(PortScanner.class);

    private final int threadCount;
    private final int timeoutMs;
    private final boolean grabBanner;
    private final ServiceMapper serviceMapper;
    private final BannerGrabber bannerGrabber;
    private final RateLimiter rateLimiter;

    public PortScanner(int threadCount, int timeoutMs, boolean grabBanner, ServiceMapper serviceMapper) {
        this(threadCount, timeoutMs, grabBanner, serviceMapper, false, 0);
    }

    public PortScanner(int threadCount, int timeoutMs, boolean grabBanner, ServiceMapper serviceMapper, boolean useProbes, int ratePerSecond) {
        this.threadCount = threadCount;
        this.timeoutMs = timeoutMs;
        this.grabBanner = grabBanner;
        this.serviceMapper = serviceMapper;
        this.bannerGrabber = new BannerGrabber(useProbes);
        this.rateLimiter = ratePerSecond > 0 ? new RateLimiter(ratePerSecond) : null;
    }

    public ScanResult scanPort(String host, int port) {
        long start = System.currentTimeMillis();
        try (Socket socket = new Socket()) {
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
        LocalDateTime scannedAt = LocalDateTime.now();
        long startTime = System.currentTimeMillis();

        // Shuffle port order when rate limiting is active (stealth mode)
        List<Integer> portList = new ArrayList<>(ports.length);
        for (int p : ports) portList.add(p);
        if (rateLimiter != null) Collections.shuffle(portList);

        int poolSize = Math.min(threadCount, Math.max(1, portList.size()));
        ExecutorService executor = Executors.newFixedThreadPool(poolSize);
        List<Future<ScanResult>> futures = new ArrayList<>(portList.size());
        AtomicInteger scanned = new AtomicInteger(0);
        int total = portList.size();

        for (int port : portList) {
            if (rateLimiter != null) rateLimiter.acquire();
            futures.add(executor.submit(() -> {
                ScanResult result = scanPort(host, port);
                int count = scanned.incrementAndGet();
                if (count % 100 == 0 || count == total) {
                    log.debug("Scanning... {}/{} ports", count, total);
                }
                System.err.printf("\rScanning... %d/%d ports", count, total);
                return result;
            }));
        }

        List<ScanResult> openPorts = new ArrayList<>();
        List<ScanResult> filteredPorts = new ArrayList<>();

        for (Future<ScanResult> future : futures) {
            try {
                ScanResult result = future.get(timeoutMs + 500L, TimeUnit.MILLISECONDS);
                if (result.getStatus() == PortStatus.OPEN) {
                    openPorts.add(result);
                } else if (result.getStatus() == PortStatus.FILTERED) {
                    filteredPorts.add(result);
                }
            } catch (Exception e) {
                log.debug("Future timed out or interrupted: {}", e.getMessage());
            }
        }

        System.err.println();
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
