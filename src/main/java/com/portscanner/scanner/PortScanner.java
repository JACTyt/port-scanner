package com.portscanner.scanner;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import com.portscanner.service.ServiceMapper;

import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class PortScanner {

    private final int threadCount;
    private final int timeoutMs;
    private final boolean grabBanner;
    private final ServiceMapper serviceMapper;
    private final BannerGrabber bannerGrabber;

    public PortScanner(int threadCount, int timeoutMs, boolean grabBanner, ServiceMapper serviceMapper) {
        this.threadCount = threadCount;
        this.timeoutMs = timeoutMs;
        this.grabBanner = grabBanner;
        this.serviceMapper = serviceMapper;
        this.bannerGrabber = new BannerGrabber();
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

        int poolSize = Math.min(threadCount, Math.max(1, ports.length));
        ExecutorService executor = Executors.newFixedThreadPool(poolSize);
        List<Future<ScanResult>> futures = new ArrayList<>(ports.length);
        AtomicInteger scanned = new AtomicInteger(0);
        int total = ports.length;

        for (int port : ports) {
            futures.add(executor.submit(() -> {
                ScanResult result = scanPort(host, port);
                System.err.printf("\rScanning... %d/%d ports", scanned.incrementAndGet(), total);
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
                // Skip futures that timed out or were interrupted
            }
        }

        System.err.println();
        executor.shutdown();

        long durationMs = System.currentTimeMillis() - startTime;

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
