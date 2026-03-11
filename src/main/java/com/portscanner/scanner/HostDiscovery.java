package com.portscanner.scanner;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Tests reachability of hosts in parallel using InetAddress.isReachable().
 * Uses ICMP echo on Unix, TCP echo (port 7) on Windows.
 * May require elevated privileges for ICMP on Linux.
 */
public class HostDiscovery {

    private final int timeoutMs;
    private final int threadCount;

    public HostDiscovery(int timeoutMs, int threadCount) {
        this.timeoutMs = timeoutMs;
        this.threadCount = threadCount;
    }

    /**
     * Tests reachability of the given host IPs in parallel.
     * Returns the subset that responded.
     */
    public List<String> discoverHosts(List<String> hostIps) {
        if (hostIps.isEmpty()) return List.of();

        int poolSize = Math.min(threadCount, hostIps.size());
        ExecutorService executor = Executors.newFixedThreadPool(poolSize);
        List<Future<String>> futures = new ArrayList<>();
        AtomicInteger checked = new AtomicInteger(0);
        int total = hostIps.size();

        for (String ip : hostIps) {
            futures.add(executor.submit(() -> {
                System.err.printf("\rDiscovering hosts... %d/%d", checked.incrementAndGet(), total);
                try {
                    InetAddress addr = InetAddress.getByName(ip);
                    return addr.isReachable(timeoutMs) ? ip : null;
                } catch (Exception e) {
                    return null;
                }
            }));
        }

        List<String> alive = new ArrayList<>();
        for (Future<String> f : futures) {
            try {
                String result = f.get(timeoutMs + 500L, TimeUnit.MILLISECONDS);
                if (result != null) alive.add(result);
            } catch (Exception ignored) {}
        }
        System.err.println();
        executor.shutdown();
        return alive;
    }
}
