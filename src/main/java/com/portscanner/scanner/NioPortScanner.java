package com.portscanner.scanner;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import com.portscanner.service.ServiceMapper;

import java.net.*;
import java.nio.channels.*;
import java.time.LocalDateTime;
import java.util.*;

/**
 * NIO-based port scanner using non-blocking SocketChannel + Selector.
 * Handles thousands of concurrent connection attempts without thread-per-port overhead.
 * Note: banner grabbing not supported in NIO mode.
 */
public class NioPortScanner {

    private static final int BATCH_SIZE = 1000;

    private final int timeoutMs;
    private final ServiceMapper serviceMapper;

    public NioPortScanner(int timeoutMs, ServiceMapper serviceMapper) {
        this.timeoutMs = timeoutMs;
        this.serviceMapper = serviceMapper;
    }

    public ScanReport scan(String host, InetAddress resolvedAddress, int[] ports) {
        LocalDateTime scannedAt = LocalDateTime.now();
        long startTime = System.currentTimeMillis();

        List<ScanResult> openPorts = new ArrayList<>();
        List<ScanResult> filteredPorts = new ArrayList<>();
        int total = ports.length;
        int scanned = 0;

        for (int batchStart = 0; batchStart < ports.length; batchStart += BATCH_SIZE) {
            int batchEnd = Math.min(batchStart + BATCH_SIZE, ports.length);
            int[] batch = Arrays.copyOfRange(ports, batchStart, batchEnd);

            ScanBatch result = scanBatch(resolvedAddress, batch);
            openPorts.addAll(result.open);
            filteredPorts.addAll(result.filtered);
            scanned += batch.length;
            System.err.printf("\rScanning (NIO)... %d/%d ports", scanned, total);
        }
        System.err.println();

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

    private ScanBatch scanBatch(InetAddress resolvedAddress, int[] ports) {
        List<ScanResult> open = new ArrayList<>();
        List<ScanResult> filtered = new ArrayList<>();
        Map<SelectableChannel, PortAttempt> attempts = new HashMap<>();

        Selector selector;
        try {
            selector = Selector.open();
        } catch (Exception e) {
            for (int port : ports) {
                filtered.add(ScanResult.builder().port(port).status(PortStatus.FILTERED).build());
            }
            return new ScanBatch(open, filtered);
        }

        for (int port : ports) {
            try {
                SocketChannel channel = SocketChannel.open();
                channel.configureBlocking(false);
                channel.register(selector, SelectionKey.OP_CONNECT);
                channel.connect(new InetSocketAddress(resolvedAddress, port));
                attempts.put(channel, new PortAttempt(port, System.currentTimeMillis()));
            } catch (Exception e) {
                filtered.add(ScanResult.builder().port(port).status(PortStatus.ERROR).build());
            }
        }

        long deadline = System.currentTimeMillis() + timeoutMs + 200;

        while (!attempts.isEmpty() && System.currentTimeMillis() < deadline) {
            try {
                long remaining = deadline - System.currentTimeMillis();
                if (remaining <= 0) break;
                selector.select(Math.min(remaining, 100));
            } catch (Exception e) {
                break;
            }

            Iterator<SelectionKey> it = selector.selectedKeys().iterator();
            while (it.hasNext()) {
                SelectionKey key = it.next();
                it.remove();
                SocketChannel channel = (SocketChannel) key.channel();
                PortAttempt attempt = attempts.remove(channel);
                if (attempt == null) continue;

                try {
                    if (channel.finishConnect()) {
                        long responseTime = System.currentTimeMillis() - attempt.startTime;
                        open.add(ScanResult.builder()
                                .port(attempt.port)
                                .status(PortStatus.OPEN)
                                .serviceName(serviceMapper.getService(attempt.port))
                                .responseTimeMs(responseTime)
                                .build());
                    } else {
                        filtered.add(ScanResult.builder().port(attempt.port).status(PortStatus.FILTERED).build());
                    }
                } catch (ConnectException e) {
                    // Actively refused = CLOSED, skip
                } catch (Exception e) {
                    filtered.add(ScanResult.builder().port(attempt.port).status(PortStatus.FILTERED).build());
                } finally {
                    closeQuietly(channel);
                }
            }

            // Expire timed-out channels
            long now = System.currentTimeMillis();
            List<SelectableChannel> expired = new ArrayList<>();
            for (Map.Entry<SelectableChannel, PortAttempt> entry : attempts.entrySet()) {
                if (now - entry.getValue().startTime > timeoutMs) expired.add(entry.getKey());
            }
            for (SelectableChannel ch : expired) {
                PortAttempt attempt = attempts.remove(ch);
                filtered.add(ScanResult.builder().port(attempt.port).status(PortStatus.FILTERED).build());
                closeQuietly(ch);
            }
        }

        for (Map.Entry<SelectableChannel, PortAttempt> entry : attempts.entrySet()) {
            filtered.add(ScanResult.builder().port(entry.getValue().port).status(PortStatus.FILTERED).build());
            closeQuietly(entry.getKey());
        }

        try { selector.close(); } catch (Exception ignored) {}
        return new ScanBatch(open, filtered);
    }

    private void closeQuietly(SelectableChannel channel) {
        try { channel.close(); } catch (Exception ignored) {}
    }

    private static class PortAttempt {
        final int port;
        final long startTime;
        PortAttempt(int port, long startTime) { this.port = port; this.startTime = startTime; }
    }

    private static class ScanBatch {
        final List<ScanResult> open;
        final List<ScanResult> filtered;
        ScanBatch(List<ScanResult> open, List<ScanResult> filtered) { this.open = open; this.filtered = filtered; }
    }
}
