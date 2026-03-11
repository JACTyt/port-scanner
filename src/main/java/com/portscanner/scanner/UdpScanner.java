package com.portscanner.scanner;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import com.portscanner.service.ServiceMapper;

import java.net.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * UDP port scanner using DatagramSocket.
 * Port states: CLOSED (ICMP port unreachable), OPEN_FILTERED (timeout = no response).
 * Note: ICMP reception may require elevated privileges on some OSes.
 */
public class UdpScanner {

    private final int threadCount;
    private final int timeoutMs;
    private final ServiceMapper serviceMapper;

    public UdpScanner(int threadCount, int timeoutMs, ServiceMapper serviceMapper) {
        this.threadCount = threadCount;
        this.timeoutMs = timeoutMs;
        this.serviceMapper = serviceMapper;
    }

    public ScanResult scanPort(String host, int port) {
        long start = System.currentTimeMillis();
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(timeoutMs);
            byte[] payload = new byte[0];
            InetAddress addr = InetAddress.getByName(host);
            DatagramPacket packet = new DatagramPacket(payload, payload.length, addr, port);
            socket.send(packet);

            // Try to receive — if ICMP port unreachable comes back, it throws PortUnreachableException
            byte[] buf = new byte[64];
            DatagramPacket response = new DatagramPacket(buf, buf.length);
            socket.receive(response);

            // Got a response → OPEN
            return ScanResult.builder()
                    .port(port)
                    .status(PortStatus.OPEN)
                    .serviceName(serviceMapper.getService(port))
                    .responseTimeMs(System.currentTimeMillis() - start)
                    .build();

        } catch (PortUnreachableException e) {
            return ScanResult.builder().port(port).status(PortStatus.CLOSED).build();
        } catch (SocketTimeoutException e) {
            // No response = OPEN|FILTERED (UDP ambiguity)
            return ScanResult.builder()
                    .port(port)
                    .status(PortStatus.OPEN_FILTERED)
                    .serviceName(serviceMapper.getService(port))
                    .build();
        } catch (Exception e) {
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
            final int p = port;
            futures.add(executor.submit(() -> {
                ScanResult result = scanPort(host, p);
                System.err.printf("\rUDP Scanning... %d/%d ports", scanned.incrementAndGet(), total);
                return result;
            }));
        }

        List<ScanResult> openPorts = new ArrayList<>();
        List<ScanResult> filteredPorts = new ArrayList<>();

        for (Future<ScanResult> future : futures) {
            try {
                ScanResult result = future.get(timeoutMs + 500L, TimeUnit.MILLISECONDS);
                if (result.getStatus() == PortStatus.OPEN || result.getStatus() == PortStatus.OPEN_FILTERED) {
                    openPorts.add(result);
                } else if (result.getStatus() == PortStatus.FILTERED) {
                    filteredPorts.add(result);
                }
            } catch (Exception e) {
                // skip
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
