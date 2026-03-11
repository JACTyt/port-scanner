package com.portscanner.scanner;

import com.portscanner.model.ScanReport;
import com.portscanner.model.SubnetReport;
import com.portscanner.service.ServiceMapper;

import java.net.InetAddress;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Scans all hosts in a CIDR subnet (e.g., 192.168.1.0/24).
 * Performs host discovery first, then port scans alive hosts.
 */
public class CidrScanner {

    private final int threadCount;
    private final int timeoutMs;
    private final boolean grabBanner;
    private final ServiceMapper serviceMapper;

    public CidrScanner(int threadCount, int timeoutMs, boolean grabBanner, ServiceMapper serviceMapper) {
        this.threadCount = threadCount;
        this.timeoutMs = timeoutMs;
        this.grabBanner = grabBanner;
        this.serviceMapper = serviceMapper;
    }

    public SubnetReport scan(String cidr, int[] ports) throws Exception {
        LocalDateTime scannedAt = LocalDateTime.now();
        long startTime = System.currentTimeMillis();

        // Parse CIDR
        String[] parts = cidr.split("/");
        if (parts.length != 2) throw new IllegalArgumentException("Invalid CIDR notation: " + cidr);

        String networkIp = parts[0];
        int prefixLen = Integer.parseInt(parts[1]);
        if (prefixLen < 0 || prefixLen > 32) throw new IllegalArgumentException("Invalid prefix length: " + prefixLen);

        // Calculate host range
        byte[] networkBytes = InetAddress.getByName(networkIp).getAddress();
        int networkInt = toInt(networkBytes);
        int mask = prefixLen == 0 ? 0 : (0xFFFFFFFF << (32 - prefixLen));
        int hostBits = 32 - prefixLen;
        int hostCount = (int) Math.pow(2, hostBits) - 2; // exclude network + broadcast
        if (hostCount <= 0) hostCount = 1;

        List<String> allHosts = new ArrayList<>();
        for (int i = 1; i <= hostCount; i++) {
            int hostInt = (networkInt & mask) | i;
            allHosts.add(toIp(hostInt));
        }

        System.out.printf("Subnet %s: discovering %d hosts...%n", cidr, allHosts.size());

        // Discover alive hosts
        HostDiscovery discovery = new HostDiscovery(Math.min(timeoutMs, 1000), threadCount);
        List<String> aliveHosts = discovery.discoverHosts(allHosts);
        System.out.printf("Found %d alive hosts. Scanning ports...%n", aliveHosts.size());

        // Port scan each alive host
        List<ScanReport> hostReports = new ArrayList<>();
        int hostsWithOpen = 0;
        for (String ip : aliveHosts) {
            InetAddress addr = InetAddress.getByName(ip);
            PortScanner scanner = new PortScanner(threadCount, timeoutMs, grabBanner, serviceMapper);
            ScanReport report = scanner.scan(ip, addr, ports);
            hostReports.add(report);
            if (report.getOpenCount() > 0) hostsWithOpen++;
        }

        long durationMs = System.currentTimeMillis() - startTime;
        return SubnetReport.builder()
                .subnet(cidr)
                .scannedAt(scannedAt)
                .durationMs(durationMs)
                .hostsScanned(aliveHosts.size())
                .hostsWithOpenPorts(hostsWithOpen)
                .hostReports(hostReports)
                .build();
    }

    private int toInt(byte[] addr) {
        return ((addr[0] & 0xFF) << 24) | ((addr[1] & 0xFF) << 16) | ((addr[2] & 0xFF) << 8) | (addr[3] & 0xFF);
    }

    private String toIp(int addr) {
        return ((addr >> 24) & 0xFF) + "." + ((addr >> 16) & 0xFF) + "." + ((addr >> 8) & 0xFF) + "." + (addr & 0xFF);
    }
}
