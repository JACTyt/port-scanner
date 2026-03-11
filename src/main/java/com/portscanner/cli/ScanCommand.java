package com.portscanner.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.portscanner.model.ScanReport;
import com.portscanner.report.ExporterFactory;
import com.portscanner.report.ReportExporter;
import com.portscanner.scanner.PortScanner;
import com.portscanner.service.ServiceMapper;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.net.InetAddress;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.Callable;

@Command(
        name = "portscanner",
        mixinStandardHelpOptions = true,
        version = "1.0",
        description = "A fast multithreaded TCP port scanner. Only use on systems you own or have explicit authorization to scan."
)
public class ScanCommand implements Callable<Integer> {

    @Option(names = {"--host", "-h"}, required = true, description = "Target hostname or IP address")
    private String host;

    @Option(names = {"--ports", "-p"}, defaultValue = "1-1024",
            description = "Port range (e.g. 1-1024) or list (e.g. 80,443,8080). Default: 1-1024")
    private String portRange;

    @Option(names = {"--timeout", "-t"}, defaultValue = "200",
            description = "Connection timeout in milliseconds (50-5000). Default: 200")
    private int timeout;

    @Option(names = {"--threads"}, defaultValue = "100",
            description = "Thread pool size (max 200). Default: 100")
    private int threads;

    @Option(names = {"--banner"}, description = "Attempt banner grabbing on open ports")
    private boolean grabBanner;

    @Option(names = {"--output", "-o"}, description = "Output file (.json, .csv, or .txt)")
    private String outputFile;

    @Option(names = {"--show-all"}, description = "Include closed ports in output (not recommended for large ranges)")
    private boolean showAll;

    @Override
    public Integer call() throws Exception {
        // Validate timeout
        if (timeout < 50 || timeout > 5000) {
            System.err.println("Error: --timeout must be between 50 and 5000 ms");
            return 2;
        }

        // Validate and cap thread count
        if (threads < 1) {
            System.err.println("Error: --threads must be at least 1");
            return 2;
        }
        threads = Math.min(threads, 200);

        // Resolve host
        InetAddress resolvedAddress;
        try {
            resolvedAddress = InetAddress.getByName(host);
        } catch (Exception e) {
            System.err.println("Error: Cannot resolve host '" + host + "'");
            return 1;
        }

        // Ethical confirmation for non-localhost hosts
        boolean isLocalhost = resolvedAddress.isLoopbackAddress() || resolvedAddress.isSiteLocalAddress();
        if (!isLocalhost) {
            System.out.println("WARNING: You are about to scan a non-localhost host: " + host + " (" + resolvedAddress.getHostAddress() + ")");
            System.out.println("Scanning systems without explicit written authorization may be illegal.");
            System.out.print("Do you have explicit authorization to scan this host? [yes/no]: ");
            Scanner inputScanner = new Scanner(System.in);
            String confirmation = inputScanner.nextLine().trim().toLowerCase();
            if (!confirmation.equals("yes")) {
                System.out.println("Scan cancelled.");
                return 0;
            }
        }

        // Parse port range
        int[] ports;
        try {
            ports = parsePorts(portRange);
        } catch (IllegalArgumentException e) {
            System.err.println("Error: Invalid port range — " + e.getMessage());
            return 2;
        }

        System.out.printf("Scanning %s (%s) — %d ports, %d threads, %dms timeout%n",
                host, resolvedAddress.getHostAddress(), ports.length, threads, timeout);

        // Configure Jackson
        ObjectMapper objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        // Run scan
        ServiceMapper serviceMapper = new ServiceMapper();
        PortScanner scanner = new PortScanner(threads, timeout, grabBanner, serviceMapper);
        ScanReport report = scanner.scan(host, resolvedAddress, ports);

        // Print summary to stdout
        printSummary(report);

        // Export to file if requested
        if (outputFile != null) {
            ReportExporter exporter = ExporterFactory.getExporter(outputFile, objectMapper);
            exporter.export(report, Path.of(outputFile));
            System.out.println("Report saved to: " + outputFile);
        }

        return 0;
    }

    private int[] parsePorts(String portRange) {
        if (portRange.contains("-") && !portRange.contains(",")) {
            // Range format: 1-1024
            String[] parts = portRange.split("-", 2);
            int start = Integer.parseInt(parts[0].trim());
            int end = Integer.parseInt(parts[1].trim());
            if (start < 1 || end > 65535 || start > end) {
                throw new IllegalArgumentException("Range must be 1-65535 and start <= end");
            }
            int[] ports = new int[end - start + 1];
            for (int i = 0; i < ports.length; i++) ports[i] = start + i;
            return ports;
        } else if (portRange.contains(",")) {
            // List format: 80,443,8080
            String[] parts = portRange.split(",");
            List<Integer> portList = new ArrayList<>();
            for (String p : parts) {
                int port = Integer.parseInt(p.trim());
                if (port < 1 || port > 65535) throw new IllegalArgumentException("Port out of range: " + port);
                portList.add(port);
            }
            return portList.stream().mapToInt(Integer::intValue).toArray();
        } else {
            // Single port
            int port = Integer.parseInt(portRange.trim());
            if (port < 1 || port > 65535) throw new IllegalArgumentException("Port out of range: " + port);
            return new int[]{port};
        }
    }

    private void printSummary(ScanReport report) {
        System.out.printf("%nScan complete in %.2f seconds — %d open, %d filtered out of %d scanned%n%n",
                report.getDurationMs() / 1000.0, report.getOpenCount(), report.getFilteredCount(), report.getTotalScanned());

        if (!report.getOpenPorts().isEmpty()) {
            System.out.printf("%-8s %-16s %-12s %s%n", "PORT", "SERVICE", "RESPONSE", "BANNER");
            System.out.println("------------------------------------------------------------");
            report.getOpenPorts().forEach(r ->
                    System.out.printf("%-8d %-16s %-12s %s%n",
                            r.getPort(),
                            r.getServiceName() != null ? r.getServiceName() : "Unknown",
                            r.getResponseTimeMs() + "ms",
                            r.getBanner() != null ? r.getBanner() : "-"));
        } else {
            System.out.println("No open ports found.");
        }
    }
}
