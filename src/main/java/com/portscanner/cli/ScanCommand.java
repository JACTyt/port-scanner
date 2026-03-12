package com.portscanner.cli;

import ch.qos.logback.classic.Level;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.portscanner.config.ConfigLoader;
import com.portscanner.config.ScannerConfig;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import com.portscanner.report.DiffReport;
import com.portscanner.report.ExporterFactory;
import com.portscanner.report.ReportDiffer;
import com.portscanner.report.ReportExporter;
import com.portscanner.scanner.CidrScanner;
import com.portscanner.scanner.HostDiscovery;
import com.portscanner.scanner.NioPortScanner;
import com.portscanner.scanner.PortScanner;
import com.portscanner.scanner.UdpScanner;
import com.portscanner.service.CveLookup;
import com.portscanner.service.ServiceMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.net.InetAddress;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.Callable;

@Command(
        name = "portscanner",
        mixinStandardHelpOptions = true,
        version = "2.0",
        description = "A fast multithreaded TCP/UDP port scanner. Only use on systems you own or have explicit authorization to scan."
)
public class ScanCommand implements Callable<Integer> {

    private static final Logger log = LoggerFactory.getLogger(ScanCommand.class);

    // ── Target ──────────────────────────────────────────────────────────────
    @Option(names = {"--host", "-h"}, description = "Target hostname or IP address")
    private String host;

    @Option(names = {"--subnet", "-s"}, description = "CIDR subnet to scan, e.g. 192.168.1.0/24")
    private String subnet;

    // ── Scan options ────────────────────────────────────────────────────────
    @Option(names = {"--ports", "-p"}, defaultValue = "1-1024",
            description = "Port range (e.g. 1-1024) or list (e.g. 80,443,8080). Default: 1-1024")
    private String portRange;

    @Option(names = {"--timeout", "-t"}, defaultValue = "200",
            description = "Connection timeout in milliseconds (50-5000). Default: 200")
    private int timeout;

    @Option(names = {"--threads"}, defaultValue = "100",
            description = "Thread pool size (max 200). Default: 100")
    private int threads;

    @Option(names = {"--protocol"}, defaultValue = "tcp",
            description = "Protocol to scan: tcp, udp, both. Default: tcp")
    private String protocol;

    @Option(names = {"--rate"}, defaultValue = "0",
            description = "Max packets per second (0 = unlimited, enables randomized port order). Default: 0")
    private int rate;

    @Option(names = {"--skip-discovery"}, description = "Skip host reachability check before scanning (useful when target blocks ICMP)")
    private boolean skipDiscovery;

    @Option(names = {"--use-nio"}, description = "Use NIO non-blocking scanner for higher throughput (disables banner grabbing)")
    private boolean useNio;

    // ── Service detection ───────────────────────────────────────────────────
    @Option(names = {"--banner"}, description = "Attempt banner grabbing on open ports")
    private boolean grabBanner;

    @Option(names = {"--probes"}, description = "Use protocol-specific probes for richer banner grabbing (requires --banner)")
    private boolean useProbes;

    @Option(names = {"--cve"}, description = "Lookup CVEs for detected services via NVD API (requires --banner, adds network latency)")
    private boolean lookupCves;

    // ── Output ──────────────────────────────────────────────────────────────
    @Option(names = {"--output", "-o"}, description = "Output file (.json, .csv, .txt, .html, .xml)")
    private String outputFile;

    @Option(names = {"--diff"}, description = "Compare current scan against a previous JSON report file")
    private String diffFile;

    @Option(names = {"--show-all"}, description = "Include closed/filtered ports in output. Not recommended for large ranges (adds thousands of lines)")
    private boolean showAll;

    @Option(names = {"--no-color"}, description = "Disable ANSI color output")
    private boolean noColor;

    @Option(names = {"--verbose", "-v"}, description = "Enable verbose/debug logging")
    private boolean verbose;

    @Override
    public Integer call() throws Exception {
        // ── Verbose / color setup ───────────────────────────────────────────
        if (noColor) System.setProperty("picocli.ansi", "false");
        if (verbose) {
            ch.qos.logback.classic.Logger root =
                    (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
            root.setLevel(Level.DEBUG);
        }

        // ── Load user config (CLI options override) ─────────────────────────
        ConfigLoader.createSampleIfAbsent();
        ScannerConfig config = ConfigLoader.load();
        if (timeout == 200 && config.getTimeout() != null)   timeout  = config.getTimeout();
        if (threads == 100 && config.getThreads() != null)   threads  = config.getThreads();
        if ("1-1024".equals(portRange) && config.getPorts() != null) portRange = config.getPorts();
        if (!grabBanner  && Boolean.TRUE.equals(config.getBanner()))  grabBanner  = true;
        if (!showAll     && Boolean.TRUE.equals(config.getShowAll())) showAll     = true;

        // ── Validate target: exactly one of --host / --subnet ───────────────
        if (host == null && subnet == null) {
            log.error("Must specify either --host or --subnet");
            System.err.println("Error: specify either --host <host> or --subnet <cidr>");
            return 2;
        }
        if (host != null && subnet != null) {
            log.error("Cannot specify both --host and --subnet");
            System.err.println("Error: --host and --subnet are mutually exclusive");
            return 2;
        }

        // ── Validate options ────────────────────────────────────────────────
        if (timeout < 50 || timeout > 5000) {
            log.error("--timeout must be between 50 and 5000 ms");
            System.err.println("Error: --timeout must be between 50 and 5000 ms");
            return 2;
        }
        if (threads < 1) {
            log.error("--threads must be at least 1");
            System.err.println("Error: --threads must be at least 1");
            return 2;
        }
        threads = Math.min(threads, 200);

        // ── Parse ports ─────────────────────────────────────────────────────
        int[] ports;
        try {
            ports = parsePorts(portRange);
        } catch (IllegalArgumentException e) {
            log.error("Invalid port range: {}", e.getMessage());
            System.err.println("Error: Invalid port range — " + e.getMessage());
            return 2;
        }

        // ── Configure Jackson ───────────────────────────────────────────────
        ObjectMapper objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        ServiceMapper serviceMapper = new ServiceMapper();

        // ── SUBNET mode ─────────────────────────────────────────────────────
        if (subnet != null) {
            // Ethical confirmation for non-local subnets
            String subnetBase = subnet.contains("/") ? subnet.split("/")[0] : subnet;
            InetAddress subnetAddr = InetAddress.getByName(subnetBase);
            boolean isLocalSubnet = subnetAddr.isLoopbackAddress() || subnetAddr.isSiteLocalAddress();
            if (!isLocalSubnet) {
                System.out.println("WARNING: You are about to scan a non-local subnet: " + subnet);
                System.out.println("Scanning systems without explicit written authorization may be illegal.");
                System.out.print("Do you have explicit authorization to scan this subnet? [yes/no]: ");
                Scanner inputScanner = new Scanner(System.in);
                String confirmation = inputScanner.nextLine().trim().toLowerCase();
                if (!confirmation.equals("yes")) {
                    System.out.println("Scan cancelled.");
                    return 0;
                }
            }

            System.out.println(color(String.format("@|bold,cyan Scanning subnet|@ @|green %s|@ — %d ports, %d threads, %dms timeout",
                    subnet, ports.length, threads, timeout)));
            CidrScanner cidrScanner = new CidrScanner(threads, timeout, grabBanner, serviceMapper);
            var subnetReport = cidrScanner.scan(subnet, ports);
            System.out.printf("%nSubnet scan complete in %.2f seconds — %d hosts scanned, %d with open ports%n",
                    subnetReport.getDurationMs() / 1000.0, subnetReport.getHostsScanned(), subnetReport.getHostsWithOpenPorts());
            subnetReport.getHostReports().forEach(r -> {
                System.out.printf("%n  Host: %s (%s) — %d open ports%n",
                        r.getHost(), r.getResolvedIp(), r.getOpenCount());
                r.getOpenPorts().forEach(p ->
                        System.out.printf("    %-6d %s%n", p.getPort(),
                                p.getServiceName() != null ? p.getServiceName() : "Unknown"));
            });
            return 0;
        }

        // ── HOST mode ───────────────────────────────────────────────────────
        InetAddress resolvedAddress;
        try {
            resolvedAddress = InetAddress.getByName(host);
        } catch (Exception e) {
            log.error("Cannot resolve host '{}'", host);
            System.err.println("Error: Cannot resolve host '" + host + "'");
            return 1;
        }

        // Ethical confirmation for non-localhost / non-LAN hosts
        boolean isLocalhost = resolvedAddress.isLoopbackAddress() || resolvedAddress.isSiteLocalAddress();
        if (!isLocalhost) {
            System.out.println("WARNING: You are about to scan a non-localhost host: "
                    + host + " (" + resolvedAddress.getHostAddress() + ")");
            System.out.println("Scanning systems without explicit written authorization may be illegal.");
            System.out.print("Do you have explicit authorization to scan this host? [yes/no]: ");
            Scanner inputScanner = new Scanner(System.in);
            String confirmation = inputScanner.nextLine().trim().toLowerCase();
            if (!confirmation.equals("yes")) {
                System.out.println("Scan cancelled.");
                return 0;
            }
        }

        // Host discovery check
        if (!skipDiscovery && !resolvedAddress.isLoopbackAddress()) {
            HostDiscovery discovery = new HostDiscovery(Math.min(timeout, 1000), threads);
            List<String> alive = discovery.discoverHosts(List.of(resolvedAddress.getHostAddress()));
            if (alive.isEmpty()) {
                System.out.println("Host appears unreachable (no response). Use --skip-discovery to scan anyway.");
                return 0;
            }
        }

        // Print scan header
        System.out.println(color(String.format(
                "@|bold,cyan Scanning|@ @|green %s|@ (@|yellow %s|@) — @|white %d|@ ports, @|white %d|@ threads, @|white %d|@ms timeout [%s]",
                host, resolvedAddress.getHostAddress(), ports.length, threads, timeout,
                protocol.toUpperCase())));
        log.info("Starting scan of {} ({}) — {} ports, protocol={}", host, resolvedAddress.getHostAddress(), ports.length, protocol);

        // ── Run TCP scan ────────────────────────────────────────────────────
        ScanReport report = null;
        if ("tcp".equalsIgnoreCase(protocol) || "both".equalsIgnoreCase(protocol)) {
            if (useNio) {
                System.out.println(color("@|cyan Using NIO non-blocking scanner (banner grabbing disabled).|@"));
                NioPortScanner nioScanner = new NioPortScanner(timeout, serviceMapper);
                report = nioScanner.scan(host, resolvedAddress, ports);
            } else {
                PortScanner scanner = new PortScanner(threads, timeout, grabBanner, serviceMapper, useProbes, rate);
                report = scanner.scan(host, resolvedAddress, ports);
            }
        }

        // ── Run UDP scan ────────────────────────────────────────────────────
        if ("udp".equalsIgnoreCase(protocol) || "both".equalsIgnoreCase(protocol)) {
            System.out.println(color("@|cyan Running UDP scan...|@"));
            UdpScanner udpScanner = new UdpScanner(threads, timeout, serviceMapper);
            ScanReport udpReport = udpScanner.scan(host, resolvedAddress, ports);
            if (report == null) {
                report = udpReport;
            } else {
                // Merge UDP results into TCP report
                List<ScanResult> merged = new ArrayList<>(report.getOpenPorts());
                merged.addAll(udpReport.getOpenPorts());
                report = report.toBuilder()
                        .openPorts(merged)
                        .openCount(merged.size())
                        .build();
            }
        }

        if (report == null) {
            System.err.println("Error: unknown protocol '" + protocol + "'. Use tcp, udp, or both.");
            return 2;
        }

        // ── CVE lookup ──────────────────────────────────────────────────────
        if (lookupCves && report.getOpenPorts() != null) {
            System.out.println("Looking up CVEs (NVD API — may be slow due to rate limits)...");
            CveLookup cveLookup = new CveLookup();
            for (ScanResult result : report.getOpenPorts()) {
                String keyword = cveLookup.extractKeyword(result.getServiceName(), result.getBanner());
                if (!keyword.isBlank()) {
                    List<String> cves = cveLookup.lookup(keyword);
                    if (!cves.isEmpty()) result.setCves(cves);
                }
            }
        }

        // ── Print summary ───────────────────────────────────────────────────
        printSummary(report, showAll);

        // ── Diff mode ───────────────────────────────────────────────────────
        if (diffFile != null) {
            try {
                ReportDiffer differ = new ReportDiffer();
                ScanReport previousReport = differ.loadReport(Path.of(diffFile));
                DiffReport diffReport = differ.diff(previousReport, report, diffFile,
                        outputFile != null ? outputFile : "<current>");
                differ.printDiff(diffReport);
            } catch (Exception e) {
                System.err.println("Warning: could not load diff file — " + e.getMessage());
            }
        }

        // ── Export to file ──────────────────────────────────────────────────
        if (outputFile != null) {
            ReportExporter exporter = ExporterFactory.getExporter(outputFile, objectMapper);
            exporter.export(report, Path.of(outputFile));
            System.out.println(color("@|green Report saved to:|@ " + outputFile));
        }

        return 0;
    }

    private void printSummary(ScanReport report, boolean showAll) {
        System.out.println(color(String.format(
                "%n@|bold,cyan Scan complete|@ in @|yellow %.2f|@ seconds — @|green %d open|@, @|yellow %d filtered|@ out of @|white %d|@ scanned%n",
                report.getDurationMs() / 1000.0, report.getOpenCount(), report.getFilteredCount(), report.getTotalScanned())));

        if (report.getOpenPorts() != null && !report.getOpenPorts().isEmpty()) {
            System.out.println(color(String.format("@|bold %-8s %-16s %-12s %s|@", "PORT", "SERVICE", "RESPONSE", "BANNER")));
            System.out.println("------------------------------------------------------------");
            report.getOpenPorts().forEach(r -> {
                System.out.println(color(String.format("@|green %-8d|@ %-16s @|yellow %-12s|@ %s",
                        r.getPort(),
                        r.getServiceName() != null ? r.getServiceName() : "Unknown",
                        r.getResponseTimeMs() + "ms",
                        r.getBanner() != null ? r.getBanner() : "-")));
                if (r.getCves() != null && !r.getCves().isEmpty()) {
                    System.out.println(color("         @|red CVEs: " + String.join(", ", r.getCves()) + "|@"));
                }
            });
        } else {
            System.out.println(color("@|yellow No open ports found.|@"));
        }

        if (showAll && report.getFilteredPorts() != null && !report.getFilteredPorts().isEmpty()) {
            System.out.println(color("\n@|bold Filtered ports:|@"));
            report.getFilteredPorts().forEach(r -> {
                System.out.println(color(String.format("@|yellow %-8d|@ %-16s @|yellow FILTERED|@",
                        r.getPort(),
                        r.getServiceName() != null ? r.getServiceName() : "Unknown")));
            });
        }
    }

    private String color(String markup) {
        return CommandLine.Help.Ansi.AUTO.string(markup);
    }

    private int[] parsePorts(String portRange) {
        if (portRange.contains("-") && !portRange.contains(",")) {
            String[] parts = portRange.split("-", 2);
            int start = Integer.parseInt(parts[0].trim());
            int end   = Integer.parseInt(parts[1].trim());
            if (start < 1 || end > 65535 || start > end) {
                throw new IllegalArgumentException("Range must be 1-65535 and start <= end");
            }
            int[] ports = new int[end - start + 1];
            for (int i = 0; i < ports.length; i++) ports[i] = start + i;
            return ports;
        } else if (portRange.contains(",")) {
            String[] parts = portRange.split(",");
            List<Integer> portList = new ArrayList<>();
            for (String p : parts) {
                int port = Integer.parseInt(p.trim());
                if (port < 1 || port > 65535) throw new IllegalArgumentException("Port out of range: " + port);
                portList.add(port);
            }
            return portList.stream().mapToInt(Integer::intValue).toArray();
        } else {
            int port = Integer.parseInt(portRange.trim());
            if (port < 1 || port > 65535) throw new IllegalArgumentException("Port out of range: " + port);
            return new int[]{port};
        }
    }
}
