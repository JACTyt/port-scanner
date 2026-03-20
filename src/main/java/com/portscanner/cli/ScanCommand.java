package com.portscanner.cli;

import ch.qos.logback.classic.Level;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.portscanner.config.ConfigLoader;
import com.portscanner.config.ProfileLoader;
import com.portscanner.config.ScanProfile;
import com.portscanner.config.ScannerConfig;
import com.portscanner.config.ScanTimingConfig;
import com.portscanner.config.TimingProfile;
import com.portscanner.db.ScanHistoryDao;
import com.portscanner.model.MultiHostReport;
import com.portscanner.scanner.MultiHostScanner;
import com.portscanner.plugin.PluginContext;
import com.portscanner.plugin.PluginRegistry;
import com.portscanner.plugin.ScanPlugin;
import com.portscanner.model.AsnInfo;
import com.portscanner.model.GeoLocation;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import com.portscanner.model.SubdomainResult;
import com.portscanner.model.ThreatInfo;
import com.portscanner.model.TracerouteHop;
import com.portscanner.scanner.Traceroute;
import com.portscanner.report.DiffReport;
import com.portscanner.report.ExporterFactory;
import com.portscanner.report.ReportDiffer;
import com.portscanner.report.ReportExporter;
import com.portscanner.api.ScanApiServer;
import com.portscanner.model.OsGuess;
import com.portscanner.report.TopologyExporter;
import com.portscanner.service.WebhookClient;
import com.portscanner.scanner.CidrScanner;
import com.portscanner.scanner.DnsBruteForcer;
import com.portscanner.scanner.HostDiscovery;
import com.portscanner.scanner.NetworkInterfaceScanner;
import com.portscanner.scanner.HttpInspector;
import com.portscanner.scanner.NioPortScanner;
import com.portscanner.scanner.OsFingerprinter;
import com.portscanner.scanner.PortScanner;
import com.portscanner.config.PolicyEvaluator;
import com.portscanner.config.PolicyLoader;
import com.portscanner.config.PolicyRule;
import com.portscanner.model.ShodanResult;
import com.portscanner.model.SubdomainResult;
import com.portscanner.report.JUnitXmlExporter;
import com.portscanner.report.SarifExporter;
import com.portscanner.scanner.HttpSecurityAuditor;
import com.portscanner.scanner.SnmpScanner;
import com.portscanner.scanner.SshAuditor;
import com.portscanner.scanner.TlsAuditor;
import com.portscanner.scanner.TlsInspector;
import com.portscanner.nuclei.NucleiRunner;
import com.portscanner.nuclei.NucleiTemplate;
import com.portscanner.nuclei.NucleiTemplateLoader;
import com.portscanner.model.NucleiResult;
import com.portscanner.service.CertTransparencyClient;
import com.portscanner.service.ShodanInternetDbClient;
import com.portscanner.scanner.TopPorts;
import com.portscanner.scanner.UdpScanner;
import com.portscanner.scanner.WatchMode;
import com.portscanner.service.AbuseIpDbClient;
import com.portscanner.service.AsnLookup;
import com.portscanner.service.CveLookup;
import com.portscanner.service.GreyNoiseClient;
import com.portscanner.service.IpInfoClient;
import com.portscanner.service.LocalCveDatabase;
import com.portscanner.service.ServiceMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Semaphore;
import java.util.stream.Collectors;

@Command(
        name = "portscanner",
        mixinStandardHelpOptions = true,
        version = "2.0",
        description = "A fast multithreaded TCP/UDP port scanner. Only use on systems you own or have explicit authorization to scan.",
        subcommands = {ScanCommand.UpdateDbCommand.class, HistoryCommand.class, ReplCommand.class}
)
public class ScanCommand implements Callable<Integer> {

    private static final Logger log = LoggerFactory.getLogger(ScanCommand.class);

    private static final Set<Integer> TLS_PORTS = Set.of(443, 8443, 465, 993, 995, 8444);
    private static final Set<Integer> HTTP_PORTS = Set.of(80, 443, 8080, 8443, 8888, 8000, 3000, 3001, 5000);

    // ── Target ──────────────────────────────────────────────────────────────
    @Option(names = {"--host", "-h"}, description = "Target hostname or IP address")
    private String host;

    @Option(names = {"--subnet", "-s"}, description = "CIDR subnet to scan, e.g. 192.168.1.0/24")
    private String subnet;

    @Option(names = "--auto-discover", description = "Scan all local network interfaces automatically (overrides --host and --subnet)")
    private boolean autoDiscover;

    // ── Scan options ────────────────────────────────────────────────────────
    @Option(names = {"--ports", "-p"}, defaultValue = "1-1024",
            description = "Port range (e.g. 1-1024) or list (e.g. 80,443,8080). Default: 1-1024")
    private String portRange;

    @Option(names = {"--timeout", "-t"}, defaultValue = "200",
            description = "Connection timeout in milliseconds (50-5000 for manual setting; timing profiles may set higher values). Default: 200")
    private int timeout;

    @Option(names = {"--threads"}, defaultValue = "100",
            description = "Max concurrent connections (max 1000, uses Java 21 virtual threads). Default: 100")
    private int threads;

    @Option(names = {"-T", "--timing"}, defaultValue = "NORMAL",
            description = "Timing profile: PARANOID(T0), SNEAKY(T1), POLITE(T2), NORMAL(T3), AGGRESSIVE(T4), INSANE(T5). Integer aliases T0-T5 accepted.")
    private String timingInput;

    @Option(names = {"--protocol"}, defaultValue = "tcp",
            description = "Protocol to scan: tcp, udp, both. Default: tcp")
    private String protocol;

    @Option(names = {"--rate"}, defaultValue = "0",
            description = "Max packets per second (0 = unlimited, enables randomized port order). Default: 0")
    private int rate;

    @Option(names = {"--skip-discovery"}, description = "Skip host reachability check before scanning (useful when target blocks ICMP)")
    private boolean skipDiscovery;

    @Option(names = {"--use-nio"}, description = "[Legacy] NIO non-blocking scanner — equivalent performance to default scanner with virtual threads. Disables banner grabbing.")
    private boolean useNio;

    // ── Service detection ───────────────────────────────────────────────────
    @Option(names = {"--banner"}, description = "Attempt banner grabbing on open ports")
    private boolean grabBanner;

    @Option(names = {"--probes"}, description = "Use protocol-specific probes for richer banner grabbing (requires --banner)")
    private boolean useProbes;

    @Option(names = {"--cve"}, description = "Lookup CVEs for detected services via NVD API (requires --banner, adds network latency)")
    private boolean lookupCves;

    @Option(names = {"--tls"}, description = "Inspect TLS/SSL certificates on open ports")
    private boolean tlsInspect;

    @Option(names = {"--http"}, description = "Analyze HTTP headers on web ports")
    private boolean httpInspect;

    // ── Enrichment ───────────────────────────────────────────────────────────
    @Option(names = {"--abuse-check"}, description = "Check IP reputation via AbuseIPDB (requires ABUSEIPDB_KEY env var or config)")
    private boolean abuseCheck;

    @Option(names = {"--greynoise"}, description = "Check IP via GreyNoise Community API (requires GREYNOISE_KEY env var or config)")
    private boolean greyNoise;

    @Option(names = {"--geolocate"}, description = "Geolocate the target IP via IPinfo.io (token optional via IPINFO_TOKEN env var)")
    private boolean geolocate;

    // ── Output ──────────────────────────────────────────────────────────────
    @Option(names = {"--top-ports"},
            description = "Scan N most commonly open ports in frequency order (overrides --ports). Max 1000.")
    private Integer topPorts;

    @Option(names = {"--output", "-o"}, description = "Output file (.json, .csv, .txt, .html, .xml, .nmap)")
    private String outputFile;

    @Option(names = {"--format"}, description = "Output format override: json, csv, txt, html, xml, nmap-xml")
    private String format;

    @Option(names = {"--diff"}, description = "Compare current scan against a previous JSON report file")
    private String diffFile;

    @Option(names = {"--show-all"}, description = "Include closed/filtered ports in output. Not recommended for large ranges (adds thousands of lines)")
    private boolean showAll;

    @Option(names = {"--no-color"}, description = "Disable ANSI color output")
    private boolean noColor;

    @Option(names = {"--verbose", "-v"}, description = "Enable verbose/debug logging")
    private boolean verbose;

    @Option(names = {"--proxy"}, description = "Route scans via SOCKS5 proxy, e.g. socks5://127.0.0.1:1080")
    private String proxy;

    // ── TUI / IPv6 / DNS ─────────────────────────────────────────────────────
    @Option(names = {"--tui"}, description = "Enable full-screen interactive TUI (requires a real terminal; falls back to progress bar automatically)")
    private boolean tui;

    @Option(names = {"--ipv6"}, description = "Prefer IPv6 addresses when resolving hostnames with both A and AAAA records")
    private boolean ipv6;

    @Option(names = {"--dns-brute"}, description = "DNS subdomain brute-force. Provide a wordlist path, or omit to use the bundled top-1000 list.")
    private String dnsBruteWordlist;

    @Option(names = {"--dns-brute-enable"}, description = "Enable DNS subdomain brute-force with the bundled top-1000 subdomain list")
    private boolean dnsBruteEnabled;

    // ── Traceroute ──────────────────────────────────────────────────────────
    @Option(names = "--traceroute", description = "Run traceroute after scanning")
    private boolean traceroute;

    @Option(names = "--traceroute-max-hops", defaultValue = "30",
            description = "Max hops for traceroute. Default: 30")
    private int tracerouteMaxHops;

    // ── Plugin/Script system ─────────────────────────────────────────────────
    @Option(names = "--scripts",
            description = "Comma-separated plugin names to run, or 'all'. E.g. --scripts http-title,ssl-cert")
    private String scripts;

    // ── Multi-host file mode ──────────────────────────────────────────────────
    @Option(names = "--hosts-file",
            description = "Scan multiple hosts from a file (one host or CIDR per line, # = comment). "
                    + "Mutually exclusive with --host, --subnet, --auto-discover.")
    private String hostsFile;

    @Option(names = "--host-parallelism", defaultValue = "4",
            description = "Max concurrent host scans when using --hosts-file. Default: 4")
    private int hostParallelism;

    // ── Scan history ──────────────────────────────────────────────────────────
    @Option(names = "--save-history",
            description = "Persist scan result to ~/.portscanner/history.db")
    private boolean saveHistory;

    @Option(names = "--history-diff",
            description = "Auto-diff current scan against the most recent entry for the same host "
                    + "in the history database. Requires at least one prior --save-history run.")
    private boolean historyDiff;

    // ── Scan profile ──────────────────────────────────────────────────────────
    @Option(names = "--profile",
            description = "Load a named scan profile: quick, web, db, full, stealth. "
                    + "Custom profiles can be defined in ~/.portscanner/profiles.yaml. "
                    + "CLI flags always override profile defaults.")
    private String profile;

    // ── REST API server mode ───────────────────────────────────────────────────
    @Option(names = "--serve",
            description = "Start an embedded REST API server instead of running a one-off scan")
    private boolean serve;

    @Option(names = "--serve-port", defaultValue = "8080",
            description = "Port for the REST API server. Default: 8080")
    private int servePort;

    @Option(names = "--serve-auth",
            description = "Require X-API-Key header on all API requests (set to your chosen key)")
    private String serveAuth;

    // ── Watch / scheduled mode ─────────────────────────────────────────────────
    @Option(names = "--watch",
            description = "Re-scan the target repeatedly, printing only diffs. Runs until Ctrl+C.")
    private boolean watch;

    @Option(names = "--watch-interval", defaultValue = "60",
            description = "Minutes between scans in watch mode. Default: 60")
    private int watchInterval;

    @Option(names = "--watch-alert",
            description = "Print an alert line whenever a port opens or closes in watch mode")
    private boolean watchAlert;

    // ── OS / TTL fingerprinting ────────────────────────────────────────────────
    @Option(names = "--os",
            description = "Attempt OS fingerprinting via TTL heuristics and banner analysis (adds latency)")
    private boolean osDetect;

    // ── Webhook / notification ─────────────────────────────────────────────────
    @Option(names = "--webhook",
            description = "POST scan summary JSON to this URL on completion. Slack/Discord URLs auto-detected.")
    private String webhook;

    @Option(names = "--webhook-on-open-only",
            description = "Only POST the webhook if at least one open port was found")
    private boolean webhookOnOpenOnly;

    // ── Topology visualization ─────────────────────────────────────────────────
    @Option(names = "--topology-output",
            description = "Write a network topology diagram to file. Extension selects format: .dot (Graphviz) or .mmd (Mermaid)")
    private String topologyOutput;

    // ── SNMP scanning ──────────────────────────────────────────────────────────
    @Option(names = "--snmp",
            description = "Probe open UDP 161 for SNMP after TCP scan completes")
    private boolean snmp;

    @Option(names = "--snmp-community", defaultValue = "public,private",
            description = "Comma-separated SNMP community strings to try. Default: public,private")
    private String snmpCommunity;

    // ── Shodan InternetDB enrichment ────────────────────────────────────────
    @Option(names = "--shodan",
            description = "Enrich results with Shodan InternetDB data (free, no API key required)")
    private boolean shodan;

    // ── CI / Policy gates ───────────────────────────────────────────────────
    @Option(names = "--fail-on-open",
            description = "Exit code 1 if any of these comma-separated ports are found open (e.g. 23,3389)")
    private String failOnOpen;

    @Option(names = "--policy-file",
            description = "YAML policy file with rules evaluated post-scan. Overrides --fail-on-open.")
    private String policyFile;

    // ── P2: Deep protocol auditing ──────────────────────────────────────────
    @Option(names = "--tls-deep",
            description = "Full TLS audit: enumerate cipher suites and detect known vulnerabilities "
                    + "(BEAST, POODLE, SWEET32, Heartbleed, RC4, NULL ciphers). Implies --tls. Adds latency.")
    private boolean tlsDeep;

    @Option(names = "--ssh-audit",
            description = "Parse SSH Key Exchange Init and flag weak algorithms (kex, ciphers, MACs). "
                    + "Runs automatically on any open SSH port when specified.")
    private boolean sshAudit;

    @Option(names = "--ct-recon",
            description = "Query Certificate Transparency logs (crt.sh) for subdomains of the given domain. "
                    + "Discovered subdomains are displayed and stored in the report. Example: --ct-recon example.com")
    private String ctRecon;

    // ── P3: Unauthenticated service detection ────────────────────────────────
    @Option(names = "--unauth-detect",
            description = "Probe open ports for unauthenticated service access "
                    + "(Redis, Memcached, Elasticsearch, FTP anon, Prometheus, Spring Actuator).")
    private boolean unauthDetect;

    // ── P3: DNS security audit ───────────────────────────────────────────────
    @Option(names = "--dns-audit",
            description = "Run DNS security audit on the target: AXFR zone transfer, open resolver, DNSSEC, TCP-53. "
                    + "Optionally supply a domain with --dns-domain.")
    private boolean dnsAudit;

    @Option(names = "--dns-domain",
            description = "Domain name to use for DNS audit zone-transfer and DNSSEC checks. "
                    + "If omitted, only open-resolver and TCP-53 tests run.")
    private String dnsDomain;

    // ── P4: Nuclei template loader ────────────────────────────────────────────
    @Option(names = "--nuclei-templates",
            description = "Path to a directory of Nuclei YAML templates. "
                    + "Runs matched templates against all open HTTP/HTTPS ports.")
    private String nucleiTemplatesPath;

    @Option(names = "--nuclei-tags",
            description = "Comma-separated severity tags to filter loaded templates, "
                    + "e.g. 'critical,high'. Default: run all templates.",
            split = ",")
    private List<String> nucleiTags;

    // ── P3: Two-phase scan pipeline ──────────────────────────────────────────
    @Option(names = "--quick",
            description = "Phase-1 fast scan: 1000 threads, 100 ms timeout, no banner/enrichment. "
                    + "Combine with --deep to automatically run full enrichment on discovered open ports.")
    private boolean quickScan;

    @Option(names = "--deep",
            description = "Phase-2 deep enrichment on open ports (banner, TLS, CVE, unauth-detect, etc.). "
                    + "When combined with --quick, runs after the fast phase automatically.")
    private boolean deepScan;

    // ── P3: CVSS failure threshold ───────────────────────────────────────────
    @Option(names = "--fail-on-cvss",
            description = "Exit with code 2 if any CVE with a CVSS score >= this threshold is found. "
                    + "Requires --cve. Example: --fail-on-cvss 7.0")
    private Double failOnCvss;

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
        boolean userSetTimeout = (timeout != 200);
        boolean userSetThreads = (threads != 100);
        if (!userSetTimeout && config.getTimeout() != null)   timeout  = config.getTimeout();
        if (!userSetThreads && config.getThreads() != null)   threads  = config.getThreads();
        if ("1-1024".equals(portRange) && config.getPorts() != null) portRange = config.getPorts();
        if (!grabBanner  && Boolean.TRUE.equals(config.getBanner()))  grabBanner  = true;
        if (!showAll     && Boolean.TRUE.equals(config.getShowAll())) showAll     = true;

        // ── Apply scan profile (sets defaults; CLI flags override) ──────────────
        if (profile != null) {
            ScanProfile scanProfile = ProfileLoader.load(profile).orElseGet(() -> {
                System.err.println("Warning: unknown profile '" + profile
                        + "'. Available: " + String.join(", ", ProfileLoader.listAll()));
                return new ScanProfile();
            });
            if (scanProfile.getPorts() != null && "1-1024".equals(portRange))            portRange   = scanProfile.getPorts();
            if (scanProfile.getTopPorts() != null && topPorts == null)                   topPorts    = scanProfile.getTopPorts();
            if (scanProfile.getBanner() != null && !grabBanner)                          grabBanner  = scanProfile.getBanner();
            if (scanProfile.getProbes() != null && !useProbes)                           useProbes   = scanProfile.getProbes();
            if (scanProfile.getTls() != null && !tlsInspect)                             tlsInspect  = scanProfile.getTls();
            if (scanProfile.getHttp() != null && !httpInspect)                           httpInspect = scanProfile.getHttp();
            if (scanProfile.getGeolocate() != null && !geolocate)                        geolocate   = scanProfile.getGeolocate();
            if (scanProfile.getTiming() != null && "NORMAL".equalsIgnoreCase(timingInput)) timingInput = scanProfile.getTiming();
            if (scanProfile.getRate() != null && rate == 0)                              rate        = scanProfile.getRate();
        }

        // ── Apply timing profile (only for unset options) ───────────────────
        TimingProfile timingProfile = TimingProfile.fromString(timingInput);
        ScanTimingConfig timingConfig = ScanTimingConfig.forProfile(timingProfile);
        if (!userSetTimeout && config.getTimeout() == null) {
            timeout = (int) Math.min(timingConfig.connectTimeoutMs(), Integer.MAX_VALUE / 2);
        }
        if (!userSetThreads && config.getThreads() == null) {
            threads = timingConfig.maxParallelism();
        }
        log.debug("Timing profile: {} (timeout={}ms, threads={}, delay={}ms)",
                timingProfile, timeout, threads, timingConfig.scanDelayMs());

        // ── Parse proxy ─────────────────────────────────────────────────────
        Proxy proxyObj = Proxy.NO_PROXY;
        if (proxy != null) {
            String proxySpec = proxy;
            if (proxySpec.startsWith("socks5://")) {
                proxySpec = proxySpec.substring("socks5://".length());
            }
            String[] parts = proxySpec.split(":", 2);
            if (parts.length != 2) {
                System.err.println("Error: --proxy must be in host:port format (e.g. socks5://127.0.0.1:1080 or 127.0.0.1:1080)");
                return 2;
            }
            try {
                int proxyPort = Integer.parseInt(parts[1]);
                proxyObj = new Proxy(Proxy.Type.SOCKS,
                        new InetSocketAddress(parts[0], proxyPort));
            } catch (NumberFormatException e) {
                System.err.println("Error: --proxy port is not a valid integer");
                return 2;
            }
        }

        // ── REST API server mode ─────────────────────────────────────────────
        if (serve) {
            try {
                ScanApiServer apiServer = new ScanApiServer(servePort, serveAuth);
                System.out.println(color(String.format(
                        "@|bold,cyan REST API server started|@ on @|green http://localhost:%d|@%n"
                        + "  POST   /scan          – submit a scan job%n"
                        + "  GET    /scan/{id}     – get status + results%n"
                        + "  GET    /scan/{id}/stream – SSE live progress%n"
                        + "  GET    /scans         – list recent jobs%n"
                        + "  DELETE /scan/{id}     – cancel a job%n"
                        + (serveAuth != null ? "  Auth:  X-API-Key header required%n" : "  Auth:  none%n"),
                        servePort)));
                apiServer.start();
                // Block until Ctrl+C
                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    System.out.println("\nShutting down API server...");
                    apiServer.stop();
                }));
                Thread.currentThread().join();
            } catch (Exception e) {
                System.err.println("Error starting API server: " + e.getMessage());
                return 1;
            }
            return 0;
        }

        // ── Validate target: exactly one of --host / --subnet / --auto-discover / --hosts-file ─
        if (!autoDiscover && host == null && subnet == null && hostsFile == null) {
            log.error("Must specify either --host, --subnet, --auto-discover, or --hosts-file");
            System.err.println("Error: specify either --host <host>, --subnet <cidr>, --auto-discover, or --hosts-file <file>");
            return 2;
        }
        if (host != null && subnet != null) {
            log.error("Cannot specify both --host and --subnet");
            System.err.println("Error: --host and --subnet are mutually exclusive");
            return 2;
        }
        if (hostsFile != null && (host != null || subnet != null || autoDiscover)) {
            System.err.println("Error: --hosts-file is mutually exclusive with --host, --subnet, and --auto-discover");
            return 2;
        }

        // ── Validate options ────────────────────────────────────────────────
        if (timeout < 50) {
            log.error("--timeout must be at least 50 ms");
            System.err.println("Error: --timeout must be at least 50 ms");
            return 2;
        }
        if (userSetTimeout && timeout > 5000) {
            log.error("--timeout must be between 50 and 5000 ms (use -T profile for longer timeouts)");
            System.err.println("Error: --timeout must be between 50 and 5000 ms (use -T PARANOID etc. for longer timeouts)");
            return 2;
        }
        if (threads < 1) {
            log.error("--threads must be at least 1");
            System.err.println("Error: --threads must be at least 1");
            return 2;
        }
        threads = Math.min(threads, 1000);

        // ── Parse ports ─────────────────────────────────────────────────────
        if (topPorts != null && !"1-1024".equals(portRange)) {
            System.err.println("Error: --top-ports and --ports are mutually exclusive");
            return 2;
        }
        int[] ports;
        if (topPorts != null) {
            ports = TopPorts.get(topPorts);
            log.debug("Using top-{} ports", ports.length);
        } else {
            try {
                ports = parsePorts(portRange);
            } catch (IllegalArgumentException e) {
                log.error("Invalid port range: {}", e.getMessage());
                System.err.println("Error: Invalid port range — " + e.getMessage());
                return 2;
            }
        }

        // ── Configure Jackson ───────────────────────────────────────────────
        ObjectMapper objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        ServiceMapper serviceMapper = new ServiceMapper();

        // ── AUTO-DISCOVER mode ───────────────────────────────────────────────
        if (autoDiscover) {
            if (host != null || subnet != null) {
                System.err.println("Error: --auto-discover cannot be combined with --host or --subnet");
                return 2;
            }
            NetworkInterfaceScanner nis = new NetworkInterfaceScanner();
            List<String> discoveredSubnets = nis.discoverLocalSubnets();
            if (discoveredSubnets.isEmpty()) {
                System.err.println("No local network interfaces found.");
                return 1;
            }
            System.out.println("Discovered subnets: " + String.join(", ", discoveredSubnets));
            CidrScanner cidrScanner = new CidrScanner(threads, timeout, grabBanner, serviceMapper);
            for (String discoveredSubnet : discoveredSubnets) {
                System.out.println(color(String.format(
                        "@|bold,cyan Scanning subnet|@ @|green %s|@ — %d ports, %d threads, %dms timeout",
                        discoveredSubnet, ports.length, threads, timeout)));
                var subnetReport = cidrScanner.scan(discoveredSubnet, ports);
                System.out.printf("%nSubnet scan complete in %.2f seconds — %d hosts scanned, %d with open ports%n",
                        subnetReport.getDurationMs() / 1000.0, subnetReport.getHostsScanned(), subnetReport.getHostsWithOpenPorts());
                subnetReport.getHostReports().forEach(r -> {
                    System.out.printf("%n  Host: %s (%s) — %d open ports%n",
                            r.getHost(), r.getResolvedIp(), r.getOpenCount());
                    r.getOpenPorts().forEach(p ->
                            System.out.printf("    %-6d %s%n", p.getPort(),
                                    p.getServiceName() != null ? p.getServiceName() : "Unknown"));
                });
            }
            return 0;
        }

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
            if (topologyOutput != null) {
                try {
                    new TopologyExporter().export(subnetReport, Path.of(topologyOutput));
                    System.out.println(color("@|green Topology diagram saved to:|@ " + topologyOutput));
                } catch (Exception e) {
                    System.err.println("Warning: topology export failed — " + e.getMessage());
                }
            }
            return 0;
        }

        // ── HOSTS-FILE mode ─────────────────────────────────────────────────
        if (hostsFile != null) {
            Path hostsPath = Path.of(hostsFile);
            if (!hostsPath.toFile().exists()) {
                System.err.println("Error: hosts file not found: " + hostsFile);
                return 2;
            }
            System.out.println(color(String.format(
                    "@|bold,cyan Scanning hosts from file|@ @|green %s|@ — %d ports, %d threads, %dms timeout",
                    hostsFile, ports.length, threads, timeout)));
            MultiHostScanner multiScanner = new MultiHostScanner(threads, timeout, grabBanner, serviceMapper, useProbes);
            MultiHostReport multiReport = multiScanner.scan(hostsPath, ports, hostParallelism);
            System.out.printf("%nMulti-host scan complete in %.2f seconds — %d hosts, %d with open ports%n",
                    multiReport.getDurationMs() / 1000.0, multiReport.getTotalHosts(), multiReport.getHostsWithOpenPorts());
            multiReport.getResults().forEach(r -> {
                System.out.printf("%n  Host: %s (%s) — %d open ports%n",
                        r.getHost(), r.getResolvedIp(), r.getOpenCount());
                r.getOpenPorts().forEach(p ->
                        System.out.printf("    %-6d %s%n", p.getPort(),
                                p.getServiceName() != null ? p.getServiceName() : "Unknown"));
            });
            if (outputFile != null) {
                objectMapper.writeValue(Path.of(outputFile).toFile(), multiReport);
                System.out.println(color("@|green Report saved to:|@ " + outputFile));
            }
            if (topologyOutput != null) {
                try {
                    new TopologyExporter().export(multiReport, Path.of(topologyOutput));
                    System.out.println(color("@|green Topology diagram saved to:|@ " + topologyOutput));
                } catch (Exception e) {
                    System.err.println("Warning: topology export failed — " + e.getMessage());
                }
            }
            return 0;
        }

        // ── HOST mode ───────────────────────────────────────────────────────
        InetAddress resolvedAddress;
        try {
            resolvedAddress = ipv6 ? resolvePreferIPv6(host) : InetAddress.getByName(host);
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

        // ── Geolocation (run early, before scan header) ─────────────────────
        GeoLocation geoLocation = null;
        if (geolocate) {
            String ipinfoToken = resolveApiKey("IPINFO_TOKEN", config.getIpinfoToken(), "IPinfo");
            if (ipinfoToken != null || true) { // token is optional for IPinfo
                Optional<GeoLocation> geoOpt = IpInfoClient.lookup(resolvedAddress.getHostAddress(),
                        ipinfoToken != null ? ipinfoToken : "");
                if (geoOpt.isPresent()) {
                    geoLocation = geoOpt.get();
                    System.out.println(color(String.format(
                            "@|cyan Location:|@ %s, %s, %s | ISP: %s | TZ: %s",
                            nvl(geoLocation.getCity()), nvl(geoLocation.getRegion()), nvl(geoLocation.getCountry()),
                            nvl(geoLocation.getOrg()), nvl(geoLocation.getTimezone()))));
                }
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
        ProgressReporter reporter;
        if (tui) {
            try {
                reporter = new TuiProgressDisplay(ports.length, host);
            } catch (Exception e) {
                log.warn("TUI unavailable ({}), falling back to progress bar", e.getMessage());
                reporter = new ProgressReporter(ports.length, System.console() != null && !noColor);
            }
        } else {
            reporter = new ProgressReporter(ports.length, System.console() != null && !noColor);
        }
        ScanReport report = null;
        if ("tcp".equalsIgnoreCase(protocol) || "both".equalsIgnoreCase(protocol)) {
            if (useNio) {
                System.out.println(color("@|cyan Using NIO non-blocking scanner (banner grabbing disabled).|@"));
                NioPortScanner nioScanner = new NioPortScanner(timeout, serviceMapper);
                reporter.start();
                try {
                    report = nioScanner.scan(host, resolvedAddress, ports);
                } finally {
                    reporter.stop();
                }
            } else {
                PortScanner scanner = new PortScanner(threads, timeout, grabBanner, serviceMapper, useProbes, rate, proxyObj);
                reporter.setControlledScanner(scanner);
                reporter.start();
                try {
                    report = scanner.scan(host, resolvedAddress, ports, reporter);
                } finally {
                    reporter.stop();
                }
            }
        }

        // ── Run UDP scan ────────────────────────────────────────────────────
        if ("udp".equalsIgnoreCase(protocol) || "both".equalsIgnoreCase(protocol)) {
            if (proxy != null) {
                log.warn("Warning: --proxy is not supported with UDP scanning, ignoring proxy");
            }
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

        // Final proxy reference for use in lambdas (proxyObj is not effectively final due to reassignment)
        final Proxy effectiveProxy = proxyObj;

        // ── TLS inspection ──────────────────────────────────────────────────
        if (tlsInspect && report.getOpenPorts() != null && !report.getOpenPorts().isEmpty()) {
            System.out.println(color("@|cyan Inspecting TLS certificates...|@"));
            List<CompletableFuture<Void>> tlsFutures = report.getOpenPorts().stream()
                    .map(result -> CompletableFuture.runAsync(() -> {
                        int port = result.getPort();
                        boolean isTlsPort = TLS_PORTS.contains(port)
                                || (result.getServiceName() != null && result.getServiceName().toLowerCase().contains("https"));
                        if (isTlsPort) {
                            TlsInspector.inspect(host, port, timeout + 1000, effectiveProxy)
                                    .ifPresent(result::setTlsInfo);
                        }
                    }))
                    .toList();
            CompletableFuture.allOf(tlsFutures.toArray(new CompletableFuture[0])).join();
        }

        // ── HTTP inspection ──────────────────────────────────────────────────
        if (httpInspect && report.getOpenPorts() != null && !report.getOpenPorts().isEmpty()) {
            System.out.println(color("@|cyan Analyzing HTTP headers...|@"));
            List<CompletableFuture<Void>> httpFutures = report.getOpenPorts().stream()
                    .map(result -> CompletableFuture.runAsync(() -> {
                        int port = result.getPort();
                        boolean isHttpPort = HTTP_PORTS.contains(port)
                                || (result.getServiceName() != null &&
                                    (result.getServiceName().toLowerCase().contains("http")
                                     || result.getServiceName().toLowerCase().contains("web")));
                        if (isHttpPort) {
                            boolean useTls = port == 443 || port == 8443
                                    || (result.getServiceName() != null
                                        && result.getServiceName().toLowerCase().contains("https"));
                            HttpInspector.inspect(host, port, useTls, timeout + 1000, effectiveProxy)
                                    .ifPresent(result::setHttpInfo);
                        }
                    }))
                    .toList();
            CompletableFuture.allOf(httpFutures.toArray(new CompletableFuture[0])).join();
        }

        // ── TLS deep audit ───────────────────────────────────────────────────
        if (tlsDeep && report.getOpenPorts() != null && !report.getOpenPorts().isEmpty()) {
            System.out.println(color("@|cyan Running TLS deep audit (cipher enumeration + vulnerability detection)...|@"));
            List<CompletableFuture<Void>> tlsAuditFutures = report.getOpenPorts().stream()
                    .map(result -> CompletableFuture.runAsync(() -> {
                        int port = result.getPort();
                        boolean isTlsPort = TLS_PORTS.contains(port)
                                || (result.getServiceName() != null
                                    && result.getServiceName().toLowerCase().contains("https"));
                        if (isTlsPort) {
                            TlsAuditor.audit(host, port, timeout + 2000).ifPresent(auditResult -> {
                                result.setTlsAuditResult(auditResult);
                                // Print per-port summary
                                int vulnCount = auditResult.getVulnerabilities() != null
                                        ? auditResult.getVulnerabilities().size() : 0;
                                int weakCount = auditResult.getWeakCiphers() != null
                                        ? auditResult.getWeakCiphers().size() : 0;
                                String protos = auditResult.getSupportedProtocols() != null
                                        ? String.join(", ", auditResult.getSupportedProtocols()) : "—";
                                System.out.println(color(String.format(
                                        "  @|white Port %d TLS:|@ protocols=[%s] weakCiphers=%d vulns=%d",
                                        port, protos, weakCount, vulnCount)));
                                if (auditResult.getVulnerabilities() != null) {
                                    for (var v : auditResult.getVulnerabilities()) {
                                        String sev = switch (v.getSeverity() != null ? v.getSeverity() : "") {
                                            case "CRITICAL" -> "@|red,bold " + v.getName() + "|@";
                                            case "HIGH"     -> "@|red " + v.getName() + "|@";
                                            case "MEDIUM"   -> "@|yellow " + v.getName() + "|@";
                                            default         -> "@|white " + v.getName() + "|@";
                                        };
                                        System.out.println(color("    [" + v.getSeverity() + "] " + sev));
                                    }
                                }
                            });
                        }
                    }))
                    .toList();
            CompletableFuture.allOf(tlsAuditFutures.toArray(new CompletableFuture[0])).join();
        }

        // ── SSH algorithm audit ──────────────────────────────────────────────
        if (sshAudit && report.getOpenPorts() != null && !report.getOpenPorts().isEmpty()) {
            System.out.println(color("@|cyan Auditing SSH algorithms (KEXINIT parser)...|@"));
            List<CompletableFuture<Void>> sshAuditFutures = report.getOpenPorts().stream()
                    .map(result -> CompletableFuture.runAsync(() -> {
                        int port = result.getPort();
                        boolean isSshPort = port == 22
                                || (result.getServiceName() != null
                                    && result.getServiceName().toLowerCase().contains("ssh"));
                        if (isSshPort) {
                            SshAuditor.audit(host, port, timeout + 1000).ifPresent(sshResult -> {
                                result.setSshAuditResult(sshResult);
                                int weakCount = sshResult.getWeakAlgorithms() != null
                                        ? sshResult.getWeakAlgorithms().size() : 0;
                                System.out.println(color(String.format(
                                        "  @|white Port %d SSH:|@ %s — %d weak algorithm(s)",
                                        port, sshResult.getServerVersion() != null
                                                ? sshResult.getServerVersion() : "unknown",
                                        weakCount)));
                                if (sshResult.getWeakAlgorithms() != null && !sshResult.getWeakAlgorithms().isEmpty()) {
                                    for (String weak : sshResult.getWeakAlgorithms()) {
                                        System.out.println(color("    @|yellow [WEAK]|@ " + weak));
                                    }
                                }
                            });
                        }
                    }))
                    .toList();
            CompletableFuture.allOf(sshAuditFutures.toArray(new CompletableFuture[0])).join();
        }

        // ── HTTP security header scoring (auto-runs with --http) ─────────────
        if (httpInspect && report.getOpenPorts() != null && !report.getOpenPorts().isEmpty()) {
            System.out.println(color("@|cyan Scoring HTTP security headers (OWASP Observatory model)...|@"));
            List<CompletableFuture<Void>> secAuditFutures = report.getOpenPorts().stream()
                    .map(result -> CompletableFuture.runAsync(() -> {
                        int port = result.getPort();
                        boolean isHttpPort = HTTP_PORTS.contains(port)
                                || (result.getServiceName() != null &&
                                    (result.getServiceName().toLowerCase().contains("http")
                                     || result.getServiceName().toLowerCase().contains("web")));
                        if (isHttpPort) {
                            boolean useTls = port == 443 || port == 8443
                                    || (result.getServiceName() != null
                                        && result.getServiceName().toLowerCase().contains("https"));
                            HttpSecurityAuditor.audit(host, port, useTls, timeout + 1000).ifPresent(auditResult -> {
                                result.setHttpSecurityAuditResult(auditResult);
                                String gradeColor = switch (auditResult.getGrade()) {
                                    case "A+", "A" -> "@|green " + auditResult.getGrade() + "|@";
                                    case "B"        -> "@|cyan " + auditResult.getGrade() + "|@";
                                    case "C"        -> "@|yellow " + auditResult.getGrade() + "|@";
                                    default         -> "@|red " + auditResult.getGrade() + "|@";
                                };
                                System.out.println(color(String.format(
                                        "  @|white Port %d HTTP security:|@ Grade=%s (score=%d/100)",
                                        port, gradeColor, auditResult.getScore())));
                            });
                        }
                    }))
                    .toList();
            CompletableFuture.allOf(secAuditFutures.toArray(new CompletableFuture[0])).join();
        }

        // ── CVE lookup (parallel, NVD rate limit: 5 req/30s without API key) ──
        if (lookupCves && report.getOpenPorts() != null) {
            System.out.println("Looking up CVEs (NVD API — may be slow due to rate limits)...");
            CveLookup cveLookup = new CveLookup();
            Semaphore nvdLimit = new Semaphore(5);
            List<CompletableFuture<Void>> cveFutures = report.getOpenPorts().stream()
                .map(result -> CompletableFuture.runAsync(() -> {
                    try {
                        nvdLimit.acquire();
                        try {
                            String keyword = cveLookup.extractKeyword(result.getServiceName(), result.getVersion() != null ? result.getVersion() : result.getBanner());
                            if (!keyword.isBlank()) {
                                List<com.portscanner.model.CveEntry> cves = cveLookup.lookup(keyword);
                                if (!cves.isEmpty()) result.setCves(cves);
                            }
                        } finally {
                            nvdLimit.release();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }))
                .toList();
            CompletableFuture.allOf(cveFutures.toArray(new CompletableFuture[0])).join();

            // ── --fail-on-cvss exit code check ─────────────────────────────────
            if (failOnCvss != null) {
                boolean exceeded = report.getOpenPorts().stream()
                    .filter(r -> r.getCves() != null)
                    .flatMap(r -> r.getCves().stream())
                    .anyMatch(c -> {
                        Double score = c.getCvssV3() != null ? c.getCvssV3() : c.getCvssV2();
                        return score != null && score >= failOnCvss;
                    });
                if (exceeded) {
                    System.err.println("POLICY VIOLATION: CVE with CVSS score >= " + failOnCvss + " found.");
                    return 2;
                }
            }
        }

        // ── Plugin/Script execution ──────────────────────────────────────────
        if (scripts != null && !scripts.isBlank()) {
            PluginRegistry registry = new PluginRegistry();
            List<ScanPlugin> toRun;
            if ("all".equalsIgnoreCase(scripts.trim())) {
                toRun = registry.getAll();
            } else {
                toRun = Arrays.stream(scripts.split(","))
                        .map(String::trim)
                        .map(registry::getByName)
                        .filter(Optional::isPresent)
                        .map(Optional::get)
                        .collect(Collectors.toList());
            }
            PluginContext ctx = new PluginContext(host, timeout, config, System.out);
            for (ScanResult result : report.getOpenPorts()) {
                for (ScanPlugin plugin : toRun) {
                    if (plugin.appliesTo(result)) {
                        try { plugin.execute(result, ctx); } catch (Exception e) { /* silent */ }
                    }
                }
            }
        }

        // ── Reverse DNS enrichment ───────────────────────────────────────────
        if (report.getOpenPorts() != null && !report.getOpenPorts().isEmpty()) {
            List<CompletableFuture<Void>> rdnsFutures = report.getOpenPorts().stream()
                    .map(result -> CompletableFuture.runAsync(() -> {
                        try {
                            String ip = resolvedAddress.getHostAddress();
                            String rdns = InetAddress.getByName(ip).getCanonicalHostName();
                            if (!rdns.equals(ip)) {
                                result.setHostname(rdns);
                            }
                        } catch (Exception ignored) {}
                    }))
                    .toList();
            CompletableFuture.allOf(rdnsFutures.toArray(new CompletableFuture[0])).join();
        }

        // ── ASN lookup ──────────────────────────────────────────────────────
        AsnInfo asnInfo = null;
        {
            Optional<AsnInfo> asnOpt = AsnLookup.lookup(resolvedAddress.getHostAddress());
            if (asnOpt.isPresent()) {
                asnInfo = asnOpt.get();
            }
        }

        // ── AbuseIPDB check ─────────────────────────────────────────────────
        ThreatInfo threatInfo = null;
        if (abuseCheck) {
            String apiKey = resolveApiKey("ABUSEIPDB_KEY", config.getAbuseIpDbKey(), "AbuseIPDB");
            if (apiKey != null) {
                Optional<ThreatInfo> threatOpt = AbuseIpDbClient.check(resolvedAddress.getHostAddress(), apiKey);
                if (threatOpt.isPresent()) {
                    threatInfo = threatOpt.get();
                }
            }
        }

        // ── GreyNoise check ─────────────────────────────────────────────────
        if (greyNoise) {
            String apiKey = resolveApiKey("GREYNOISE_KEY", config.getGreynoiseKey(), "GreyNoise");
            Optional<ThreatInfo> gnOpt = GreyNoiseClient.check(resolvedAddress.getHostAddress(),
                    apiKey != null ? apiKey : "");
            if (gnOpt.isPresent()) {
                ThreatInfo gnInfo = gnOpt.get();
                if (threatInfo == null) {
                    threatInfo = gnInfo;
                } else {
                    // Merge GreyNoise fields into existing ThreatInfo
                    threatInfo = ThreatInfo.builder()
                            .abuseConfidenceScore(threatInfo.getAbuseConfidenceScore())
                            .abuseReportCount(threatInfo.getAbuseReportCount())
                            .isp(threatInfo.getIsp() != null ? threatInfo.getIsp() : gnInfo.getIsp())
                            .greynoiseClassification(gnInfo.getGreynoiseClassification())
                            .greynoiseIsScanner(gnInfo.isGreynoiseIsScanner())
                            .build();
                }
            }
        }

        // ── Attach enrichment to report ─────────────────────────────────────
        ScanReport.ScanReportBuilder reportBuilder = report.toBuilder();
        if (asnInfo != null) reportBuilder.asnInfo(asnInfo);
        if (threatInfo != null) reportBuilder.threatInfo(threatInfo);
        if (geoLocation != null) reportBuilder.geoLocation(geoLocation);
        report = reportBuilder.build();

        // ── Traceroute ──────────────────────────────────────────────────────
        if (traceroute) {
            System.out.printf("%nTRACEROUTE (%d hops max):%n", tracerouteMaxHops);
            List<TracerouteHop> hops = new Traceroute().run(host, tracerouteMaxHops);
            if (hops.isEmpty()) {
                System.out.println("(no results — traceroute may not be available on this system)");
            } else {
                for (TracerouteHop hop : hops) {
                    if ("*".equals(hop.ip())) {
                        System.out.printf(" %-3d  %-10s (timeout)%n", hop.hopNumber(), "*");
                    } else {
                        String rttStr = hop.rttMs() < 0 ? "*" : String.format("%.1fms", hop.rttMs());
                        String nameStr = hop.hostname() != null && !hop.hostname().equals(hop.ip())
                                ? " (" + hop.hostname() + ")" : "";
                        System.out.printf(" %-3d  %-10s %s%s%n", hop.hopNumber(), rttStr, hop.ip(), nameStr);
                    }
                }
            }
            report = report.toBuilder().tracerouteHops(hops).build();
        }

        // ── OS fingerprinting ────────────────────────────────────────────────
        if (osDetect) {
            System.out.println(color("@|cyan Detecting OS...|@"));
            OsFingerprinter fp = new OsFingerprinter();
            OsGuess guess = fp.fingerprint(resolvedAddress,
                    report.getOpenPorts() != null ? report.getOpenPorts() : List.of());
            if (guess != null) {
                report = report.toBuilder().osGuess(guess).build();
            }
        }

        // ── SNMP probe ───────────────────────────────────────────────────────
        if (snmp) {
            System.out.println(color("@|cyan Probing SNMP (UDP 161)...|@"));
            SnmpScanner snmpScanner = new SnmpScanner(Math.max(timeout, 1000),
                    SnmpScanner.parseCommunities(snmpCommunity));
            final ScanReport snmpReport = report;
            snmpScanner.probe(resolvedAddress).ifPresent(info -> {
                System.out.println(color(String.format(
                        "@|cyan SNMP:|@ sysName=@|white %s|@ sysDescr=@|white %s|@",
                        info.getSysName() != null ? info.getSysName() : "—",
                        info.getSysDescr() != null ? info.getSysDescr() : "—")));
                if (info.getSysLocation() != null)
                    System.out.println(color("       location=" + info.getSysLocation()));
                // Attach to any port-161 result if present
                if (snmpReport.getOpenPorts() != null) {
                    snmpReport.getOpenPorts().stream()
                            .filter(r -> r.getPort() == 161)
                            .findFirst()
                            .ifPresent(r -> r.setSnmpInfo(info));
                }
                log.info("SNMP response from {} community={}", host, info.getCommunity());
            });
        }

        // ── Shodan InternetDB enrichment ──────────────────────────────────────
        if (shodan) {
            String lookupIp = resolvedAddress.getHostAddress();
            System.out.println(color("@|cyan Querying Shodan InternetDB for:|@ " + lookupIp));
            Optional<ShodanResult> shodanOpt = new ShodanInternetDbClient().query(lookupIp);
            if (shodanOpt.isPresent()) {
                ShodanResult sr = shodanOpt.get();
                report = report.toBuilder().shodanResult(sr).build();
                List<Integer> shodanPorts = sr.getPorts() != null ? sr.getPorts() : List.of();
                System.out.println(color(String.format(
                        "@|cyan Shodan sees:|@ %d port(s): %s",
                        shodanPorts.size(),
                        shodanPorts.stream().map(String::valueOf).collect(Collectors.joining(", ")))));
                if (sr.getVulns() != null && !sr.getVulns().isEmpty())
                    System.out.println(color("@|red Shodan CVEs:|@ " + String.join(", ", sr.getVulns())));
                if (sr.getTags() != null && !sr.getTags().isEmpty())
                    System.out.println(color("@|yellow Shodan tags:|@ " + String.join(", ", sr.getTags())));
                // Delta between Shodan and this scan
                List<Integer> ourPorts = report.getOpenPorts() != null
                        ? report.getOpenPorts().stream().map(ScanResult::getPort).toList() : List.of();
                List<Integer> onlyInShodan = shodanPorts.stream().filter(p -> !ourPorts.contains(p)).toList();
                List<Integer> onlyInOurs   = ourPorts.stream().filter(p -> !shodanPorts.contains(p)).toList();
                if (!onlyInShodan.isEmpty())
                    System.out.println(color("@|yellow In Shodan but not in this scan:|@ " +
                            onlyInShodan.stream().map(String::valueOf).collect(Collectors.joining(", "))));
                if (!onlyInOurs.isEmpty())
                    System.out.println(color("@|green In this scan but not in Shodan:|@ " +
                            onlyInOurs.stream().map(String::valueOf).collect(Collectors.joining(", "))));
            }
        }

        // ── Nuclei template execution ──────────────────────────────────────────
        if (nucleiTemplatesPath != null) {
            Path nucleiDir = Path.of(nucleiTemplatesPath);
            if (Files.isDirectory(nucleiDir)) {
                try {
                    NucleiTemplateLoader loader = new NucleiTemplateLoader();
                    List<NucleiTemplate> templates = loader.load(nucleiDir, nucleiTags);
                    if (!templates.isEmpty()) {
                        System.out.println(color(String.format(
                                "@|cyan Nuclei:|@ running %d template(s) against open ports...", templates.size())));
                        NucleiRunner runner = new NucleiRunner();
                        List<ScanResult> openPorts = report.getOpenPorts();
                        if (openPorts != null) {
                            for (ScanResult r : openPorts) {
                                List<NucleiResult> findings = runner.run(
                                        report.getResolvedIp() != null ? report.getResolvedIp() : host, r, templates);
                                if (!findings.isEmpty()) {
                                    r.setNucleiFindings(findings);
                                    findings.forEach(f -> System.out.println(color(String.format(
                                            "  @|red [%s]|@ %s matched at %s",
                                            f.getSeverity(), f.getTemplateId(), f.getMatchedAt()))));
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    System.err.println("Warning: Nuclei execution failed — " + e.getMessage());
                    log.debug("Nuclei error", e);
                }
            } else {
                System.err.println("Warning: --nuclei-templates path is not a directory: " + nucleiTemplatesPath);
            }
        }

        // ── Populate TUI open ports table (if TUI was used) ─────────────────
        if (reporter instanceof TuiProgressDisplay tuiDisplay) {
            tuiDisplay.setOpenPorts(report.getOpenPorts() != null ? report.getOpenPorts() : List.of());
        }

        // ── DNS subdomain brute-force ────────────────────────────────────────
        List<SubdomainResult> subdomainResults = List.of();
        if (dnsBruteEnabled || dnsBruteWordlist != null) {
            System.out.println(color(String.format(
                    "%n@|cyan DNS brute-force:|@ target=%s  wordlist=%s",
                    host,
                    dnsBruteWordlist != null ? dnsBruteWordlist : "bundled top-1000")));
            try {
                DnsBruteForcer bruteForcer = new DnsBruteForcer(host, Math.max(timeout, 2000));
                Path wordlistPath = dnsBruteWordlist != null ? Path.of(dnsBruteWordlist) : null;
                List<String> wordlist = bruteForcer.loadWordlist(wordlistPath);
                System.out.printf("Brute-forcing %d subdomain candidates...%n", wordlist.size());
                subdomainResults = bruteForcer.bruteForce(wordlist);
                printSubdomainResults(subdomainResults);
                if (!subdomainResults.isEmpty()) {
                    report = report.toBuilder().subdomains(subdomainResults).build();
                }
            } catch (Exception e) {
                System.err.println("Warning: DNS brute-force failed — " + e.getMessage());
                log.debug("DNS brute-force error", e);
            }
        }

        // ── CT recon (Certificate Transparency log query) ────────────────────
        if (ctRecon != null && !ctRecon.isBlank()) {
            System.out.println(color(String.format(
                    "%n@|cyan CT recon:|@ querying crt.sh for subdomains of @|white %s|@...", ctRecon.trim())));
            try {
                CertTransparencyClient ctClient = new CertTransparencyClient();
                List<String> ctHosts = ctClient.findSubdomains(ctRecon.trim());
                if (ctHosts.isEmpty()) {
                    System.out.println(color("@|yellow No subdomains found in CT logs.|@"));
                } else {
                    System.out.printf("Found @|green %d|@ subdomain(s) in CT logs:%n", ctHosts.size());
                    ctHosts.forEach(h -> System.out.println(color("  @|white " + h + "|@")));

                    // Resolve each CT hostname and store as SubdomainResult
                    List<SubdomainResult> ctSubdomainResults = new ArrayList<>();
                    for (String ctHost : ctHosts) {
                        try {
                            InetAddress addr = InetAddress.getByName(ctHost);
                            ctSubdomainResults.add(SubdomainResult.builder()
                                    .subdomain(ctHost)
                                    .addresses(List.of(addr.getHostAddress()))
                                    .build());
                        } catch (Exception ignored) {
                            // Unresolvable — still record it
                            ctSubdomainResults.add(SubdomainResult.builder()
                                    .subdomain(ctHost)
                                    .build());
                        }
                    }
                    long resolved = ctSubdomainResults.stream()
                            .filter(r -> r.getAddresses() != null && !r.getAddresses().isEmpty()).count();
                    System.out.println(color(String.format(
                            "@|cyan CT recon:|@ %d/%d subdomains resolved. "
                                    + "Use --hosts-file to scan discovered hosts.",
                            resolved, ctHosts.size())));
                    report = report.toBuilder().ctSubdomains(ctSubdomainResults).build();
                }
            } catch (Exception e) {
                System.err.println("Warning: CT recon failed — " + e.getMessage());
                log.debug("CT recon error", e);
            }
        }

        // ── Print summary ───────────────────────────────────────────────────
        printSummary(report, showAll);

        // ── Auto-diff against history ────────────────────────────────────────
        if (historyDiff) {
            try {
                ScanHistoryDao dao = new ScanHistoryDao();
                Optional<ScanReport> mostRecent = dao.getMostRecent(host);
                if (mostRecent.isPresent()) {
                    ReportDiffer differ = new ReportDiffer();
                    DiffReport diffReport = differ.diff(mostRecent.get(), report, "previous scan", "current scan");
                    System.out.println();
                    System.out.println("History diff (vs most recent scan for this host):");
                    differ.printDiff(diffReport);
                } else {
                    System.out.println("No prior scan in history for: " + host);
                }
            } catch (Exception e) {
                System.err.println("Warning: history diff failed — " + e.getMessage());
                log.debug("History diff error", e);
            }
        }

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

        // ── Save to history ──────────────────────────────────────────────────
        if (saveHistory) {
            try {
                new ScanHistoryDao().save(report);
                System.out.println(color("@|green History saved to:|@ ~/.portscanner/history.db"));
            } catch (Exception e) {
                System.err.println("Warning: could not save history — " + e.getMessage());
                log.debug("History save error", e);
            }
        }

        // ── Topology diagram ─────────────────────────────────────────────────
        if (topologyOutput != null) {
            try {
                new TopologyExporter().export(report, Path.of(topologyOutput));
                System.out.println(color("@|green Topology diagram saved to:|@ " + topologyOutput));
            } catch (Exception e) {
                System.err.println("Warning: topology export failed — " + e.getMessage());
                log.debug("Topology export error", e);
            }
        }

        // ── Webhook notification ──────────────────────────────────────────────
        String effectiveWebhook = webhook != null ? webhook
                : (config.getWebhook() != null ? config.getWebhook() : null);
        boolean effectiveOnOpenOnly = webhookOnOpenOnly
                || Boolean.TRUE.equals(config.getWebhookOnOpenOnly());
        if (effectiveWebhook != null) {
            boolean shouldSend = !effectiveOnOpenOnly || report.getOpenCount() > 0;
            if (shouldSend) {
                System.out.println(color("@|cyan Sending webhook...|@"));
                new WebhookClient().send(report, effectiveWebhook);
            } else {
                log.debug("Webhook skipped (--webhook-on-open-only and no open ports)");
            }
        }

        // ── Policy evaluation ────────────────────────────────────────────────
        List<PolicyRule> policyRules = List.of();
        if (policyFile != null) {
            policyRules = PolicyLoader.load(Path.of(policyFile));
        } else if (failOnOpen != null && !failOnOpen.isBlank()) {
            // Build synthetic FAIL rules from --fail-on-open port list
            List<PolicyRule> synthetic = new ArrayList<>();
            for (String token : failOnOpen.split(",")) {
                String t = token.trim();
                if (t.isEmpty()) continue;
                try {
                    PolicyRule r = new PolicyRule();
                    r.setPort(Integer.parseInt(t));
                    r.setState("OPEN");
                    r.setAction("FAIL");
                    r.setName("port-" + t + "-blocked");
                    r.setMessage("Port " + t + " is open — blocked by --fail-on-open");
                    synthetic.add(r);
                } catch (NumberFormatException ignored) {
                    log.warn("--fail-on-open: '{}' is not a valid port number", t);
                }
            }
            policyRules = synthetic;
        }

        List<PolicyEvaluator.PolicyViolation> violations = List.of();
        if (!policyRules.isEmpty()) {
            violations = PolicyEvaluator.evaluate(report, policyRules);
            if (!violations.isEmpty()) {
                System.out.println();
                for (PolicyEvaluator.PolicyViolation v : violations) {
                    String level = "FAIL".equalsIgnoreCase(v.rule().getAction()) ? "@|red,bold FAIL|@"
                            : "WARN".equalsIgnoreCase(v.rule().getAction()) ? "@|yellow WARN|@" : "@|white INFO|@";
                    String portStr = v.port() != null ? "port " + v.port().getPort() : "required port " + v.rule().getPort() + " missing";
                    System.out.println(color(String.format("[%s] %s — %s",
                            level, v.rule().getName() != null ? v.rule().getName() : portStr,
                            v.rule().getMessage() != null ? v.rule().getMessage() : portStr)));
                }
            }
        }

        // Build fail-ports list for JUnit exporter
        final List<Integer> failPortsList = policyRules.stream()
                .filter(r -> "OPEN".equalsIgnoreCase(r.getState()))
                .map(PolicyRule::getPort).filter(java.util.Objects::nonNull).toList();

        // ── Export to file ──────────────────────────────────────────────────
        if (outputFile != null && !watch) {
            // Use fail-port-aware JUnit exporter when applicable
            ReportExporter exporter;
            boolean isJunit = "junit".equalsIgnoreCase(format) || "junit-xml".equalsIgnoreCase(format);
            if (!failPortsList.isEmpty() && isJunit) {
                exporter = new JUnitXmlExporter(failPortsList);
            } else {
                exporter = ExporterFactory.getExporter(outputFile, format, objectMapper);
            }
            exporter.export(report, Path.of(outputFile));
            System.out.println(color("@|green Report saved to:|@ " + outputFile));
        }

        // ── Watch mode ───────────────────────────────────────────────────────
        if (watch) {
            final int[]    finalPorts   = ports;
            final InetAddress finalAddr = resolvedAddress;
            final Proxy    finalProxy   = proxyObj;
            final ScanReport firstReport = report;

            // Export the first scan result (already done above outside watch loop)
            if (outputFile != null) {
                String timestamped = watchOutputName(outputFile, 1);
                ReportExporter exporter = ExporterFactory.getExporter(timestamped, format, objectMapper);
                exporter.export(firstReport, Path.of(timestamped));
                System.out.println(color("@|green Report saved to:|@ " + timestamped));
            }

            WatchMode watchMode = new WatchMode(watchInterval, watchAlert, saveHistory);
            int[] scanIndex = {1};
            watchMode.run(host, () -> {
                // Each re-scan reuses the same scanner configuration
                PortScanner sc = new PortScanner(threads, timeout, grabBanner, new ServiceMapper(),
                        useProbes, rate, finalProxy);
                try {
                    ScanReport r = sc.scan(host, finalAddr, finalPorts);
                    if (osDetect) {
                        OsGuess g = new OsFingerprinter().fingerprint(finalAddr,
                                r.getOpenPorts() != null ? r.getOpenPorts() : List.of());
                        if (g != null) r = r.toBuilder().osGuess(g).build();
                    }
                    return r;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }, eachReport -> {
                if (outputFile != null) {
                    scanIndex[0]++;
                    String timestamped = watchOutputName(outputFile, scanIndex[0]);
                    try {
                        ReportExporter exporter = ExporterFactory.getExporter(timestamped, format, objectMapper);
                        exporter.export(eachReport, Path.of(timestamped));
                    } catch (Exception e) {
                        log.warn("Failed to export watch scan report: {}", e.getMessage());
                    }
                }
            });
        }

        return PolicyEvaluator.hasFatal(violations) ? 1 : 0;
    }

    /** Produces e.g. scan.json → scan-001.json, scan-002.json */
    private static String watchOutputName(String outputFile, int index) {
        int dot = outputFile.lastIndexOf('.');
        if (dot < 0) return outputFile + String.format("-%03d", index);
        return outputFile.substring(0, dot) + String.format("-%03d", index) + outputFile.substring(dot);
    }

    private InetAddress resolvePreferIPv6(String host) throws java.net.UnknownHostException {
        InetAddress[] all = InetAddress.getAllByName(host);
        for (InetAddress addr : all) {
            if (addr instanceof Inet6Address) return addr;
        }
        return all[0]; // fallback to first address if no IPv6
    }

    private void printSubdomainResults(List<SubdomainResult> results) {
        if (results.isEmpty()) {
            System.out.println(color("@|yellow No subdomains discovered.|@"));
            return;
        }
        System.out.println(color(String.format("%n@|bold %-50s %-25s %s|@", "SUBDOMAIN", "ADDRESS(ES)", "CNAME")));
        System.out.println("-".repeat(95));
        for (SubdomainResult r : results) {
            String addr  = (r.getAddresses() != null && !r.getAddresses().isEmpty())
                    ? String.join(", ", r.getAddresses()) : "-";
            String cname = r.getCname() != null ? r.getCname() : "-";
            System.out.println(color(String.format(
                    "@|green %-50s|@ @|yellow %-25s|@ %s", r.getSubdomain(), addr, cname)));
        }
        System.out.printf("%n%d subdomain(s) discovered.%n", results.size());
    }

    private String resolveApiKey(String envVar, String configValue, String serviceName) {
        String key = System.getenv(envVar);
        if (key != null && !key.isBlank()) return key;
        if (configValue != null && !configValue.isBlank()) return configValue;
        System.err.println("Warning: " + serviceName + " API key not found. Set " + envVar + " env var or add to config.");
        return null;
    }

    private void printSummary(ScanReport report, boolean showAll) {
        System.out.println(color(String.format(
                "%n@|bold,cyan Scan complete|@ in @|yellow %.2f|@ seconds — @|green %d open|@, @|yellow %d filtered|@ out of @|white %d|@ scanned%n",
                report.getDurationMs() / 1000.0, report.getOpenCount(), report.getFilteredCount(), report.getTotalScanned())));

        // OS guess
        if (report.getOsGuess() != null) {
            var os = report.getOsGuess();
            System.out.println(color(String.format(
                    "@|cyan OS Guess:|@ @|white %s|@ (confidence: %s, method: %s)",
                    os.getOs(), os.getConfidence(), os.getMethod())));
        }

        // Threat info
        if (report.getThreatInfo() != null) {
            ThreatInfo t = report.getThreatInfo();
            if (t.getAbuseConfidenceScore() > 25) {
                System.out.println(color(String.format(
                        "@|red,bold !! THREAT: AbuseIPDB score %d/100 (%d reports) -- HIGH RISK|@",
                        t.getAbuseConfidenceScore(), t.getAbuseReportCount())));
            }
            if (t.getGreynoiseClassification() != null) {
                String scannerPart = t.isGreynoiseIsScanner()
                        ? " (Scanner: " + nvl(t.getIsp()) + ")" : "";
                System.out.println(color(String.format("@|yellow GreyNoise: %s%s|@",
                        t.getGreynoiseClassification().toUpperCase(), scannerPart)));
            }
        }

        // ASN info
        if (report.getAsnInfo() != null) {
            AsnInfo a = report.getAsnInfo();
            System.out.println(color(String.format("@|cyan ASN: %s %s | %s | %s|@",
                    nvl(a.getAsn()), nvl(a.getName()), nvl(a.getPrefix()), nvl(a.getCountry()))));
        }

        if (report.getOpenPorts() != null && !report.getOpenPorts().isEmpty()) {
            System.out.println(color(String.format("@|bold %-8s %-16s %-12s %s|@", "PORT", "SERVICE", "RESPONSE", "BANNER")));
            System.out.println("------------------------------------------------------------");
            report.getOpenPorts().forEach(r -> {
                String hostname = r.getHostname() != null ? " (" + r.getHostname() + ")" : "";
                System.out.println(color(String.format("@|green %-8d|@ %-16s @|yellow %-12s|@ %s%s",
                        r.getPort(),
                        r.getServiceName() != null ? r.getServiceName() : "Unknown",
                        r.getResponseTimeMs() + "ms",
                        r.getBanner() != null ? r.getBanner() : "-",
                        hostname)));
                if (r.getCves() != null && !r.getCves().isEmpty()) {
                    String cveStr = r.getCves().stream().map(c -> c.getId()).collect(Collectors.joining(", "));
                    System.out.println(color("         @|red CVEs: " + cveStr + "|@"));
                }
                if (r.getTlsInfo() != null) {
                    var tls = r.getTlsInfo();
                    System.out.println(color(String.format("         @|cyan TLS: %s | Expires: %s | CN=%s|@",
                            nvl(tls.getProtocol()),
                            tls.getCertExpiry() != null ? tls.getCertExpiry() : "N/A",
                            extractCn(tls.getCertSubject()))));
                    if (tls.isExpired()) System.out.println(color("         @|red [EXPIRED CERTIFICATE]|@"));
                    if (tls.isExpiresSoon()) System.out.println(color("         @|yellow [CERTIFICATE EXPIRES SOON]|@"));
                    if (tls.isDeprecatedProtocol()) System.out.println(color("         @|yellow [DEPRECATED PROTOCOL: " + tls.getProtocol() + "]|@"));
                    if (tls.isWeakCipher()) System.out.println(color("         @|yellow [WEAK CIPHER SUITE]|@"));
                }
                if (r.getHttpInfo() != null) {
                    var http = r.getHttpInfo();
                    System.out.println(color(String.format("         @|green HTTP %d | Server: %s|@",
                            http.getStatusCode(), nvl(http.getServerHeader()))));
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

    private String extractCn(String dn) {
        if (dn == null) return "-";
        for (String part : dn.split(",")) {
            String trimmed = part.trim();
            if (trimmed.startsWith("CN=")) return trimmed.substring(3);
        }
        return dn;
    }

    private String nvl(String s) {
        return s != null ? s : "-";
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

    @Command(name = "update-db", description = "Download/update local CVE database from NVD")
    static class UpdateDbCommand implements Callable<Integer> {
        @Option(names = "--nvd-api-key", description = "NVD API key (optional, increases rate limit)")
        private String nvdApiKey;

        @Override
        public Integer call() {
            String apiKey = nvdApiKey != null ? nvdApiKey : System.getenv("NVD_API_KEY");
            System.out.println("Syncing CVE database from NVD...");
            new LocalCveDatabase().sync(apiKey);
            System.out.println("CVE database updated: ~/.portscanner/cve-db.sqlite");
            return 0;
        }
    }
}
