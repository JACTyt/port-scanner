package com.portscanner.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.portscanner.api.dto.AgentRegistration;
import com.portscanner.api.dto.AgentResult;
import com.portscanner.api.dto.WorkItem;
import com.portscanner.model.ScanReport;
import com.portscanner.scanner.PortScanner;
import com.portscanner.service.ServiceMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Scan agent that polls a {@link CoordinatorServer} for work, executes scans,
 * and reports results back.
 */
public class ScanAgentClient {

    private static final Logger log = LoggerFactory.getLogger(ScanAgentClient.class);
    private static final Duration POLL_INTERVAL = Duration.ofSeconds(5);
    private static final Duration HEARTBEAT_INTERVAL = Duration.ofSeconds(30);

    private final String coordinatorUrl;
    private final String token;
    private final String agentId;
    private final String label;
    private final HttpClient http;
    private final ObjectMapper mapper;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private ScheduledExecutorService scheduler;

    public ScanAgentClient(String coordinatorUrl, String token, String label) {
        this.coordinatorUrl = coordinatorUrl.replaceAll("/$", "");
        this.token          = token;
        this.agentId        = UUID.randomUUID().toString();
        this.label          = label != null ? label : agentId;
        this.http           = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        this.mapper         = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    /** Register this agent with the coordinator, then start polling. */
    public void start() throws Exception {
        register();
        running.set(true);
        scheduler = Executors.newScheduledThreadPool(2);
        scheduler.scheduleWithFixedDelay(this::pollAndExecute,
                0, POLL_INTERVAL.toSeconds(), TimeUnit.SECONDS);
        scheduler.scheduleWithFixedDelay(this::heartbeat,
                HEARTBEAT_INTERVAL.toSeconds(), HEARTBEAT_INTERVAL.toSeconds(), TimeUnit.SECONDS);
        log.info("Agent {} started, polling {}", agentId, coordinatorUrl);
    }

    public void stop() {
        running.set(false);
        if (scheduler != null) scheduler.shutdownNow();
        log.info("Agent {} stopped", agentId);
    }

    // ── internals ─────────────────────────────────────────────────────────────

    private void register() throws Exception {
        AgentRegistration reg = AgentRegistration.builder()
                .agentId(agentId).label(label).token(token).build();
        post("/agent/register", reg);
        log.info("Registered as agent {} ({})", agentId, label);
    }

    private void pollAndExecute() {
        if (!running.get()) return;
        try {
            HttpResponse<String> resp = get("/agent/work");
            if (resp.statusCode() == 204) return; // no work available
            if (resp.statusCode() != 200) {
                log.warn("Unexpected /agent/work status: {}", resp.statusCode());
                return;
            }
            WorkItem item = mapper.readValue(resp.body(), WorkItem.class);
            log.info("Received work {}: {} {}", item.getWorkId(), item.getTarget(), item.getPorts());
            ScanReport report = executeScan(item);
            AgentResult result = AgentResult.builder()
                    .workId(item.getWorkId()).agentId(agentId).report(report).build();
            post("/agent/result", result);
            log.info("Submitted result for work {}", item.getWorkId());
        } catch (Exception e) {
            log.error("Error in poll cycle: {}", e.getMessage());
        }
    }

    private void heartbeat() {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(coordinatorUrl + "/agent/heartbeat"))
                    .header("Authorization", "Bearer " + token)
                    .PUT(HttpRequest.BodyPublishers.noBody())
                    .build();
            http.send(req, HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) {
            log.debug("Heartbeat failed: {}", e.getMessage());
        }
    }

    private ScanReport executeScan(WorkItem item) throws Exception {
        int timeout = item.getTimeout() > 0 ? item.getTimeout() : 200;
        int threads = item.getThreads() > 0 ? item.getThreads() : 100;
        String portsStr = item.getPorts() != null ? item.getPorts() : "1-1024";

        // Parse port range/list into int[]
        int[] ports = parsePorts(portsStr);

        ServiceMapper svc = new ServiceMapper();
        PortScanner scanner = new PortScanner(threads, timeout, item.isBanner(), svc);
        InetAddress addr = InetAddress.getByName(item.getTarget());
        return scanner.scan(item.getTarget(), addr, ports);
    }

    /** Parses "80,443,8080" or "1-1024" into an int[]. */
    private int[] parsePorts(String spec) {
        if (spec.contains("-") && !spec.contains(",")) {
            String[] parts = spec.split("-");
            int from = Integer.parseInt(parts[0].trim());
            int to   = Integer.parseInt(parts[1].trim());
            int[] arr = new int[to - from + 1];
            for (int i = 0; i < arr.length; i++) arr[i] = from + i;
            return arr;
        }
        return java.util.Arrays.stream(spec.split(","))
                .mapToInt(p -> Integer.parseInt(p.trim())).toArray();
    }

    private void post(String path, Object body) throws Exception {
        String json = mapper.writeValueAsString(body);
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(coordinatorUrl + path))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();
        http.send(req, HttpResponse.BodyHandlers.discarding());
    }

    private HttpResponse<String> get(String path) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(coordinatorUrl + path))
                .header("Authorization", "Bearer " + token)
                .GET().build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }

    public String getAgentId() { return agentId; }
}
