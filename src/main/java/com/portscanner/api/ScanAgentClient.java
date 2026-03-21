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
                .agentId(agentId).label(label).build();
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
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(coordinatorUrl + "/agent/heartbeat"))
                    .PUT(HttpRequest.BodyPublishers.noBody());
            if (token != null) builder.header("Authorization", "Bearer " + token);
            http.send(builder.build(), HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) {
            log.debug("Heartbeat failed: {}", e.getMessage());
        }
    }

    private ScanReport executeScan(WorkItem item) throws Exception {
        int timeout = item.getTimeout() > 0 ? item.getTimeout() : 200;
        int threads = item.getThreads() > 0 ? item.getThreads() : 100;
        String portsStr = item.getPorts() != null ? item.getPorts() : "1-1024";

        int[] ports = PortRangeParser.parse(portsStr);

        ServiceMapper svc = new ServiceMapper();
        PortScanner scanner = new PortScanner(threads, timeout, item.isBanner(), svc);
        InetAddress addr = InetAddress.getByName(item.getTarget());
        return scanner.scan(item.getTarget(), addr, ports);
    }

    private void post(String path, Object body) throws Exception {
        String json = mapper.writeValueAsString(body);
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(coordinatorUrl + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json));
        if (token != null) builder.header("Authorization", "Bearer " + token);
        http.send(builder.build(), HttpResponse.BodyHandlers.discarding());
    }

    private HttpResponse<String> get(String path) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(coordinatorUrl + path))
                .GET();
        if (token != null) builder.header("Authorization", "Bearer " + token);
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    public String getAgentId() { return agentId; }
}
