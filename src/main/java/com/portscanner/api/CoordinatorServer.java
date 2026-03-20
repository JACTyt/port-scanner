package com.portscanner.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.portscanner.api.dto.AgentRegistration;
import com.portscanner.api.dto.AgentResult;
import com.portscanner.api.dto.WorkItem;
import com.portscanner.model.ScanReport;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

/**
 * Coordinator node for distributed scanning.
 *
 * <pre>
 *   POST   /agent/register   – agent announces itself
 *   GET    /agent/work       – agent polls for a work item
 *   POST   /agent/result     – agent submits completed scan result
 *   PUT    /agent/heartbeat  – agent signals it is alive
 *   POST   /work/submit      – external caller enqueues a scan job
 *   GET    /scans            – combined results list
 * </pre>
 */
public class CoordinatorServer {

    private static final Logger log = LoggerFactory.getLogger(CoordinatorServer.class);

    private final HttpServer server;
    private final ObjectMapper mapper;
    private final String token; // null = no auth

    // registered agents: agentId → label
    private final Map<String, String> agents = new ConcurrentHashMap<>();
    // work queue
    private final BlockingQueue<WorkItem> workQueue = new LinkedBlockingDeque<>();
    // completed results
    private final List<ScanReport> results = Collections.synchronizedList(new ArrayList<>());

    public CoordinatorServer(int port, String token) throws IOException {
        this.token  = token;
        this.mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .enable(SerializationFeature.INDENT_OUTPUT);

        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/agent/register",  this::handleRegister);
        server.createContext("/agent/work",       this::handleWork);
        server.createContext("/agent/result",     this::handleResult);
        server.createContext("/agent/heartbeat",  this::handleHeartbeat);
        server.createContext("/work/submit",      this::handleSubmit);
        server.createContext("/scans",            this::handleScans);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    }

    public void start() {
        server.start();
        log.info("Coordinator listening on port {}", server.getAddress().getPort());
    }

    public void stop() { server.stop(0); }

    public int getPort() { return server.getAddress().getPort(); }

    // ── handlers ─────────────────────────────────────────────────────────────

    private void handleRegister(HttpExchange ex) throws IOException {
        if (!isAuthorized(ex)) { send(ex, 401, "Unauthorized"); return; }
        if (!"POST".equals(ex.getRequestMethod())) { send(ex, 405, "Method Not Allowed"); return; }
        AgentRegistration reg = mapper.readValue(ex.getRequestBody(), AgentRegistration.class);
        agents.put(reg.getAgentId(), reg.getLabel() != null ? reg.getLabel() : reg.getAgentId());
        log.info("Agent registered: {} ({})", reg.getAgentId(), reg.getLabel());
        send(ex, 200, "{\"status\":\"registered\"}");
    }

    private void handleWork(HttpExchange ex) throws IOException {
        if (!isAuthorized(ex)) { send(ex, 401, "Unauthorized"); return; }
        WorkItem item = workQueue.poll();
        if (item == null) {
            sendNoContent(ex);
        } else {
            send(ex, 200, mapper.writeValueAsString(item));
        }
    }

    private void handleResult(HttpExchange ex) throws IOException {
        if (!isAuthorized(ex)) { send(ex, 401, "Unauthorized"); return; }
        if (!"POST".equals(ex.getRequestMethod())) { send(ex, 405, "Method Not Allowed"); return; }
        AgentResult result = mapper.readValue(ex.getRequestBody(), AgentResult.class);
        if (result.getReport() != null) {
            results.add(result.getReport());
            log.info("Received result from agent {} for workId {}", result.getAgentId(), result.getWorkId());
        }
        send(ex, 200, "{\"status\":\"accepted\"}");
    }

    private void handleHeartbeat(HttpExchange ex) throws IOException {
        if (!isAuthorized(ex)) { send(ex, 401, "Unauthorized"); return; }
        send(ex, 200, "{\"status\":\"ok\"}");
    }

    private void handleSubmit(HttpExchange ex) throws IOException {
        if (!isAuthorized(ex)) { send(ex, 401, "Unauthorized"); return; }
        if (!"POST".equals(ex.getRequestMethod())) { send(ex, 405, "Method Not Allowed"); return; }
        WorkItem item = mapper.readValue(ex.getRequestBody(), WorkItem.class);
        if (item.getWorkId() == null) item.setWorkId(UUID.randomUUID().toString());
        workQueue.offer(item);
        log.info("Work item queued: {} → {}", item.getWorkId(), item.getTarget());
        send(ex, 200, "{\"workId\":\"" + item.getWorkId() + "\"}");
    }

    private void handleScans(HttpExchange ex) throws IOException {
        if (!isAuthorized(ex)) { send(ex, 401, "Unauthorized"); return; }
        List<ScanReport> snapshot = new ArrayList<>(results);
        send(ex, 200, mapper.writeValueAsString(snapshot));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private boolean isAuthorized(HttpExchange ex) {
        if (token == null) return true;
        String auth = ex.getRequestHeaders().getFirst("Authorization");
        return auth != null && auth.equals("Bearer " + token);
    }

    private void send(HttpExchange ex, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }

    /** Send a 204 No Content response with no body, as required by RFC 7230. */
    private void sendNoContent(HttpExchange ex) throws IOException {
        ex.sendResponseHeaders(204, -1);
        ex.getResponseBody().close();
    }

    /** Enqueue work programmatically (used by tests and ScanCommand). */
    public void enqueue(WorkItem item) {
        if (item.getWorkId() == null) item.setWorkId(UUID.randomUUID().toString());
        workQueue.offer(item);
    }

    public List<ScanReport> getResults() { return Collections.unmodifiableList(results); }
}
