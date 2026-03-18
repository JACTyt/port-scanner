package com.portscanner.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.portscanner.api.dto.ScanRequest;
import com.portscanner.api.dto.ScanResponse;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.Executors;

/**
 * Embedded HTTP API server (JDK {@code com.sun.net.httpserver} — no extra dependency).
 *
 * <p>Endpoints:
 * <pre>
 *   POST   /scan          – submit a scan job, returns { id, status, host, submittedAt }
 *   GET    /scan/{id}     – fetch job status + results
 *   GET    /scan/{id}/stream – SSE stream of live status (polls internally every 1 s)
 *   GET    /scans         – list the last 50 jobs
 *   DELETE /scan/{id}     – cancel a PENDING or RUNNING job
 * </pre>
 *
 * All routes require {@code X-API-Key} header when {@code --serve-auth} is set.
 */
public class ScanApiServer {

    private static final Logger log = LoggerFactory.getLogger(ScanApiServer.class);

    private final HttpServer server;
    private final ScanJobManager jobManager;
    private final ObjectMapper mapper;
    private final String apiKey; // null = no auth

    public ScanApiServer(int port, String apiKey) throws IOException {
        this.apiKey     = apiKey;
        this.jobManager = new ScanJobManager();
        this.mapper     = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .enable(SerializationFeature.INDENT_OUTPUT);

        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/scan",  this::handleScan);
        server.createContext("/scans", this::handleScans);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    }

    public void start() {
        server.start();
        log.info("REST API server listening on port {}", server.getAddress().getPort());
    }

    public void stop() {
        server.stop(1);
        jobManager.shutdown();
    }

    // ── /scan dispatcher ─────────────────────────────────────────────────────

    private void handleScan(HttpExchange ex) throws IOException {
        if (!authenticate(ex)) return;

        String path   = ex.getRequestURI().getPath();   // e.g. /scan  or  /scan/abc1234  or  /scan/abc1234/stream
        String method = ex.getRequestMethod();
        String[] segments = path.replaceAll("^/+", "").split("/");
        // segments[0] = "scan"  segments[1] = id (optional)  segments[2] = "stream" (optional)

        // POST /scan
        if ("POST".equals(method) && segments.length == 1) {
            try {
                ScanRequest req = mapper.readValue(ex.getRequestBody(), ScanRequest.class);
                if (req.getHost() == null || req.getHost().isBlank()) {
                    sendJson(ex, 400, "{\"error\":\"host is required\"}");
                    return;
                }
                ScanResponse resp = jobManager.submit(req);
                sendJson(ex, 202, mapper.writeValueAsString(resp));
            } catch (Exception e) {
                sendJson(ex, 400, "{\"error\":\"" + escape(e.getMessage()) + "\"}");
            }
            return;
        }

        // Routes that need an id
        if (segments.length >= 2) {
            String id = segments[1];
            boolean isStream = segments.length >= 3 && "stream".equals(segments[2]);

            // GET /scan/{id}/stream  — SSE
            if ("GET".equals(method) && isStream) {
                handleStream(ex, id);
                return;
            }

            // GET /scan/{id}
            if ("GET".equals(method)) {
                ScanResponse resp = jobManager.get(id);
                if (resp == null) sendJson(ex, 404, "{\"error\":\"scan not found\"}");
                else              sendJson(ex, 200, mapper.writeValueAsString(resp));
                return;
            }

            // DELETE /scan/{id}
            if ("DELETE".equals(method)) {
                boolean cancelled = jobManager.cancel(id);
                if (cancelled) sendJson(ex, 200, "{\"status\":\"cancelled\"}");
                else           sendJson(ex, 404, "{\"error\":\"scan not found or already completed\"}");
                return;
            }
        }

        sendJson(ex, 405, "{\"error\":\"method not allowed\"}");
    }

    // ── GET /scans ────────────────────────────────────────────────────────────

    private void handleScans(HttpExchange ex) throws IOException {
        if (!authenticate(ex)) return;
        if (!"GET".equals(ex.getRequestMethod())) {
            sendJson(ex, 405, "{\"error\":\"method not allowed\"}");
            return;
        }
        List<ScanResponse> scans = jobManager.listRecent();
        sendJson(ex, 200, mapper.writeValueAsString(scans));
    }

    // ── SSE stream ────────────────────────────────────────────────────────────

    private void handleStream(HttpExchange ex, String id) throws IOException {
        ex.getResponseHeaders().set("Content-Type", "text/event-stream");
        ex.getResponseHeaders().set("Cache-Control", "no-cache");
        ex.getResponseHeaders().set("Connection", "keep-alive");
        ex.sendResponseHeaders(200, 0); // chunked

        try (OutputStream out = ex.getResponseBody()) {
            for (int i = 0; i < 120; i++) { // max ~2 min of polling
                ScanResponse resp = jobManager.get(id);
                if (resp == null) {
                    writeEvent(out, "{\"error\":\"not found\"}");
                    break;
                }
                writeEvent(out, mapper.writeValueAsString(resp));
                String status = resp.getStatus();
                if ("DONE".equals(status) || "FAILED".equals(status) || "CANCELLED".equals(status)) {
                    break;
                }
                try { Thread.sleep(1_000); } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
    }

    private static void writeEvent(OutputStream out, String data) throws IOException {
        String event = "data: " + data + "\n\n";
        out.write(event.getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private boolean authenticate(HttpExchange ex) throws IOException {
        if (apiKey == null || apiKey.isBlank()) return true;
        String header = ex.getRequestHeaders().getFirst("X-API-Key");
        if (!apiKey.equals(header)) {
            sendJson(ex, 401, "{\"error\":\"unauthorized — X-API-Key header required\"}");
            return false;
        }
        return true;
    }

    private static void sendJson(HttpExchange ex, int status, String json) throws IOException {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, body.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(body);
        }
    }

    private static String escape(String s) {
        return s == null ? "" : s.replace("\"", "'");
    }
}
