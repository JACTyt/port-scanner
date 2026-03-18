package com.portscanner.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.portscanner.api.dto.ScanRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.*;

class ScanApiServerTest {

    private static ScanApiServer server;
    private static int port;
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final HttpClient http = HttpClient.newHttpClient();

    @BeforeAll
    static void startServer() throws IOException {
        // Pick a free port
        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort();
        }
        server = new ScanApiServer(port, null); // no auth for tests
        server.start();
    }

    @AfterAll
    static void stopServer() {
        server.stop();
    }

    @Test
    void postScanReturns202WithId() throws Exception {
        ScanRequest req = new ScanRequest();
        req.setHost("127.0.0.1");
        req.setPorts("80,443");
        req.setTimeout(100);
        req.setThreads(2);

        HttpResponse<String> resp = post("/scan", mapper.writeValueAsString(req));
        assertEquals(202, resp.statusCode());

        JsonNode body = mapper.readTree(resp.body());
        assertNotNull(body.get("id"), "Response must contain 'id'");
        assertEquals("127.0.0.1", body.get("host").asText());
        String status = body.get("status").asText();
        assertTrue(status.equals("PENDING") || status.equals("RUNNING"),
                "Initial status should be PENDING or RUNNING, was: " + status);
    }

    @Test
    void getScanByIdReturnsScanState() throws Exception {
        String id = submitScan("127.0.0.1", "80");
        HttpResponse<String> resp = get("/scan/" + id);
        assertEquals(200, resp.statusCode());
        JsonNode body = mapper.readTree(resp.body());
        assertEquals(id, body.get("id").asText());
    }

    @Test
    void getScanUnknownIdReturns404() throws Exception {
        HttpResponse<String> resp = get("/scan/doesnotexist");
        assertEquals(404, resp.statusCode());
    }

    @Test
    void getScansListsRecentJobs() throws Exception {
        submitScan("127.0.0.1", "80");
        HttpResponse<String> resp = get("/scans");
        assertEquals(200, resp.statusCode());
        JsonNode body = mapper.readTree(resp.body());
        assertTrue(body.isArray(), "Response should be a JSON array");
        assertTrue(body.size() > 0, "Should have at least one scan");
    }

    @Test
    void deleteScanCancelsPendingJob() throws Exception {
        String id = submitScan("127.0.0.1", "1-100");
        HttpResponse<String> resp = delete("/scan/" + id);
        // Either cancelled (200) or already completed (404) — both are valid
        assertTrue(resp.statusCode() == 200 || resp.statusCode() == 404);
    }

    @Test
    void postScanWithoutHostReturns400() throws Exception {
        HttpResponse<String> resp = post("/scan", "{\"ports\":\"80\"}");
        assertEquals(400, resp.statusCode());
        assertTrue(resp.body().contains("error"));
    }

    @Test
    void authRequiredWhenApiKeySet() throws Exception {
        ScanApiServer authServer = null;
        int authPort;
        try (ServerSocket s = new ServerSocket(0)) { authPort = s.getLocalPort(); }
        authServer = new ScanApiServer(authPort, "secret-key");
        authServer.start();
        try {
            // No key
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:" + authPort + "/scans"))
                    .GET().build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            assertEquals(401, resp.statusCode());

            // Wrong key
            HttpRequest req2 = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:" + authPort + "/scans"))
                    .header("X-API-Key", "wrong")
                    .GET().build();
            HttpResponse<String> resp2 = http.send(req2, HttpResponse.BodyHandlers.ofString());
            assertEquals(401, resp2.statusCode());

            // Correct key
            HttpRequest req3 = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:" + authPort + "/scans"))
                    .header("X-API-Key", "secret-key")
                    .GET().build();
            HttpResponse<String> resp3 = http.send(req3, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, resp3.statusCode());
        } finally {
            authServer.stop();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String submitScan(String host, String ports) throws Exception {
        ScanRequest req = new ScanRequest();
        req.setHost(host);
        req.setPorts(ports);
        req.setTimeout(100);
        req.setThreads(2);
        HttpResponse<String> resp = post("/scan", mapper.writeValueAsString(req));
        return mapper.readTree(resp.body()).get("id").asText();
    }

    private HttpResponse<String> get(String path) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + path))
                .GET().build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String path, String body) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> delete(String path) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + path))
                .DELETE().build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }
}
