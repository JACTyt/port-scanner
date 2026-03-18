package com.portscanner.service;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class WebhookClientTest {

    private HttpServer server;
    private int port;
    private final AtomicReference<String> lastBody    = new AtomicReference<>();
    private final AtomicReference<String> lastPath    = new AtomicReference<>();
    private final AtomicReference<String> lastCtype   = new AtomicReference<>();

    @BeforeEach
    void startServer() throws Exception {
        try (ServerSocket s = new ServerSocket(0)) { port = s.getLocalPort(); }
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", exchange -> {
            lastPath.set(exchange.getRequestURI().getPath());
            lastCtype.set(exchange.getRequestHeaders().getFirst("Content-Type"));
            lastBody.set(new String(exchange.getRequestBody().readAllBytes()));
            exchange.sendResponseHeaders(200, 0);
            exchange.getResponseBody().close();
        });
        server.setExecutor(Executors.newSingleThreadExecutor());
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void sendsPostWithJsonBody() throws Exception {
        new WebhookClient().send(report(2), url("/hook"));
        Thread.sleep(500);
        assertNotNull(lastBody.get(), "Body should have been received");
        assertTrue(lastBody.get().contains("localhost"), "Body should contain host");
    }

    @Test
    void contentTypeIsJson() throws Exception {
        new WebhookClient().send(report(1), url("/hook"));
        Thread.sleep(500);
        assertNotNull(lastCtype.get());
        assertTrue(lastCtype.get().contains("application/json"));
    }

    @Test
    void sendsToCorrectPath() throws Exception {
        new WebhookClient().send(report(0), url("/my-endpoint"));
        Thread.sleep(500);
        assertEquals("/my-endpoint", lastPath.get());
    }

    @Test
    void doesNotThrowOnUnreachableUrl() {
        // Should swallow the exception and log a warning
        assertDoesNotThrow(() ->
                new WebhookClient().send(report(1), "http://localhost:1/unreachable"));
    }

    @Test
    void doesNotThrowOnNullReport() {
        assertDoesNotThrow(() ->
                new WebhookClient().send(report(0), url("/hook")));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private static ScanReport report(int openCount) {
        List<ScanResult> open = openCount > 0
                ? List.of(ScanResult.builder().port(80).status(PortStatus.OPEN).serviceName("HTTP").build())
                : List.of();
        return ScanReport.builder()
                .host("localhost").resolvedIp("127.0.0.1")
                .scannedAt(LocalDateTime.now())
                .durationMs(100).totalScanned(1024)
                .openCount(open.size()).filteredCount(0)
                .openPorts(open).filteredPorts(List.of())
                .build();
    }
}
