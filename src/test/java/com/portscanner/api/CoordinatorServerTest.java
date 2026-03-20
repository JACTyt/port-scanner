package com.portscanner.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.portscanner.api.dto.AgentRegistration;
import com.portscanner.api.dto.AgentResult;
import com.portscanner.api.dto.WorkItem;
import com.portscanner.model.ScanReport;
import org.junit.jupiter.api.*;

import java.net.URI;
import java.net.http.*;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CoordinatorServerTest {

    private CoordinatorServer coordinator;
    private HttpClient client;
    private ObjectMapper mapper;
    private int port;

    @BeforeEach
    void start() throws Exception {
        coordinator = new CoordinatorServer(0, "test-token");
        coordinator.start();
        port = coordinator.getPort();
        client = HttpClient.newHttpClient();
        mapper = new ObjectMapper().registerModule(new JavaTimeModule());
    }

    @AfterEach
    void stop() { coordinator.stop(); }

    private HttpResponse<String> post(String path, Object body) throws Exception {
        String json = mapper.writeValueAsString(body);
        return client.send(HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + path))
                .header("Authorization", "Bearer test-token")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(String path) throws Exception {
        return client.send(HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + path))
                .header("Authorization", "Bearer test-token")
                .GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void agentCanRegister() throws Exception {
        AgentRegistration reg = AgentRegistration.builder()
                .agentId("agent-1").label("dmz").token("test-token").build();
        HttpResponse<String> resp = post("/agent/register", reg);
        assertEquals(200, resp.statusCode());
        assertTrue(resp.body().contains("registered"));
    }

    @Test
    void workItemDispatchedToAgent() throws Exception {
        WorkItem item = WorkItem.builder()
                .target("192.168.1.1").ports("80,443").timeout(200).threads(10).build();
        coordinator.enqueue(item);

        HttpResponse<String> resp = get("/agent/work");
        assertEquals(200, resp.statusCode());
        WorkItem received = mapper.readValue(resp.body(), WorkItem.class);
        assertEquals("192.168.1.1", received.getTarget());
    }

    @Test
    void noWorkReturns204() throws Exception {
        HttpResponse<String> resp = get("/agent/work");
        assertEquals(204, resp.statusCode());
    }

    @Test
    void agentResultAppearsInScans() throws Exception {
        ScanReport report = ScanReport.builder()
                .host("192.168.1.1").scannedAt(LocalDateTime.now())
                .openPorts(List.of()).build();
        AgentResult result = AgentResult.builder()
                .workId("w1").agentId("agent-1").report(report).build();
        post("/agent/result", result);

        HttpResponse<String> scans = get("/scans");
        assertEquals(200, scans.statusCode());
        assertTrue(scans.body().contains("192.168.1.1"));
    }

    @Test
    void unauthorizedWithoutToken() throws Exception {
        HttpResponse<String> resp = client.send(HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/scans"))
                .GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(401, resp.statusCode());
    }
}
