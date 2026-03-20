package com.portscanner.api;

import com.portscanner.api.dto.WorkItem;
import com.portscanner.model.ScanReport;
import org.junit.jupiter.api.*;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class ScanAgentClientTest {

    private CoordinatorServer coordinator;
    private ScanAgentClient agent;
    private int coordPort;

    @BeforeEach
    void setup() throws Exception {
        coordinator = new CoordinatorServer(0, "tok");
        coordinator.start();
        coordPort = coordinator.getPort();

        agent = new ScanAgentClient(
                "http://localhost:" + coordPort, "tok", "test-agent");
        agent.start();
    }

    @AfterEach
    void teardown() {
        agent.stop();
        coordinator.stop();
    }

    @Test
    void agentRegistersAndPollsWork() throws Exception {
        // Queue work targeting localhost port 80 only
        WorkItem item = WorkItem.builder()
                .workId("w-test")
                .target("localhost")
                .ports("80")
                .timeout(100)
                .threads(1)
                .build();
        coordinator.enqueue(item);

        // Wait up to 15s for result to appear
        List<ScanReport> results = coordinator.getResults();
        long deadline = System.currentTimeMillis() + 15_000;
        while (results.isEmpty() && System.currentTimeMillis() < deadline) {
            TimeUnit.MILLISECONDS.sleep(200);
        }

        assertFalse(results.isEmpty(), "Agent should have submitted a result");
        assertEquals("localhost", results.get(0).getHost());
    }
}
