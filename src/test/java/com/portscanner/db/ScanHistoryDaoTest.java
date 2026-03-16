package com.portscanner.db;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class ScanHistoryDaoTest {

    @TempDir
    Path tempDir;

    private ScanHistoryDao dao;

    @BeforeEach
    void setUp() {
        HistorySchema.setDbPathForTesting(tempDir.resolve("test-history.db").toString());
        dao = new ScanHistoryDao();
    }

    @AfterEach
    void tearDown() {
        HistorySchema.setDbPathForTesting(null);
    }

    private ScanReport buildReport(String host, int... openPorts) {
        List<ScanResult> open = new java.util.ArrayList<>();
        for (int p : openPorts) {
            open.add(ScanResult.builder().port(p).status(PortStatus.OPEN)
                    .serviceName("TEST").responseTimeMs(10).build());
        }
        return ScanReport.builder()
                .host(host).resolvedIp("127.0.0.1")
                .scannedAt(LocalDateTime.now()).durationMs(100)
                .totalScanned(1024).openCount(open.size()).filteredCount(0)
                .openPorts(open).filteredPorts(List.of())
                .build();
    }

    @Test
    void save_and_retrieve_single_scan() {
        ScanReport report = buildReport("testhost", 80, 443);
        dao.save(report);

        List<ScanReport> history = dao.getHistory("testhost", 10);
        assertEquals(1, history.size());
        assertEquals("testhost", history.get(0).getHost());
        assertEquals(2, history.get(0).getOpenCount());
    }

    @Test
    void getHistory_returns_empty_for_unknown_host() {
        List<ScanReport> history = dao.getHistory("no-such-host", 10);
        assertTrue(history.isEmpty());
    }

    @Test
    void getHistory_respects_limit() {
        for (int i = 0; i < 5; i++) {
            dao.save(buildReport("limithost", 80));
        }
        List<ScanReport> history = dao.getHistory("limithost", 3);
        assertEquals(3, history.size());
    }

    @Test
    void getMostRecent_returns_latest_scan() throws InterruptedException {
        dao.save(buildReport("recenthost", 22));
        Thread.sleep(10); // ensure distinct scannedAt timestamps
        ScanReport newer = buildReport("recenthost", 80, 443);
        dao.save(newer);

        Optional<ScanReport> most = dao.getMostRecent("recenthost");
        assertTrue(most.isPresent());
        assertEquals(2, most.get().getOpenCount());
    }

    @Test
    void getMostRecent_returns_empty_for_unknown_host() {
        Optional<ScanReport> result = dao.getMostRecent("nonexistent");
        assertFalse(result.isPresent());
    }

    @Test
    void history_preserves_open_port_details() {
        dao.save(buildReport("portdetailhost", 22, 80, 443));
        List<ScanReport> history = dao.getHistory("portdetailhost", 1);
        assertFalse(history.isEmpty());
        assertEquals(3, history.get(0).getOpenPorts().size());
    }

    @Test
    void multiple_hosts_are_isolated() {
        dao.save(buildReport("host-a", 22));
        dao.save(buildReport("host-b", 80, 443));

        assertEquals(1, dao.getHistory("host-a", 10).size());
        assertEquals(1, dao.getHistory("host-b", 10).size());
        assertEquals(2, dao.getHistory("host-b", 10).get(0).getOpenCount());
    }
}
