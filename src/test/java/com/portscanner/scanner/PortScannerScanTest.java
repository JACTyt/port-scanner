package com.portscanner.scanner;

import com.portscanner.model.ScanReport;
import com.portscanner.service.ServiceMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

import static org.junit.jupiter.api.Assertions.*;

class PortScannerScanTest {

    private ServerSocket serverSocket;
    private int openPort;
    private PortScanner scanner;

    @BeforeEach
    void setUp() throws IOException {
        serverSocket = new ServerSocket(0);
        openPort = serverSocket.getLocalPort();
        scanner = new PortScanner(10, 500, false, new ServiceMapper());
    }

    @AfterEach
    void tearDown() throws IOException {
        if (serverSocket != null && !serverSocket.isClosed()) serverSocket.close();
    }

    @Test
    void scan_returns_report_with_correct_host() throws Exception {
        ScanReport report = scanner.scan("localhost", InetAddress.getLoopbackAddress(), new int[]{openPort});
        assertEquals("localhost", report.getHost());
        assertEquals("127.0.0.1", report.getResolvedIp());
    }

    @Test
    void scan_detects_open_listening_port() throws Exception {
        ScanReport report = scanner.scan("localhost", InetAddress.getLoopbackAddress(), new int[]{openPort});
        assertFalse(report.getOpenPorts().isEmpty(), "Expected the listening port to be detected as open");
        assertEquals(openPort, report.getOpenPorts().get(0).getPort());
    }

    @Test
    void scan_open_count_matches_open_ports_list() throws Exception {
        ScanReport report = scanner.scan("localhost", InetAddress.getLoopbackAddress(), new int[]{openPort});
        assertEquals(report.getOpenPorts().size(), report.getOpenCount());
    }

    @Test
    void scan_records_total_ports_scanned() throws Exception {
        ScanReport report = scanner.scan("localhost", InetAddress.getLoopbackAddress(), new int[]{openPort});
        assertEquals(1, report.getTotalScanned());
    }

    @Test
    void scan_has_non_null_timestamp_and_non_negative_duration() throws Exception {
        ScanReport report = scanner.scan("localhost", InetAddress.getLoopbackAddress(), new int[]{openPort});
        assertNotNull(report.getScannedAt());
        assertTrue(report.getDurationMs() >= 0);
    }

    @Test
    void closed_port_does_not_appear_in_open_ports() throws Exception {
        int closedPort = serverSocket.getLocalPort();
        serverSocket.close();
        ScanReport report = scanner.scan("localhost", InetAddress.getLoopbackAddress(), new int[]{closedPort});
        assertTrue(report.getOpenPorts().isEmpty());
        assertEquals(0, report.getOpenCount());
    }

    @Test
    void scan_multiple_ports_counts_are_consistent() throws Exception {
        // Open one port, use a second closed port — total should be 2 scanned
        int closedPort = serverSocket.getLocalPort();
        serverSocket.close();
        ServerSocket second = new ServerSocket(0);
        int secondOpen = second.getLocalPort();
        try {
            ScanReport report = scanner.scan("localhost", InetAddress.getLoopbackAddress(),
                    new int[]{closedPort, secondOpen});
            assertEquals(2, report.getTotalScanned());
            assertEquals(1, report.getOpenCount());
            assertEquals(secondOpen, report.getOpenPorts().get(0).getPort());
        } finally {
            second.close();
        }
    }
}
