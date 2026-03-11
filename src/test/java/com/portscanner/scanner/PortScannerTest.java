package com.portscanner.scanner;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanResult;
import com.portscanner.service.ServiceMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.ServerSocket;

import static org.junit.jupiter.api.Assertions.*;

class PortScannerTest {

    private ServerSocket serverSocket;
    private int openPort;
    private PortScanner scanner;

    @BeforeEach
    void setUp() throws IOException {
        // Bind to port 0 — OS assigns a free port
        serverSocket = new ServerSocket(0);
        openPort = serverSocket.getLocalPort();
        scanner = new PortScanner(10, 500, false, new ServiceMapper());
    }

    @AfterEach
    void tearDown() throws IOException {
        if (serverSocket != null && !serverSocket.isClosed()) {
            serverSocket.close();
        }
    }

    @Test
    void scanPort_openPort_returnsOpen() {
        ScanResult result = scanner.scanPort("localhost", openPort);
        assertEquals(PortStatus.OPEN, result.getStatus());
        assertEquals(openPort, result.getPort());
        assertTrue(result.getResponseTimeMs() >= 0);
    }

    @Test
    void scanPort_closedPort_returnsClosed() throws IOException {
        // Close server so the port is not listening
        int closedPort = serverSocket.getLocalPort();
        serverSocket.close();

        ScanResult result = scanner.scanPort("localhost", closedPort);
        assertEquals(PortStatus.CLOSED, result.getStatus());
    }

    @Test
    void scanPort_openPort_hasServiceName() {
        // Use port 80's slot to verify serviceName enrichment on well-known port
        // We scan our open test port — service will be "Unknown" since it's dynamic
        ScanResult result = scanner.scanPort("localhost", openPort);
        assertNotNull(result.getServiceName());
    }
}
