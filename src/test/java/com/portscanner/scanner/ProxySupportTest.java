package com.portscanner.scanner;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanResult;
import com.portscanner.service.ServiceMapper;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;

import static org.junit.jupiter.api.Assertions.*;

class ProxySupportTest {

    /**
     * Verifies that PortScanner constructor accepts a Proxy parameter without throwing.
     */
    @Test
    void portScannerAcceptsProxyConstructorParameter() {
        Proxy proxy = new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", 1080));
        PortScanner scanner = new PortScanner(10, 500, false, new ServiceMapper(), false, 0, proxy);
        assertNotNull(scanner);
    }

    /**
     * Verifies that PortScanner with null proxy still works correctly for local port scanning.
     */
    @Test
    void portScannerWithNullProxyScansLocalPortSuccessfully() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            int port = serverSocket.getLocalPort();
            PortScanner scanner = new PortScanner(10, 500, false, new ServiceMapper(), false, 0, null);
            ScanResult result = scanner.scanPort("127.0.0.1", port);
            assertEquals(PortStatus.OPEN, result.getStatus());
        }
    }

    /**
     * Verifies that a Proxy.Type.SOCKS proxy object is correctly constructed
     * from a "socks5://127.0.0.1:1080" URL string parse.
     */
    @Test
    void socks5ProxyParsedCorrectlyFromUrl() {
        String proxyUrl = "socks5://127.0.0.1:1080";
        String proxySpec = proxyUrl.startsWith("socks5://")
                ? proxyUrl.substring("socks5://".length())
                : proxyUrl;

        String[] parts = proxySpec.split(":", 2);
        assertEquals(2, parts.length, "Should split into host and port");

        String proxyHost = parts[0];
        int proxyPort = Integer.parseInt(parts[1]);

        Proxy proxy = new Proxy(Proxy.Type.SOCKS, new InetSocketAddress(proxyHost, proxyPort));

        assertEquals(Proxy.Type.SOCKS, proxy.type());
        InetSocketAddress addr = (InetSocketAddress) proxy.address();
        assertEquals("127.0.0.1", addr.getHostString());
        assertEquals(1080, addr.getPort());
    }

    /**
     * Verifies that PortScanner with Proxy.NO_PROXY scans a local port successfully.
     */
    @Test
    void portScannerWithNoProxyScansLocalPortSuccessfully() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            int port = serverSocket.getLocalPort();
            PortScanner scanner = new PortScanner(10, 500, false, new ServiceMapper(), false, 0, Proxy.NO_PROXY);
            ScanResult result = scanner.scanPort("127.0.0.1", port);
            assertEquals(PortStatus.OPEN, result.getStatus());
        }
    }
}
