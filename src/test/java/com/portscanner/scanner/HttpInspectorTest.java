package com.portscanner.scanner;

import com.portscanner.model.HttpInfo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class HttpInspectorTest {

    private ServerSocket serverSocket;
    private int port;
    private Thread serverThread;

    @BeforeEach
    void setUp() throws Exception {
        serverSocket = new ServerSocket(0);
        port = serverSocket.getLocalPort();
    }

    @AfterEach
    void tearDown() throws Exception {
        if (serverThread != null) serverThread.interrupt();
        if (serverSocket != null && !serverSocket.isClosed()) serverSocket.close();
    }

    private void serveResponse(String response) {
        serverThread = new Thread(() -> {
            try {
                Socket client = serverSocket.accept();
                // Read request
                byte[] buf = new byte[4096];
                int n = client.getInputStream().read(buf);
                // Send response
                OutputStream out = client.getOutputStream();
                out.write(response.getBytes(StandardCharsets.UTF_8));
                out.flush();
                Thread.sleep(200);
                client.close();
            } catch (Exception ignored) {}
        });
        serverThread.setDaemon(true);
        serverThread.start();
    }

    @Test
    void parses_status_code_and_server_header() throws Exception {
        String response = "HTTP/1.1 200 OK\r\n" +
                "Server: nginx/1.24.0\r\n" +
                "Content-Type: text/html\r\n" +
                "\r\n" +
                "<html></html>";
        serveResponse(response);

        Optional<HttpInfo> result = HttpInspector.inspect("localhost", port, false, 2000);
        assertTrue(result.isPresent());
        assertEquals(200, result.get().getStatusCode());
        assertEquals("nginx/1.24.0", result.get().getServerHeader());
    }

    @Test
    void detects_php_technology() throws Exception {
        String response = "HTTP/1.1 200 OK\r\n" +
                "Server: Apache/2.4.57\r\n" +
                "X-Powered-By: PHP/8.1.0\r\n" +
                "\r\n";
        serveResponse(response);

        Optional<HttpInfo> result = HttpInspector.inspect("localhost", port, false, 2000);
        assertTrue(result.isPresent());
        assertNotNull(result.get().getDetectedTechnology());
        assertTrue(result.get().getDetectedTechnology().contains("PHP"));
    }

    @Test
    void detects_cloudflare() throws Exception {
        String response = "HTTP/1.1 200 OK\r\n" +
                "Server: cloudflare\r\n" +
                "CF-Ray: 1234567890abcdef-AMS\r\n" +
                "\r\n";
        serveResponse(response);

        Optional<HttpInfo> result = HttpInspector.inspect("localhost", port, false, 2000);
        assertTrue(result.isPresent());
        assertNotNull(result.get().getDetectedTechnology());
        assertTrue(result.get().getDetectedTechnology().contains("Cloudflare"));
    }

    @Test
    void parses_redirect_location() throws Exception {
        String response = "HTTP/1.1 301 Moved Permanently\r\n" +
                "Location: https://www.example.com/\r\n" +
                "Server: Apache\r\n" +
                "\r\n";
        serveResponse(response);

        Optional<HttpInfo> result = HttpInspector.inspect("localhost", port, false, 2000);
        assertTrue(result.isPresent());
        assertEquals(301, result.get().getStatusCode());
        assertEquals("https://www.example.com/", result.get().getRedirectsTo());
    }

    @Test
    void checks_security_headers_presence() throws Exception {
        String response = "HTTP/1.1 200 OK\r\n" +
                "Server: Apache\r\n" +
                "Strict-Transport-Security: max-age=31536000\r\n" +
                "X-Frame-Options: DENY\r\n" +
                "\r\n";
        serveResponse(response);

        Optional<HttpInfo> result = HttpInspector.inspect("localhost", port, false, 2000);
        assertTrue(result.isPresent());
        assertNotNull(result.get().getSecurityHeaders());
        assertTrue(result.get().getSecurityHeaders().get("strict-transport-security"));
        assertTrue(result.get().getSecurityHeaders().get("x-frame-options"));
        assertFalse(result.get().getSecurityHeaders().get("content-security-policy"));
    }

    @Test
    void returns_empty_when_no_server() throws Exception {
        int closedPort = serverSocket.getLocalPort();
        serverSocket.close();
        Optional<HttpInfo> result = HttpInspector.inspect("localhost", closedPort, false, 200);
        assertTrue(result.isEmpty());
    }
}
