package com.portscanner.scanner.probe;

import com.portscanner.model.UnauthResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Probes Prometheus for unauthenticated /metrics endpoint access.
 * An exposed metrics endpoint leaks internal application and infrastructure telemetry.
 */
public class PromUnauthProbe implements UnauthProbe {

    private static final Logger log = LoggerFactory.getLogger(PromUnauthProbe.class);

    @Override
    public List<Integer> getApplicablePorts() {
        return List.of(9090, 9091, 9093);
    }

    @Override
    public List<String> getApplicableServices() {
        return List.of("prometheus");
    }

    @Override
    public UnauthResult probe(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            OutputStream out = socket.getOutputStream();
            String request = "GET /metrics HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
            out.write(request.getBytes(StandardCharsets.UTF_8));
            out.flush();

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));

            // Check status line and headers for 200 + text/plain
            String statusLine = reader.readLine();
            if (statusLine == null || !statusLine.contains("200")) {
                return UnauthResult.builder().unauthenticated(false).service("Prometheus").build();
            }

            // Read headers looking for Content-Type: text/plain
            String line;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                if (line.toLowerCase().contains("content-type") && line.contains("text/plain")) {
                    return UnauthResult.builder()
                            .unauthenticated(true)
                            .evidence("Prometheus /metrics endpoint accessible without authentication")
                            .severity("MEDIUM")
                            .service("Prometheus")
                            .build();
                }
            }
            // Read body for Prometheus metric format (starts with # HELP or metric_name{)
            String bodyLine = reader.readLine();
            if (bodyLine != null && (bodyLine.startsWith("# HELP") || bodyLine.startsWith("# TYPE")
                    || bodyLine.matches("[a-z_]+\\{?.*\\}?\\s+[0-9].*"))) {
                return UnauthResult.builder()
                        .unauthenticated(true)
                        .evidence("Prometheus metrics exposed: " + bodyLine)
                        .severity("MEDIUM")
                        .service("Prometheus")
                        .build();
            }
            return UnauthResult.builder().unauthenticated(false).service("Prometheus").build();
        } catch (Exception e) {
            log.debug("Prometheus probe failed for {}:{} — {}", host, port, e.getMessage());
            return UnauthResult.builder().unauthenticated(false).service("Prometheus").build();
        }
    }
}
