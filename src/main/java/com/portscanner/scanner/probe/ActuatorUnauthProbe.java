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
 * Probes Spring Boot Actuator for unauthenticated access to /actuator endpoint.
 * An exposed Actuator reveals application internals, env vars, heap dumps, etc.
 */
public class ActuatorUnauthProbe implements UnauthProbe {

    private static final Logger log = LoggerFactory.getLogger(ActuatorUnauthProbe.class);

    @Override
    public List<Integer> getApplicablePorts() {
        return List.of(8080, 8081, 8443, 8888, 5000, 3000);
    }

    @Override
    public List<String> getApplicableServices() {
        return List.of("http", "https", "spring", "actuator");
    }

    @Override
    public UnauthResult probe(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            OutputStream out = socket.getOutputStream();
            String request = "GET /actuator HTTP/1.1\r\nHost: " + host
                    + "\r\nAccept: application/json\r\nConnection: close\r\n\r\n";
            out.write(request.getBytes(StandardCharsets.UTF_8));
            out.flush();

            // Read response
            StringBuilder body = new StringBuilder();
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            String line;
            boolean inBody = false;
            while ((line = reader.readLine()) != null) {
                if (line.isEmpty()) { inBody = true; continue; }
                if (inBody) body.append(line);
                if (body.length() > 1024) break;
            }

            String bodyStr = body.toString();
            if (bodyStr.contains("\"_links\"")) {
                return UnauthResult.builder()
                        .unauthenticated(true)
                        .evidence("Spring Boot Actuator /actuator endpoint accessible without authentication")
                        .severity("MEDIUM")
                        .service("Spring Actuator")
                        .build();
            }
            return UnauthResult.builder().unauthenticated(false).service("Spring Actuator").build();
        } catch (Exception e) {
            log.debug("Actuator probe failed for {}:{} — {}", host, port, e.getMessage());
            return UnauthResult.builder().unauthenticated(false).service("Spring Actuator").build();
        }
    }
}
