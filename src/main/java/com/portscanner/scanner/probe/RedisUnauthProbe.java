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
 * Probes Redis for unauthenticated access by sending a PING command.
 * A "+PONG" response indicates the server accepts commands without AUTH.
 */
public class RedisUnauthProbe implements UnauthProbe {

    private static final Logger log = LoggerFactory.getLogger(RedisUnauthProbe.class);

    @Override
    public List<Integer> getApplicablePorts() {
        return List.of(6379, 6380);
    }

    @Override
    public List<String> getApplicableServices() {
        return List.of("redis");
    }

    @Override
    public UnauthResult probe(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            OutputStream out = socket.getOutputStream();
            out.write("PING\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            String response = reader.readLine();

            if (response != null && response.startsWith("+PONG")) {
                return UnauthResult.builder()
                        .unauthenticated(true)
                        .evidence("Redis responded: " + response.trim())
                        .severity("CRITICAL")
                        .service("Redis")
                        .build();
            }
            // AUTH required — server returned -NOAUTH or similar
            return UnauthResult.builder()
                    .unauthenticated(false)
                    .service("Redis")
                    .build();
        } catch (Exception e) {
            log.debug("Redis unauth probe failed for {}:{} — {}", host, port, e.getMessage());
            return UnauthResult.builder().unauthenticated(false).service("Redis").build();
        }
    }
}
