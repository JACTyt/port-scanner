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
 * Probes Memcached for unauthenticated access by sending the "stats" command.
 * A response starting with "STAT " indicates the server is accessible without authentication.
 */
public class MemcachedUnauthProbe implements UnauthProbe {

    private static final Logger log = LoggerFactory.getLogger(MemcachedUnauthProbe.class);

    @Override
    public List<Integer> getApplicablePorts() {
        return List.of(11211);
    }

    @Override
    public List<String> getApplicableServices() {
        return List.of("memcache", "memcached");
    }

    @Override
    public UnauthResult probe(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            OutputStream out = socket.getOutputStream();
            out.write("stats\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            String response = reader.readLine();

            if (response != null && response.startsWith("STAT ")) {
                return UnauthResult.builder()
                        .unauthenticated(true)
                        .evidence("Memcached stats response: " + response.trim())
                        .severity("CRITICAL")
                        .service("Memcached")
                        .build();
            }
            return UnauthResult.builder().unauthenticated(false).service("Memcached").build();
        } catch (Exception e) {
            log.debug("Memcached probe failed for {}:{} — {}", host, port, e.getMessage());
            return UnauthResult.builder().unauthenticated(false).service("Memcached").build();
        }
    }
}
