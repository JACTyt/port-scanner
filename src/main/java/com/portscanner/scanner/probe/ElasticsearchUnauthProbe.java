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
 * Probes Elasticsearch / OpenSearch for unauthenticated access by sending a GET / HTTP request.
 * A JSON response containing "cluster_name" indicates the server is accessible without auth.
 */
public class ElasticsearchUnauthProbe implements UnauthProbe {

    private static final Logger log = LoggerFactory.getLogger(ElasticsearchUnauthProbe.class);

    @Override
    public List<Integer> getApplicablePorts() {
        return List.of(9200, 9201, 9202);
    }

    @Override
    public List<String> getApplicableServices() {
        return List.of("elasticsearch", "opensearch", "elastic");
    }

    @Override
    public UnauthResult probe(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            OutputStream out = socket.getOutputStream();
            String request = "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
            out.write(request.getBytes(StandardCharsets.UTF_8));
            out.flush();

            // Read response body (skip headers, look for cluster_name)
            StringBuilder body = new StringBuilder();
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            String line;
            boolean inBody = false;
            while ((line = reader.readLine()) != null) {
                if (line.isEmpty()) { inBody = true; continue; }
                if (inBody) body.append(line);
                if (body.length() > 2048) break;
            }

            String bodyStr = body.toString();
            if (bodyStr.contains("\"cluster_name\"") || bodyStr.contains("\"name\"") && bodyStr.contains("\"version\"")) {
                return UnauthResult.builder()
                        .unauthenticated(true)
                        .evidence("Elasticsearch responded with cluster info without authentication")
                        .severity("CRITICAL")
                        .service("Elasticsearch")
                        .build();
            }
            // 401 or 403 — auth required
            return UnauthResult.builder().unauthenticated(false).service("Elasticsearch").build();
        } catch (Exception e) {
            log.debug("Elasticsearch probe failed for {}:{} — {}", host, port, e.getMessage());
            return UnauthResult.builder().unauthenticated(false).service("Elasticsearch").build();
        }
    }
}
