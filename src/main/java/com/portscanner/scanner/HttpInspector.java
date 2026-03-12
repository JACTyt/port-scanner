package com.portscanner.scanner;

import com.portscanner.model.HttpInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class HttpInspector {

    private static final Logger log = LoggerFactory.getLogger(HttpInspector.class);

    private static final List<String> SECURITY_HEADERS = List.of(
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy"
    );

    public static Optional<HttpInfo> inspect(String host, int port, boolean useTls, int timeoutMs) {
        try {
            Socket socket;
            if (useTls) {
                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                socket = factory.createSocket();
            } else {
                socket = new Socket();
            }

            try (Socket s = socket) {
                s.connect(new InetSocketAddress(host, port), timeoutMs);
                s.setSoTimeout(timeoutMs);

                String request = "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n";
                OutputStream out = s.getOutputStream();
                out.write(request.getBytes(StandardCharsets.UTF_8));
                out.flush();

                BufferedReader reader = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));

                // Read status line
                String statusLine = reader.readLine();
                if (statusLine == null) return Optional.empty();

                int statusCode = 0;
                try {
                    String[] parts = statusLine.split(" ", 3);
                    if (parts.length >= 2) {
                        statusCode = Integer.parseInt(parts[1]);
                    }
                } catch (NumberFormatException e) {
                    return Optional.empty();
                }

                // Read headers until blank line
                Map<String, String> headers = new LinkedHashMap<>();
                String line;
                while ((line = reader.readLine()) != null && !line.isEmpty()) {
                    int colon = line.indexOf(':');
                    if (colon > 0) {
                        String key = line.substring(0, colon).trim().toLowerCase();
                        String value = line.substring(colon + 1).trim();
                        headers.put(key, value);
                    }
                }

                // Parse fields
                String serverHeader = headers.get("server");
                String poweredBy = headers.get("x-powered-by");
                String redirectsTo = (statusCode == 301 || statusCode == 302 || statusCode == 307 || statusCode == 308)
                        ? headers.get("location") : null;

                // Technology detection
                StringBuilder tech = new StringBuilder();
                if (poweredBy != null) {
                    String pb = poweredBy.toLowerCase();
                    if (pb.startsWith("php")) {
                        tech.append("PHP ").append(poweredBy.substring(4).trim());
                    } else if (pb.contains("asp.net")) {
                        tech.append("ASP.NET");
                    } else {
                        tech.append(poweredBy);
                    }
                }
                String xGenerator = headers.get("x-generator");
                if (xGenerator != null && xGenerator.toLowerCase().contains("wordpress")) {
                    if (tech.length() > 0) tech.append(", ");
                    tech.append("WordPress");
                }
                if (headers.containsKey("cf-ray")) {
                    if (tech.length() > 0) tech.append(" ");
                    tech.append("(Cloudflare CDN)");
                }
                if (headers.containsKey("x-varnish")) {
                    if (tech.length() > 0) tech.append(" ");
                    tech.append("(Varnish cache)");
                }
                if (headers.containsKey("x-served-by")) {
                    if (tech.length() > 0) tech.append(" ");
                    tech.append("(Fastly CDN)");
                }

                // Security headers audit
                Map<String, Boolean> securityHeadersMap = new LinkedHashMap<>();
                for (String h : SECURITY_HEADERS) {
                    securityHeadersMap.put(h, headers.containsKey(h));
                }

                return Optional.of(HttpInfo.builder()
                        .statusCode(statusCode)
                        .serverHeader(serverHeader)
                        .poweredBy(poweredBy)
                        .detectedTechnology(tech.length() > 0 ? tech.toString() : null)
                        .redirectsTo(redirectsTo)
                        .securityHeaders(securityHeadersMap)
                        .build());
            }
        } catch (Exception e) {
            log.debug("HTTP inspection failed for {}:{} — {}", host, port, e.getMessage());
            return Optional.empty();
        }
    }
}
