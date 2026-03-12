package com.portscanner.plugin.builtin;

import com.portscanner.model.ScanResult;
import com.portscanner.plugin.PluginContext;
import com.portscanner.plugin.ScanPlugin;

import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * Plugin that fetches the HTML title from HTTP/HTTPS ports and sets it as the banner.
 */
public class HttpTitlePlugin implements ScanPlugin {

    private static final Set<Integer> HTTP_PORTS = Set.of(80, 443, 8080, 8443);
    private static final int MAX_BYTES = 8192;

    @Override
    public String name() {
        return "http-title";
    }

    @Override
    public boolean appliesTo(ScanResult result) {
        if (HTTP_PORTS.contains(result.getPort())) {
            return true;
        }
        String service = result.getServiceName();
        return service != null && service.toLowerCase().contains("http");
    }

    @Override
    public void execute(ScanResult result, PluginContext ctx) {
        try {
            int port = result.getPort();
            boolean useSsl = (port == 443 || port == 8443);
            String host = ctx.getHost();
            int timeout = ctx.getTimeoutMs();

            Socket socket;
            if (useSsl) {
                socket = SSLSocketFactory.getDefault().createSocket();
                socket.connect(new java.net.InetSocketAddress(host, port), timeout);
            } else {
                socket = new Socket();
                socket.connect(new java.net.InetSocketAddress(host, port), timeout);
            }

            try (socket) {
                socket.setSoTimeout(timeout);

                String request = "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
                OutputStream out = socket.getOutputStream();
                out.write(request.getBytes(StandardCharsets.UTF_8));
                out.flush();

                // Read up to MAX_BYTES looking for </title>
                StringBuilder sb = new StringBuilder();
                byte[] buf = new byte[MAX_BYTES];
                int totalRead = 0;
                java.io.InputStream in = socket.getInputStream();
                int n;
                while (totalRead < MAX_BYTES && (n = in.read(buf, 0, Math.min(buf.length, MAX_BYTES - totalRead))) != -1) {
                    sb.append(new String(buf, 0, n, StandardCharsets.UTF_8));
                    totalRead += n;
                    String lower = sb.toString().toLowerCase();
                    if (lower.contains("</title>")) {
                        break;
                    }
                }

                String body = sb.toString();
                String lower = body.toLowerCase();
                int start = lower.indexOf("<title>");
                int end = lower.indexOf("</title>");
                if (start != -1 && end != -1 && end > start) {
                    String title = body.substring(start + 7, end).trim();
                    if (!title.isEmpty()) {
                        result.setBanner("Title: " + title);
                    }
                }
            }
        } catch (Exception e) {
            // Silently ignore — plugin failures must not disrupt the scan
        }
    }
}
