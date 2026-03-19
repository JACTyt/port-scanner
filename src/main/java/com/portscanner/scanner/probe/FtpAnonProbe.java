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
 * Probes FTP servers for anonymous login by sending "USER anonymous" + "PASS anon@example.com".
 * A 230 (Login successful) response indicates anonymous FTP is enabled.
 */
public class FtpAnonProbe implements UnauthProbe {

    private static final Logger log = LoggerFactory.getLogger(FtpAnonProbe.class);

    @Override
    public List<Integer> getApplicablePorts() {
        return List.of(21, 2121);
    }

    @Override
    public List<String> getApplicableServices() {
        return List.of("ftp");
    }

    @Override
    public UnauthResult probe(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            OutputStream out = socket.getOutputStream();

            // Read banner (220 response)
            String banner = reader.readLine();
            if (banner == null || !banner.startsWith("220")) {
                return UnauthResult.builder().unauthenticated(false).service("FTP").build();
            }

            // Send anonymous credentials
            out.write("USER anonymous\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();
            String userResponse = reader.readLine();

            // 230 = Login OK, 331 = Password required
            if (userResponse != null && userResponse.startsWith("230")) {
                return UnauthResult.builder()
                        .unauthenticated(true)
                        .evidence("FTP: USER anonymous accepted without password (230)")
                        .severity("HIGH")
                        .service("FTP")
                        .build();
            }
            if (userResponse == null || !userResponse.startsWith("331")) {
                return UnauthResult.builder().unauthenticated(false).service("FTP").build();
            }

            out.write("PASS anon@example.com\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();
            String passResponse = reader.readLine();

            if (passResponse != null && passResponse.startsWith("230")) {
                return UnauthResult.builder()
                        .unauthenticated(true)
                        .evidence("FTP: Anonymous login accepted (USER anonymous / PASS anon@)")
                        .severity("HIGH")
                        .service("FTP")
                        .build();
            }
            return UnauthResult.builder().unauthenticated(false).service("FTP").build();
        } catch (Exception e) {
            log.debug("FTP anon probe failed for {}:{} — {}", host, port, e.getMessage());
            return UnauthResult.builder().unauthenticated(false).service("FTP").build();
        }
    }
}
