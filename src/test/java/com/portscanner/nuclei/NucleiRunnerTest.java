package com.portscanner.nuclei;

import com.portscanner.model.NucleiResult;
import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.*;

class NucleiRunnerTest {

    private ServerSocket server;
    private int port;
    private ExecutorService exec;
    private String stubBody = "<html>Apache/2.4.49</html>";
    private int stubStatus = 200;

    @BeforeEach
    void startStub() throws Exception {
        server = new ServerSocket(0);
        port = server.getLocalPort();
        exec = Executors.newSingleThreadExecutor();
        exec.submit(() -> {
            while (!server.isClosed()) {
                try (Socket s = server.accept();
                     BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
                     OutputStream out = s.getOutputStream()) {
                    // drain request
                    String line;
                    while ((line = in.readLine()) != null && !line.isEmpty()) {}
                    // send response
                    String body = stubBody;
                    String response = "HTTP/1.1 " + stubStatus + " OK\r\n"
                            + "Content-Length: " + body.length() + "\r\n"
                            + "Connection: close\r\n\r\n" + body;
                    out.write(response.getBytes());
                } catch (Exception ignored) {}
            }
        });
    }

    @AfterEach
    void stopStub() throws Exception {
        server.close();
        exec.shutdownNow();
    }

    private NucleiTemplate regexTemplate(String regex) {
        NucleiTemplate t = new NucleiTemplate();
        t.setId("test-id");
        NucleiTemplate.Info info = new NucleiTemplate.Info();
        info.setName("Test"); info.setSeverity("high");
        t.setInfo(info);
        NucleiTemplate.Matcher m = new NucleiTemplate.Matcher();
        m.setType("regex"); m.setRegex(List.of(regex));
        NucleiTemplate.HttpRequest req = new NucleiTemplate.HttpRequest();
        req.setMethod("GET"); req.setPath(List.of("{{BaseURL}}/"));
        req.setMatchers(List.of(m));
        t.setHttp(List.of(req));
        return t;
    }

    @Test
    void matchesBodyRegex() {
        ScanResult result = ScanResult.builder().port(port).status(PortStatus.OPEN).build();
        List<NucleiResult> findings = new NucleiRunner()
                .run("localhost", result, List.of(regexTemplate("Apache")));
        assertEquals(1, findings.size());
        assertTrue(findings.get(0).isMatched());
        assertEquals("high", findings.get(0).getSeverity());
    }

    @Test
    void noMatchWhenBodyDoesNotContainPattern() {
        ScanResult result = ScanResult.builder().port(port).status(PortStatus.OPEN).build();
        List<NucleiResult> findings = new NucleiRunner()
                .run("localhost", result, List.of(regexTemplate("nginx")));
        assertTrue(findings.isEmpty());
    }
}
