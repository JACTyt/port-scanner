package com.portscanner.nuclei;

import com.portscanner.model.NucleiResult;
import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanResult;
import com.portscanner.nuclei.matcher.StatusMatcher;
import com.portscanner.nuclei.matcher.WordMatcher;
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
        assertEquals("high", findings.get(0).getSeverity());
    }

    @Test
    void noMatchWhenBodyDoesNotContainPattern() {
        ScanResult result = ScanResult.builder().port(port).status(PortStatus.OPEN).build();
        List<NucleiResult> findings = new NucleiRunner()
                .run("localhost", result, List.of(regexTemplate("nginx")));
        assertTrue(findings.isEmpty());
    }

    // ── WordMatcher unit tests ────────────────────────────────────────────────

    @Test
    void wordMatcher_hit() {
        WordMatcher wm = new WordMatcher();
        NucleiTemplate.Matcher m = new NucleiTemplate.Matcher();
        m.setWords(List.of("Apache"));
        assertTrue(wm.matches(m, "<html>Apache/2.4</html>"));
    }

    @Test
    void wordMatcher_miss() {
        WordMatcher wm = new WordMatcher();
        NucleiTemplate.Matcher m = new NucleiTemplate.Matcher();
        m.setWords(List.of("nginx"));
        assertFalse(wm.matches(m, "<html>Apache/2.4</html>"));
    }

    @Test
    void wordMatcher_condition_and_all_present() {
        WordMatcher wm = new WordMatcher();
        NucleiTemplate.Matcher m = new NucleiTemplate.Matcher();
        m.setWords(List.of("Apache", "2.4"));
        m.setCondition("and");
        assertTrue(wm.matches(m, "Apache/2.4"));
    }

    @Test
    void wordMatcher_condition_and_one_missing() {
        WordMatcher wm = new WordMatcher();
        NucleiTemplate.Matcher m = new NucleiTemplate.Matcher();
        m.setWords(List.of("Apache", "nginx"));
        m.setCondition("and");
        assertFalse(wm.matches(m, "Apache/2.4"));
    }

    @Test
    void wordMatcher_negative_true_inverts_hit() {
        WordMatcher wm = new WordMatcher();
        NucleiTemplate.Matcher m = new NucleiTemplate.Matcher();
        m.setWords(List.of("Apache"));
        m.setNegative(true);
        assertFalse(wm.matches(m, "<html>Apache/2.4</html>"));
    }

    @Test
    void wordMatcher_negative_true_inverts_miss() {
        WordMatcher wm = new WordMatcher();
        NucleiTemplate.Matcher m = new NucleiTemplate.Matcher();
        m.setWords(List.of("nginx"));
        m.setNegative(true);
        assertTrue(wm.matches(m, "<html>Apache/2.4</html>"));
    }

    // ── StatusMatcher unit tests ──────────────────────────────────────────────

    @Test
    void statusMatcher_code_in_list() {
        StatusMatcher sm = new StatusMatcher();
        NucleiTemplate.Matcher m = new NucleiTemplate.Matcher();
        m.setStatus(List.of(200, 301));
        assertTrue(sm.matches(m, 200));
    }

    @Test
    void statusMatcher_code_not_in_list() {
        StatusMatcher sm = new StatusMatcher();
        NucleiTemplate.Matcher m = new NucleiTemplate.Matcher();
        m.setStatus(List.of(200, 301));
        assertFalse(sm.matches(m, 404));
    }

    @Test
    void statusMatcher_negative_true_inverts_in_list() {
        StatusMatcher sm = new StatusMatcher();
        NucleiTemplate.Matcher m = new NucleiTemplate.Matcher();
        m.setStatus(List.of(200));
        m.setNegative(true);
        assertFalse(sm.matches(m, 200));
    }

    @Test
    void statusMatcher_negative_true_inverts_not_in_list() {
        StatusMatcher sm = new StatusMatcher();
        NucleiTemplate.Matcher m = new NucleiTemplate.Matcher();
        m.setStatus(List.of(200));
        m.setNegative(true);
        assertTrue(sm.matches(m, 404));
    }
}
