package com.portscanner.integration;

import com.portscanner.model.HttpInfo;
import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import com.portscanner.scanner.HttpInspector;
import com.portscanner.scanner.PortScanner;
import com.portscanner.service.ServiceMapper;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.InetAddress;
import java.net.Proxy;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers(disabledWithoutDocker = true)
@Tag("integration")
class HttpScanIntegrationTest {

    @Container
    static GenericContainer<?> nginx = new GenericContainer<>("nginx:alpine")
            .withExposedPorts(80)
            .waitingFor(Wait.forHttp("/").forStatusCode(200));

    @Test
    void httpPortIsOpen() throws Exception {
        String host = nginx.getHost();
        int port = nginx.getMappedPort(80);
        InetAddress addr = InetAddress.getByName(host);

        PortScanner scanner = new PortScanner(1, 3000, false, new ServiceMapper());
        ScanReport report = scanner.scan(host, addr, new int[]{port});

        assertFalse(report.getOpenPorts().isEmpty(), "HTTP port should be OPEN");
        ScanResult result = report.getOpenPorts().get(0);
        assertEquals(PortStatus.OPEN, result.getStatus());
    }

    @Test
    void httpInspectorDetectsNginxServerHeader() throws Exception {
        String host = nginx.getHost();
        int port = nginx.getMappedPort(80);

        Optional<HttpInfo> httpInfo = HttpInspector.inspect(host, port, false, 5000, Proxy.NO_PROXY);

        assertTrue(httpInfo.isPresent(), "HttpInspector should return a result");
        assertNotNull(httpInfo.get().getServerHeader(), "Server header should be present");
        assertTrue(httpInfo.get().getServerHeader().toLowerCase().contains("nginx"),
                "Server header should mention nginx, got: " + httpInfo.get().getServerHeader());
    }

    @Test
    void httpInspectorReturns200StatusCode() throws Exception {
        String host = nginx.getHost();
        int port = nginx.getMappedPort(80);

        Optional<HttpInfo> httpInfo = HttpInspector.inspect(host, port, false, 5000, Proxy.NO_PROXY);

        assertTrue(httpInfo.isPresent());
        assertEquals(200, httpInfo.get().getStatusCode(), "nginx should return HTTP 200");
    }
}
