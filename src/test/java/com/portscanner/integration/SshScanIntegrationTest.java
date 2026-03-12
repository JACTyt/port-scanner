package com.portscanner.integration;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import com.portscanner.scanner.PortScanner;
import com.portscanner.service.ServiceMapper;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers(disabledWithoutDocker = true)
@Tag("integration")
class SshScanIntegrationTest {

    @Container
    static GenericContainer<?> sshServer = new GenericContainer<>("rastasheep/ubuntu-sshd:18.04")
            .withExposedPorts(22)
            .waitingFor(Wait.forListeningPort());

    @Test
    void sshPortIsOpen() throws Exception {
        String host = sshServer.getHost();
        int port = sshServer.getMappedPort(22);
        InetAddress addr = InetAddress.getByName(host);

        PortScanner scanner = new PortScanner(1, 3000, false, new ServiceMapper());
        ScanReport report = scanner.scan(host, addr, new int[]{port});

        assertFalse(report.getOpenPorts().isEmpty(), "SSH port should be OPEN");
        ScanResult result = report.getOpenPorts().get(0);
        assertEquals(PortStatus.OPEN, result.getStatus());
        assertEquals(port, result.getPort());
    }

    @Test
    void sshBannerContainsSshVersionString() throws Exception {
        String host = sshServer.getHost();
        int port = sshServer.getMappedPort(22);
        InetAddress addr = InetAddress.getByName(host);

        PortScanner scanner = new PortScanner(1, 3000, true, new ServiceMapper());
        ScanReport report = scanner.scan(host, addr, new int[]{port});

        assertFalse(report.getOpenPorts().isEmpty(), "SSH port should be OPEN");
        ScanResult result = report.getOpenPorts().get(0);
        assertNotNull(result.getBanner(), "Banner should not be null");
        assertTrue(result.getBanner().startsWith("SSH-2.0"),
                "SSH banner should start with 'SSH-2.0', got: " + result.getBanner());
    }
}
