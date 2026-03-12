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
class RedisScanIntegrationTest {

    @Container
    static GenericContainer<?> redis = new GenericContainer<>("redis:7-alpine")
            .withExposedPorts(6379)
            .waitingFor(Wait.forListeningPort());

    @Test
    void redisPortIsOpen() throws Exception {
        String host = redis.getHost();
        int port = redis.getMappedPort(6379);
        InetAddress addr = InetAddress.getByName(host);

        PortScanner scanner = new PortScanner(1, 3000, false, new ServiceMapper());
        ScanReport report = scanner.scan(host, addr, new int[]{port});

        assertFalse(report.getOpenPorts().isEmpty(), "Redis port should be OPEN");
        ScanResult result = report.getOpenPorts().get(0);
        assertEquals(PortStatus.OPEN, result.getStatus());
        assertEquals(port, result.getPort());
    }

    @Test
    void redisProbeReturnsPongBanner() throws Exception {
        String host = redis.getHost();
        int port = redis.getMappedPort(6379);
        InetAddress addr = InetAddress.getByName(host);

        // useProbes=true to trigger the RedisProbe
        PortScanner scanner = new PortScanner(1, 3000, true, new ServiceMapper(), true, 0);
        ScanReport report = scanner.scan(host, addr, new int[]{port});

        assertFalse(report.getOpenPorts().isEmpty(), "Redis port should be OPEN");
        ScanResult result = report.getOpenPorts().get(0);
        assertEquals(PortStatus.OPEN, result.getStatus());
        assertNotNull(result.getBanner(), "Banner should not be null for Redis with probes");
        assertTrue(result.getBanner().contains("+PONG") || result.getBanner().toLowerCase().contains("redis"),
                "Banner should contain Redis indicator, got: " + result.getBanner());
    }

    @Test
    void redisServiceNameIsRecognized() throws Exception {
        String host = redis.getHost();
        int port = redis.getMappedPort(6379);
        InetAddress addr = InetAddress.getByName(host);

        PortScanner scanner = new PortScanner(1, 3000, false, new ServiceMapper());
        ScanReport report = scanner.scan(host, addr, new int[]{port});

        assertFalse(report.getOpenPorts().isEmpty());
        ScanResult result = report.getOpenPorts().get(0);
        // Port 6379 should be mapped to "Redis" in services.json
        assertNotNull(result.getServiceName());
        assertTrue(result.getServiceName().toLowerCase().contains("redis"),
                "Service name for port 6379 should be Redis, got: " + result.getServiceName());
    }
}
