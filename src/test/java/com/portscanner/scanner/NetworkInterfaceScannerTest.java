package com.portscanner.scanner;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class NetworkInterfaceScannerTest {

    private NetworkInterfaceScanner scanner;

    @BeforeEach
    void setUp() {
        scanner = new NetworkInterfaceScanner();
    }

    // ── computeNetworkAddress tests ──────────────────────────────────────────

    @Test
    void computeNetworkAddress_class_c_prefix24() throws Exception {
        InetAddress addr = InetAddress.getByName("192.168.1.100");
        String result = scanner.computeNetworkAddress(addr, 24);
        assertEquals("192.168.1.0", result);
    }

    @Test
    void computeNetworkAddress_class_a_prefix8() throws Exception {
        InetAddress addr = InetAddress.getByName("10.0.0.1");
        String result = scanner.computeNetworkAddress(addr, 8);
        assertEquals("10.0.0.0", result);
    }

    @Test
    void computeNetworkAddress_class_b_prefix16() throws Exception {
        InetAddress addr = InetAddress.getByName("172.16.5.10");
        String result = scanner.computeNetworkAddress(addr, 16);
        assertEquals("172.16.0.0", result);
    }

    @Test
    void computeNetworkAddress_host_route_prefix32() throws Exception {
        InetAddress addr = InetAddress.getByName("192.168.1.1");
        String result = scanner.computeNetworkAddress(addr, 32);
        assertEquals("192.168.1.1", result);
    }

    @Test
    void computeNetworkAddress_default_route_prefix0() throws Exception {
        InetAddress addr = InetAddress.getByName("10.20.30.40");
        String result = scanner.computeNetworkAddress(addr, 0);
        assertEquals("0.0.0.0", result);
    }

    // ── discoverLocalSubnets tests ───────────────────────────────────────────

    @Test
    void discoverLocalSubnets_returns_non_null_list() {
        List<String> subnets = scanner.discoverLocalSubnets();
        assertNotNull(subnets);
    }

    @Test
    void discoverLocalSubnets_entries_are_valid_cidr_format() {
        List<String> subnets = scanner.discoverLocalSubnets();
        for (String subnet : subnets) {
            assertTrue(subnet.contains("/"),
                    "Subnet entry should be in CIDR notation: " + subnet);
            String[] parts = subnet.split("/", 2);
            assertEquals(2, parts.length);
            // Network address part should be parseable as an IP
            assertDoesNotThrow(() -> InetAddress.getByName(parts[0]),
                    "Network address should be a valid IP: " + parts[0]);
            // Prefix length should be 0–32
            int prefix = Integer.parseInt(parts[1]);
            assertTrue(prefix >= 0 && prefix <= 32,
                    "Prefix length should be 0-32, got: " + prefix);
        }
    }
}
