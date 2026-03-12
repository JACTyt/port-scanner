package com.portscanner.scanner;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class IPv6CidrEnumeratorTest {

    @Test
    void isIPv6Cidr_detects_colon() {
        assertTrue(IPv6CidrEnumerator.isIPv6Cidr("2001:db8::/64"));
        assertTrue(IPv6CidrEnumerator.isIPv6Cidr("::1/128"));
        assertFalse(IPv6CidrEnumerator.isIPv6Cidr("192.168.0.0/24"));
        assertFalse(IPv6CidrEnumerator.isIPv6Cidr(null));
    }

    @Test
    void enumerate_single_address_returns_one_entry() {
        List<String> hosts = IPv6CidrEnumerator.enumerate("::1/128");
        assertEquals(1, hosts.size());
        assertEquals("::1", hosts.get(0));
    }

    @Test
    void enumerate_slash120_returns_256_addresses() {
        List<String> hosts = IPv6CidrEnumerator.enumerate("2001:db8::/120");
        // /120 = 256 addresses — fits within MAX_HOSTS
        assertEquals(256, hosts.size());
    }

    @Test
    void enumerate_caps_at_max_hosts_for_large_subnet() {
        // /64 has 2^64 addresses — far exceeds MAX_HOSTS
        List<String> hosts = IPv6CidrEnumerator.enumerate("2001:db8::/64");
        assertEquals(IPv6CidrEnumerator.MAX_HOSTS, hosts.size());
    }

    @Test
    void enumerate_invalid_cidr_throws_IllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> IPv6CidrEnumerator.enumerate("not-a-cidr"));
    }

    @Test
    void enumerate_ipv4_cidr_throws_IllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> IPv6CidrEnumerator.enumerate("192.168.1.0/24"));
    }
}
