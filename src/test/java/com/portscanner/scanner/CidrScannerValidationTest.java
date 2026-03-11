package com.portscanner.scanner;

import com.portscanner.service.ServiceMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CidrScannerValidationTest {

    private final CidrScanner scanner = new CidrScanner(10, 200, false, new ServiceMapper());

    @Test
    void invalid_cidr_without_slash_throws() {
        assertThrows(Exception.class, () -> scanner.scan("192.168.1.0", new int[]{80}));
    }

    @Test
    void invalid_prefix_length_negative_throws() {
        assertThrows(IllegalArgumentException.class, () -> scanner.scan("192.168.1.0/-1", new int[]{80}));
    }

    @Test
    void invalid_prefix_length_over_32_throws() {
        assertThrows(IllegalArgumentException.class, () -> scanner.scan("192.168.1.0/33", new int[]{80}));
    }

    @Test
    void valid_prefix_lengths_do_not_throw_IllegalArgumentException() {
        // /32 is a valid prefix — should not throw IllegalArgumentException from validation.
        // It may complete normally (loopback is reachable) so we just check no IAE is raised.
        try {
            scanner.scan("127.0.0.1/32", new int[]{65535});
        } catch (IllegalArgumentException e) {
            fail("Valid /32 CIDR should not throw IllegalArgumentException: " + e.getMessage());
        } catch (Exception ignored) {
            // Other exceptions (network, etc.) are acceptable
        }
    }
}
