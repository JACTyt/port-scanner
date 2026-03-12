package com.portscanner.scanner;

import com.portscanner.model.TracerouteHop;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class TracerouteTest {

    // ── Windows line parsing ────────────────────────────────────────────────

    @Test
    void parseWindowsLine_normalHop_returnsCorrectHop() {
        String line = "  1    <1 ms    <1 ms    <1 ms  192.168.1.1";
        Optional<TracerouteHop> result = Traceroute.parseWindowsLine(line);
        assertTrue(result.isPresent(), "Expected a hop to be parsed");
        TracerouteHop hop = result.get();
        assertEquals(1, hop.hopNumber());
        assertEquals("192.168.1.1", hop.ip());
        // <1 ms should be parsed as 0.5
        assertEquals(0.5, hop.rttMs(), 0.01);
    }

    @Test
    void parseWindowsLine_multiMsHop_returnsCorrectRtt() {
        String line = "  2    10 ms    11 ms    10 ms  10.0.0.1";
        Optional<TracerouteHop> result = Traceroute.parseWindowsLine(line);
        assertTrue(result.isPresent());
        TracerouteHop hop = result.get();
        assertEquals(2, hop.hopNumber());
        assertEquals("10.0.0.1", hop.ip());
        assertEquals(10.0, hop.rttMs(), 0.01);
    }

    @Test
    void parseWindowsLine_timeout_returnsTimeoutHop() {
        String line = "  3     *        *        *     Request timed out.";
        Optional<TracerouteHop> result = Traceroute.parseWindowsLine(line);
        assertTrue(result.isPresent(), "Expected a timeout hop to be parsed");
        TracerouteHop hop = result.get();
        assertEquals(3, hop.hopNumber());
        assertEquals("*", hop.ip());
        assertEquals(-1.0, hop.rttMs(), 0.01);
    }

    @Test
    void parseWindowsLine_blankLine_returnsEmpty() {
        Optional<TracerouteHop> result = Traceroute.parseWindowsLine("");
        assertFalse(result.isPresent());
    }

    @Test
    void parseWindowsLine_headerLine_returnsEmpty() {
        // typical Windows tracert header line — should not parse as a hop
        String line = "Tracing route to google.com [142.250.185.46]";
        Optional<TracerouteHop> result = Traceroute.parseWindowsLine(line);
        assertFalse(result.isPresent());
    }

    // ── Linux line parsing ──────────────────────────────────────────────────

    @Test
    void parseLinuxLine_normalHop_returnsCorrectHop() {
        String line = " 1  192.168.1.1 (192.168.1.1)  0.543 ms  0.412 ms  0.398 ms";
        Optional<TracerouteHop> result = Traceroute.parseLinuxLine(line);
        assertTrue(result.isPresent(), "Expected a hop to be parsed");
        TracerouteHop hop = result.get();
        assertEquals(1, hop.hopNumber());
        assertEquals("192.168.1.1", hop.ip());
        assertEquals(0.543, hop.rttMs(), 0.001);
    }

    @Test
    void parseLinuxLine_hopWithHostname_returnsHostname() {
        String line = " 2  router.local (10.0.0.1)  8.234 ms  7.901 ms  8.100 ms";
        Optional<TracerouteHop> result = Traceroute.parseLinuxLine(line);
        assertTrue(result.isPresent());
        TracerouteHop hop = result.get();
        assertEquals(2, hop.hopNumber());
        assertEquals("10.0.0.1", hop.ip());
        assertEquals("router.local", hop.hostname());
        assertEquals(8.234, hop.rttMs(), 0.001);
    }

    @Test
    void parseLinuxLine_timeout_returnsTimeoutHop() {
        String line = " 3  * * *";
        Optional<TracerouteHop> result = Traceroute.parseLinuxLine(line);
        assertTrue(result.isPresent(), "Expected a timeout hop to be parsed");
        TracerouteHop hop = result.get();
        assertEquals(3, hop.hopNumber());
        assertEquals("*", hop.ip());
        assertEquals(-1.0, hop.rttMs(), 0.01);
    }

    @Test
    void parseLinuxLine_blankLine_returnsEmpty() {
        Optional<TracerouteHop> result = Traceroute.parseLinuxLine("");
        assertFalse(result.isPresent());
    }

    @Test
    void parseLinuxLine_headerLine_returnsEmpty() {
        String line = "traceroute to google.com (142.250.185.46), 30 hops max, 60 byte packets";
        Optional<TracerouteHop> result = Traceroute.parseLinuxLine(line);
        assertFalse(result.isPresent());
    }
}
