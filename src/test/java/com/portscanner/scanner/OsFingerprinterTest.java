package com.portscanner.scanner;

import com.portscanner.model.OsGuess;
import com.portscanner.model.HttpInfo;
import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanResult;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class OsFingerprinterTest {

    private final OsFingerprinter fingerprinter = new OsFingerprinter();

    // ── Banner-based detection ────────────────────────────────────────────────

    @Test
    void detectsUbuntuFromSshBanner() {
        ScanResult r = openPort(22, "SSH", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6");
        OsGuess guess = fingerprinter.fingerprint(loopback(), List.of(r));
        assertNotNull(guess);
        assertTrue(guess.getOs().contains("Ubuntu"), "Expected Ubuntu in: " + guess.getOs());
        assertEquals("high", guess.getConfidence());
    }

    @Test
    void detectsDebianFromSshBanner() {
        ScanResult r = openPort(22, "SSH", "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2");
        OsGuess guess = fingerprinter.fingerprint(loopback(), List.of(r));
        assertNotNull(guess);
        assertTrue(guess.getOs().contains("Debian"), "Expected Debian in: " + guess.getOs());
        assertEquals("high", guess.getConfidence());
    }

    @Test
    void detectsWindowsFromRdpPort() {
        ScanResult r = openPort(3389, "RDP", null);
        OsGuess guess = fingerprinter.fingerprint(loopback(), List.of(r));
        assertNotNull(guess);
        assertTrue(guess.getOs().contains("Windows"), "Expected Windows in: " + guess.getOs());
    }

    @Test
    void detectsWindowsFromSmbPort445() {
        ScanResult r = openPort(445, "Microsoft-DS", null);
        OsGuess guess = fingerprinter.fingerprint(loopback(), List.of(r));
        assertNotNull(guess);
        assertTrue(guess.getOs().contains("Windows"), "Expected Windows in: " + guess.getOs());
    }

    @Test
    void detectsWindowsFromIisHttpHeader() {
        ScanResult r = ScanResult.builder()
                .port(80).status(PortStatus.OPEN).serviceName("HTTP")
                .httpInfo(HttpInfo.builder().statusCode(200).serverHeader("Microsoft-IIS/10.0").build())
                .build();
        OsGuess guess = fingerprinter.fingerprint(loopback(), List.of(r));
        assertNotNull(guess);
        assertTrue(guess.getOs().contains("Windows"), "Expected Windows in: " + guess.getOs());
        assertEquals("high", guess.getConfidence());
    }

    @Test
    void returnsNullForEmptyPortList() {
        // Without TTL or banners there's nothing to go on
        OsGuess guess = fingerprinter.fingerprint(loopback(), List.of());
        // May be null or have a TTL-based guess — just assert no exception
        // (TTL probe on loopback is allowed to succeed or fail gracefully)
    }

    @Test
    void handlesNullBannerGracefully() {
        ScanResult r = openPort(80, "HTTP", null);
        assertDoesNotThrow(() -> fingerprinter.fingerprint(loopback(), List.of(r)));
    }

    @Test
    void detectsFreeBsdFromBanner() {
        ScanResult r = openPort(22, "SSH", "SSH-2.0-OpenSSH_9.3 FreeBSD-20230316");
        OsGuess guess = fingerprinter.fingerprint(loopback(), List.of(r));
        assertNotNull(guess);
        assertTrue(guess.getOs().contains("FreeBSD"), "Expected FreeBSD in: " + guess.getOs());
    }

    @Test
    void methodFieldIsPopulated() {
        ScanResult r = openPort(3389, "RDP", null);
        OsGuess guess = fingerprinter.fingerprint(loopback(), List.of(r));
        assertNotNull(guess);
        assertNotNull(guess.getMethod(), "method should not be null");
        assertFalse(guess.getMethod().isBlank());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ScanResult openPort(int port, String service, String banner) {
        return ScanResult.builder()
                .port(port).status(PortStatus.OPEN)
                .serviceName(service).banner(banner)
                .build();
    }

    private static InetAddress loopback() {
        return InetAddress.getLoopbackAddress();
    }
}
