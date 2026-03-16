package com.portscanner.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class VersionExtractorTest {

    @Test
    void ssh_version_extracted_from_banner() {
        // Pattern captures the implementation token only (no spaces), stopping before " Ubuntu-..."
        String banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6";
        String version = VersionExtractor.extract("SSH", banner);
        assertEquals("OpenSSH_8.9p1", version);
    }

    @Test
    void ftp_version_extracted_from_220_response() {
        // FTP pattern captures "software version#" — alphabetic suffix ('a') is not in [\d._-]
        String banner = "220 ProFTPD 1.3.7a Server";
        String version = VersionExtractor.extract("FTP", banner);
        assertNotNull(version);
        assertTrue(version.contains("ProFTPD"), "Expected ProFTPD in: " + version);
        assertTrue(version.contains("1.3.7"), "Expected version number 1.3.7 in: " + version);
    }

    @Test
    void http_server_header_extracted() {
        String banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.51 (Ubuntu)\r\nContent-Type: text/html";
        String version = VersionExtractor.extract("HTTP", banner);
        assertNotNull(version);
        assertTrue(version.contains("Apache"), "Expected Apache in: " + version);
    }

    @Test
    void null_banner_returns_null() {
        assertNull(VersionExtractor.extract("SSH", null));
    }

    @Test
    void blank_banner_returns_null() {
        assertNull(VersionExtractor.extract("SSH", "   "));
    }

    @Test
    void null_service_returns_null() {
        assertNull(VersionExtractor.extract(null, "SSH-2.0-OpenSSH_8.9"));
    }

    @Test
    void unknown_service_with_no_matching_pattern_returns_null() {
        assertNull(VersionExtractor.extract("UNKNOWNXYZ", "some random banner text"));
    }

    @Test
    void smtp_version_extracted() {
        String banner = "220 mail.example.com ESMTP Postfix 3.6.4";
        String version = VersionExtractor.extract("SMTP", banner);
        assertNotNull(version);
    }

    @Test
    void case_insensitive_service_name() {
        String banner = "SSH-2.0-OpenSSH_9.0";
        assertEquals(VersionExtractor.extract("SSH", banner), VersionExtractor.extract("ssh", banner));
    }
}
