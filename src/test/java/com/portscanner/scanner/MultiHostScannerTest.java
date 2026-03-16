package com.portscanner.scanner;

import com.portscanner.model.MultiHostReport;
import com.portscanner.service.ServiceMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MultiHostScannerTest {

    @TempDir
    Path tempDir;

    @Test
    void parseHostsFile_strips_comments_and_blank_lines() throws IOException {
        Path file = tempDir.resolve("hosts.txt");
        Files.writeString(file, """
                # This is a comment
                192.168.1.1

                # another comment
                10.0.0.1  # inline comment
                """);

        List<String> entries = MultiHostScanner.parseHostsFile(file);
        assertEquals(2, entries.size());
        assertEquals("192.168.1.1", entries.get(0));
        assertEquals("10.0.0.1", entries.get(1));
    }

    @Test
    void parseHostsFile_empty_file_returns_empty_list() throws IOException {
        Path file = tempDir.resolve("empty.txt");
        Files.writeString(file, "# only comments\n\n");
        List<String> entries = MultiHostScanner.parseHostsFile(file);
        assertTrue(entries.isEmpty());
    }

    @Test
    void isCidr_returns_true_for_cidr_notation() {
        assertTrue(MultiHostScanner.isCidr("192.168.1.0/24"));
        assertTrue(MultiHostScanner.isCidr("10.0.0.0/8"));
    }

    @Test
    void isCidr_returns_false_for_plain_host() {
        assertFalse(MultiHostScanner.isCidr("192.168.1.1"));
        assertFalse(MultiHostScanner.isCidr("example.com"));
    }

    @Test
    void scan_detects_open_port_on_localhost() throws Exception {
        try (ServerSocket server = new ServerSocket(0)) {
            int port = server.getLocalPort();
            Path file = tempDir.resolve("hosts.txt");
            Files.writeString(file, "127.0.0.1\n");

            MultiHostScanner scanner = new MultiHostScanner(10, 500, false,
                    new ServiceMapper(), false);
            MultiHostReport report = scanner.scan(file, new int[]{port}, 1);

            assertEquals(1, report.getTotalHosts());
            assertFalse(report.getResults().isEmpty());
            assertTrue(report.getResults().get(0).getOpenCount() > 0,
                    "Expected port " + port + " to be open");
        }
    }

    @Test
    void scan_empty_hosts_file_returns_zero_hosts_report() throws Exception {
        Path file = tempDir.resolve("empty.txt");
        Files.writeString(file, "# no hosts\n");

        MultiHostScanner scanner = new MultiHostScanner(10, 200, false, new ServiceMapper(), false);
        MultiHostReport report = scanner.scan(file, new int[]{80}, 1);

        assertEquals(0, report.getTotalHosts());
        assertEquals(0, report.getHostsWithOpenPorts());
        assertTrue(report.getResults().isEmpty());
    }
}
