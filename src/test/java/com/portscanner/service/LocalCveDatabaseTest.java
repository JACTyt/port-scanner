package com.portscanner.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class LocalCveDatabaseTest {

    @TempDir
    Path tempDir;

    @Test
    void query_emptyKeyword_returnsEmptyList() {
        Path dbFile = tempDir.resolve("cve-db.sqlite");
        LocalCveDatabase db = new LocalCveDatabase(dbFile);
        List<String> result = db.query("");
        assertTrue(result.isEmpty(), "Empty keyword should return empty list");
    }

    @Test
    void query_nullKeyword_returnsEmptyList() {
        Path dbFile = tempDir.resolve("cve-db.sqlite");
        LocalCveDatabase db = new LocalCveDatabase(dbFile);
        List<String> result = db.query(null);
        assertTrue(result.isEmpty(), "Null keyword should return empty list");
    }

    @Test
    void query_afterInsert_returnsMatchingCveId() throws Exception {
        Path dbFile = tempDir.resolve("cve-db.sqlite");
        LocalCveDatabase db = new LocalCveDatabase(dbFile);

        // Trigger DB creation by running an empty query first
        db.query("init");

        // Insert a test row directly via JDBC
        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + dbFile);
             PreparedStatement ps = conn.prepareStatement(
                 "INSERT OR REPLACE INTO cves(cve_id, description, cvss_v3, severity, cpe_list, last_modified) VALUES(?,?,?,?,?,?)")) {
            ps.setString(1, "CVE-2023-12345");
            ps.setString(2, "nginx vulnerability");
            ps.setDouble(3, 9.8);
            ps.setString(4, "CRITICAL");
            ps.setString(5, "nginx:1.21.0");
            ps.setString(6, "2023-01-01");
            ps.executeUpdate();
        }

        List<String> results = db.query("nginx");
        assertFalse(results.isEmpty(), "Should find CVE matching 'nginx'");
        assertEquals("CVE-2023-12345", results.get(0));
    }

    @Test
    void getLastSyncDate_neverSynced_returnsEmpty() {
        Path dbFile = tempDir.resolve("cve-db.sqlite");
        LocalCveDatabase db = new LocalCveDatabase(dbFile);
        Optional<String> lastSync = db.getLastSyncDate();
        assertTrue(lastSync.isEmpty(), "Fresh database should return empty Optional for last sync date");
    }

    @Test
    void isDatabasePresent_afterCreation_returnsTrue() {
        Path dbFile = tempDir.resolve("cve-db.sqlite");
        LocalCveDatabase db = new LocalCveDatabase(dbFile);

        assertFalse(db.isDatabasePresent(), "DB should not exist before first use");

        // Trigger creation via query
        db.query("trigger-creation");

        assertTrue(db.isDatabasePresent(), "DB should exist after first query");
    }
}
