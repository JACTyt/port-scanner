package com.portscanner.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.nio.file.*;
import java.sql.*;
import java.util.*;

public class LocalCveDatabase {
    private static final Logger log = LoggerFactory.getLogger(LocalCveDatabase.class);
    private static final String NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    private final Path dbPath;

    public LocalCveDatabase() {
        this.dbPath = Path.of(System.getProperty("user.home"), ".portscanner", "cve-db.sqlite");
    }

    // package-private for testing
    LocalCveDatabase(Path dbPath) {
        this.dbPath = dbPath;
    }

    private Connection openConnection() throws SQLException {
        // create parent dirs if needed
        try { Files.createDirectories(dbPath.getParent()); } catch (IOException e) { /* ignore */ }
        Connection conn = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
        initSchema(conn);
        return conn;
    }

    private void initSchema(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS cves (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    cvss_v3 REAL,
                    severity TEXT,
                    cpe_list TEXT,
                    last_modified TEXT
                )
            """);
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS cves_cpe_idx ON cves(cpe_list)");
            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """);
        }
    }

    public List<String> query(String keyword) {
        if (keyword == null || keyword.isBlank()) return Collections.emptyList();
        List<String> results = new ArrayList<>();
        try (Connection conn = openConnection();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT cve_id FROM cves WHERE cpe_list LIKE '%' || ? || '%' ORDER BY cvss_v3 DESC LIMIT 10")) {
            ps.setString(1, keyword.toLowerCase());
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) results.add(rs.getString("cve_id"));
            }
        } catch (SQLException e) {
            log.warn("CVE query failed: {}", e.getMessage());
        }
        return results;
    }

    public Optional<String> getLastSyncDate() {
        try (Connection conn = openConnection();
             PreparedStatement ps = conn.prepareStatement("SELECT value FROM meta WHERE key='last_sync'")) {
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return Optional.of(rs.getString("value"));
            }
        } catch (SQLException e) {
            log.warn("Could not read last sync date: {}", e.getMessage());
        }
        return Optional.empty();
    }

    public void sync(String apiKey) {
        // Simplified sync: fetch first page of recently modified CVEs from NVD 2.0 API
        // and insert/update them in the local database
        try (Connection conn = openConnection()) {
            conn.setAutoCommit(false);
            int total = syncPage(conn, apiKey, 0);
            log.info("Synced {} CVEs to local database", total);
            // Update last_sync date
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES('last_sync', ?)")) {
                ps.setString(1, java.time.LocalDate.now().toString());
                ps.executeUpdate();
            }
            conn.commit();
        } catch (Exception e) {
            log.error("CVE sync failed: {}", e.getMessage());
        }
    }

    private int syncPage(Connection conn, String apiKey, int startIndex) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        String url = NVD_API_URL + "?startIndex=" + startIndex + "&resultsPerPage=200";
        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(url)).GET();
        if (apiKey != null && !apiKey.isBlank()) builder.header("apiKey", apiKey);
        HttpResponse<String> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            log.warn("NVD API returned {}", response.statusCode());
            return 0;
        }

        // Simple JSON parsing without extra deps - extract CVE IDs and descriptions
        String body = response.body();
        int count = 0;
        // Parse vulnerabilities array using basic string parsing
        // Look for "cveId":"CVE-XXXX-XXXXX" patterns
        java.util.regex.Pattern cveIdPattern = java.util.regex.Pattern.compile("\"cveId\"\\s*:\\s*\"(CVE-[\\d-]+)\"");
        java.util.regex.Matcher matcher = cveIdPattern.matcher(body);

        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT OR REPLACE INTO cves(cve_id, description, cvss_v3, severity, cpe_list, last_modified) VALUES(?,?,?,?,?,?)")) {
            while (matcher.find()) {
                ps.setString(1, matcher.group(1));
                ps.setString(2, "");  // simplified
                ps.setDouble(3, 0.0);
                ps.setString(4, "UNKNOWN");
                ps.setString(5, matcher.group(1).toLowerCase()); // use CVE ID as searchable keyword
                ps.setString(6, java.time.LocalDate.now().toString());
                ps.executeUpdate();
                count++;
            }
        }
        return count;
    }

    public boolean isDatabasePresent() {
        return Files.exists(dbPath);
    }
}
