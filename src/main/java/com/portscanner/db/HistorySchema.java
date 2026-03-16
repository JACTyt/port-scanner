package com.portscanner.db;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Manages the SQLite schema for scan history.
 * Database location: {@code ~/.portscanner/history.db} (overridable via
 * {@link #setDbPathForTesting(String)} for tests).
 */
public class HistorySchema {

    private static final Logger log = LoggerFactory.getLogger(HistorySchema.class);

    /** Default DB path — can be overridden by tests. */
    private static String dbPath = null;

    public static String getDbPath() {
        if (dbPath != null) return dbPath;
        return System.getProperty("user.home") + "/.portscanner/history.db";
    }

    /** Package-visible override for unit tests. Pass {@code null} to restore the default. */
    static void setDbPathForTesting(String path) {
        dbPath = path;
    }

    /** Opens (and creates) the SQLite database at {@link #getDbPath()}. */
    public static Connection connect() throws SQLException {
        Path path = Path.of(getDbPath());
        try {
            Files.createDirectories(path.getParent());
        } catch (IOException e) {
            throw new SQLException("Cannot create database directory: " + e.getMessage(), e);
        }
        return DriverManager.getConnection("jdbc:sqlite:" + getDbPath());
    }

    /**
     * Creates the {@code scans} and {@code open_ports} tables if they do not exist.
     * Safe to call multiple times.
     */
    public static void init() {
        try (Connection conn = connect();
             Statement stmt = conn.createStatement()) {

            stmt.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        host        TEXT    NOT NULL,
                        scanned_at  TEXT    NOT NULL,
                        duration_ms INTEGER,
                        report_json TEXT    NOT NULL
                    )
                    """);

            stmt.execute("""
                    CREATE TABLE IF NOT EXISTS open_ports (
                        scan_id  INTEGER REFERENCES scans(id) ON DELETE CASCADE,
                        port     INTEGER,
                        service  TEXT,
                        banner   TEXT,
                        PRIMARY KEY (scan_id, port)
                    )
                    """);

            stmt.execute("CREATE INDEX IF NOT EXISTS idx_scans_host ON scans(host)");
            log.debug("History database initialised at {}", getDbPath());

        } catch (SQLException e) {
            log.warn("Could not initialise history database: {}", e.getMessage());
        }
    }
}
