package com.portscanner.db;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Persists and retrieves scan history from the SQLite database managed by
 * {@link HistorySchema}.
 */
public class ScanHistoryDao {

    private static final Logger log = LoggerFactory.getLogger(ScanHistoryDao.class);

    private final ObjectMapper mapper;

    public ScanHistoryDao() {
        this.mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    /**
     * Persists a completed scan to the history database.
     * The full {@link ScanReport} is stored as JSON, and open ports are also
     * indexed in the {@code open_ports} table for faster querying.
     */
    public void save(ScanReport report) {
        HistorySchema.init();
        try (Connection conn = HistorySchema.connect()) {
            conn.setAutoCommit(false);

            String reportJson = mapper.writeValueAsString(report);
            String scannedAt = report.getScannedAt() != null
                    ? report.getScannedAt().toString()
                    : LocalDateTime.now().toString();

            long scanId;
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO scans (host, scanned_at, duration_ms, report_json) VALUES (?,?,?,?)",
                    Statement.RETURN_GENERATED_KEYS)) {
                ps.setString(1, report.getHost());
                ps.setString(2, scannedAt);
                ps.setLong(3, report.getDurationMs());
                ps.setString(4, reportJson);
                ps.executeUpdate();
                try (ResultSet keys = ps.getGeneratedKeys()) {
                    scanId = keys.next() ? keys.getLong(1) : -1;
                }
            }

            if (scanId > 0 && report.getOpenPorts() != null && !report.getOpenPorts().isEmpty()) {
                try (PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO open_ports (scan_id, port, service, banner) VALUES (?,?,?,?)")) {
                    for (ScanResult r : report.getOpenPorts()) {
                        ps.setLong(1, scanId);
                        ps.setInt(2, r.getPort());
                        ps.setString(3, r.getServiceName());
                        ps.setString(4, r.getBanner());
                        ps.addBatch();
                    }
                    ps.executeBatch();
                }
            }

            conn.commit();
            log.debug("Saved scan of {} to history (scan_id={})", report.getHost(), scanId);

        } catch (Exception e) {
            log.warn("Could not save scan to history: {}", e.getMessage());
        }
    }

    /**
     * Returns the most recent {@code limit} scans for the given host,
     * newest first.
     */
    public List<ScanReport> getHistory(String host, int limit) {
        HistorySchema.init();
        List<ScanReport> results = new ArrayList<>();
        try (Connection conn = HistorySchema.connect();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT report_json FROM scans WHERE host = ? ORDER BY scanned_at DESC LIMIT ?")) {
            ps.setString(1, host);
            ps.setInt(2, limit);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    ScanReport report = mapper.readValue(rs.getString("report_json"), ScanReport.class);
                    results.add(report);
                }
            }
        } catch (Exception e) {
            log.warn("Could not load scan history for {}: {}", host, e.getMessage());
        }
        return results;
    }

    /**
     * Returns the single most recent scan for the given host, if any.
     */
    public Optional<ScanReport> getMostRecent(String host) {
        List<ScanReport> history = getHistory(host, 1);
        return history.isEmpty() ? Optional.empty() : Optional.of(history.get(0));
    }
}
