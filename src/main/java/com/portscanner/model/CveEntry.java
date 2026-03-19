package com.portscanner.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Enriched CVE record with CVSS scores, severity, and EPSS exploit probability.
 * Replaces the plain {@code String} CVE ID previously stored in {@code ScanResult.cves}.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CveEntry {
    /** CVE identifier, e.g. "CVE-2023-38408". */
    private String id;

    /** CVSS v3.x base score (0.0 – 10.0). Null when not available. */
    private Double cvssV3;

    /** CVSS v2 base score (0.0 – 10.0). Null when not available. */
    private Double cvssV2;

    /** CVSS vector string, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H". */
    private String cvssVector;

    /** Textual severity derived from CVSS score: CRITICAL / HIGH / MEDIUM / LOW / INFO. */
    private String severity;

    /**
     * EPSS (Exploit Prediction Scoring System) probability: 0.0–1.0.
     * Represents the probability this CVE will be exploited in the wild within 30 days.
     */
    private Double epss;

    /** First 120 characters of the NVD English description. */
    private String description;

    // ── Convenience helpers ──────────────────────────────────────────────────

    /** Returns the CVE ID as a string (used where String.join was previously called). */
    @Override
    public String toString() {
        return id != null ? id : "unknown";
    }

    /**
     * Derives a severity label from a CVSS v3 score when no explicit label is available.
     * CVSS v3: CRITICAL ≥ 9.0, HIGH ≥ 7.0, MEDIUM ≥ 4.0, LOW ≥ 0.1, INFO = 0.0
     */
    public static String deriveSeverity(double cvssScore) {
        if (cvssScore >= 9.0) return "CRITICAL";
        if (cvssScore >= 7.0) return "HIGH";
        if (cvssScore >= 4.0) return "MEDIUM";
        if (cvssScore >= 0.1) return "LOW";
        return "INFO";
    }
}
