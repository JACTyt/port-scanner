package com.portscanner.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Result of an unauthenticated service access probe.
 * If {@code unauthenticated} is true, the service accepted a connection and
 * responded without requiring any credentials.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UnauthResult {
    /** True if the service is accessible without credentials. */
    private boolean unauthenticated;

    /** Human-readable evidence: what the server responded with. */
    private String evidence;

    /** Risk severity: CRITICAL, HIGH, MEDIUM. */
    private String severity;

    /** Detected service name (e.g. "Redis", "Elasticsearch"). */
    private String service;
}
