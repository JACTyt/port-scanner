package com.portscanner.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * A single rule in a scan policy file.
 *
 * <pre>
 * rules:
 *   - name: "No Telnet"
 *     port: 23
 *     state: OPEN
 *     action: FAIL
 *     message: "Telnet is unencrypted — disable it"
 *
 *   - name: "Must have HTTPS"
 *     port: 443
 *     state: PASS_IF_PRESENT
 *     action: FAIL
 * </pre>
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class PolicyRule {
    /** Human-readable rule name shown in violation output. */
    private String name;

    /** Port number this rule applies to. Required. */
    private Integer port;

    /**
     * Port state that triggers this rule:
     * <ul>
     *   <li>{@code OPEN} — trigger when the port IS open (use to block dangerous ports)</li>
     *   <li>{@code PASS_IF_PRESENT} — trigger when the port is NOT open (use to require a port)</li>
     * </ul>
     */
    private String state;

    /**
     * Optional service name filter (case-insensitive substring match).
     * When set, the rule only fires if the detected service name contains this string.
     */
    private String service;

    /**
     * Consequence when the rule is triggered:
     * <ul>
     *   <li>{@code FAIL} — marks the scan as failed (exit code 1)</li>
     *   <li>{@code WARN} — prints a warning but does not change exit code</li>
     *   <li>{@code INFO} — informational only</li>
     * </ul>
     */
    private String action;

    /** Message printed when this rule is violated. */
    private String message;
}
