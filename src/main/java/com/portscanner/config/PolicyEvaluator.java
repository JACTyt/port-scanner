package com.portscanner.config;

import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates a list of {@link PolicyRule} objects against a completed {@link ScanReport}.
 */
public class PolicyEvaluator {

    /** A rule that was triggered along with the matching port (may be null for PASS_IF_PRESENT). */
    public record PolicyViolation(PolicyRule rule, ScanResult port) {}

    /**
     * Evaluate all rules and return violations.
     *
     * @param report completed scan report
     * @param rules  rules to evaluate
     * @return list of violations; empty means all rules passed
     */
    public static List<PolicyViolation> evaluate(ScanReport report, List<PolicyRule> rules) {
        List<ScanResult> open = report.getOpenPorts() != null ? report.getOpenPorts() : List.of();
        List<PolicyViolation> violations = new ArrayList<>();

        for (PolicyRule rule : rules) {
            if (rule.getPort() == null) continue;

            String state = rule.getState() != null ? rule.getState().toUpperCase() : "OPEN";

            if ("OPEN".equals(state)) {
                // Trigger if this port IS open
                open.stream()
                    .filter(r -> r.getPort() == rule.getPort())
                    .filter(r -> serviceMatches(r, rule.getService()))
                    .forEach(r -> violations.add(new PolicyViolation(rule, r)));

            } else if ("PASS_IF_PRESENT".equals(state)) {
                // Trigger if this port is NOT open (required port missing)
                boolean found = open.stream().anyMatch(r -> r.getPort() == rule.getPort());
                if (!found) {
                    violations.add(new PolicyViolation(rule, null));
                }
            }
        }

        return violations;
    }

    /** Returns true if no service filter is set, or if the result's service name matches. */
    private static boolean serviceMatches(ScanResult r, String serviceFilter) {
        if (serviceFilter == null || serviceFilter.isBlank()) return true;
        if (r.getServiceName() == null) return false;
        return r.getServiceName().toLowerCase().contains(serviceFilter.toLowerCase());
    }

    /** True if any violation has action=FAIL — these cause exit code 1. */
    public static boolean hasFatal(List<PolicyViolation> violations) {
        return violations.stream()
                .anyMatch(v -> "FAIL".equalsIgnoreCase(v.rule().getAction()));
    }
}
