package com.portscanner.config;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PolicyEvaluatorTest {

    private ScanReport buildReport(int... openPorts) {
        List<ScanResult> results = new java.util.ArrayList<>();
        for (int p : openPorts) {
            results.add(ScanResult.builder().port(p).status(PortStatus.OPEN)
                    .serviceName(p == 23 ? "Telnet" : p == 22 ? "SSH" : "HTTP").build());
        }
        return ScanReport.builder()
                .host("192.168.1.1").resolvedIp("192.168.1.1")
                .openCount(openPorts.length).filteredCount(0).totalScanned(100)
                .openPorts(results).filteredPorts(List.of()).build();
    }

    private PolicyRule rule(int port, String state, String action) {
        PolicyRule r = new PolicyRule();
        r.setName("test-rule-" + port);
        r.setPort(port);
        r.setState(state);
        r.setAction(action);
        r.setMessage("test");
        return r;
    }

    // ── OPEN state ──────────────────────────────────────────────────────────

    @Test
    void no_violation_when_blocked_port_is_not_open() {
        ScanReport report = buildReport(22, 80);
        List<PolicyEvaluator.PolicyViolation> v =
                PolicyEvaluator.evaluate(report, List.of(rule(23, "OPEN", "FAIL")));
        assertTrue(v.isEmpty());
    }

    @Test
    void violation_when_blocked_port_is_open() {
        ScanReport report = buildReport(22, 23, 80);
        List<PolicyEvaluator.PolicyViolation> v =
                PolicyEvaluator.evaluate(report, List.of(rule(23, "OPEN", "FAIL")));
        assertEquals(1, v.size());
        assertEquals(23, v.get(0).port().getPort());
    }

    @Test
    void multiple_blocked_ports_each_produce_violation() {
        ScanReport report = buildReport(22, 23, 80);
        List<PolicyEvaluator.PolicyViolation> v =
                PolicyEvaluator.evaluate(report, List.of(
                        rule(22, "OPEN", "FAIL"),
                        rule(23, "OPEN", "FAIL")));
        assertEquals(2, v.size());
    }

    @Test
    void warn_action_is_non_fatal() {
        ScanReport report = buildReport(23);
        List<PolicyEvaluator.PolicyViolation> v =
                PolicyEvaluator.evaluate(report, List.of(rule(23, "OPEN", "WARN")));
        assertEquals(1, v.size());
        assertFalse(PolicyEvaluator.hasFatal(v));
    }

    @Test
    void fail_action_is_fatal() {
        ScanReport report = buildReport(23);
        List<PolicyEvaluator.PolicyViolation> v =
                PolicyEvaluator.evaluate(report, List.of(rule(23, "OPEN", "FAIL")));
        assertTrue(PolicyEvaluator.hasFatal(v));
    }

    // ── PASS_IF_PRESENT state ────────────────────────────────────────────────

    @Test
    void no_violation_when_required_port_is_present() {
        ScanReport report = buildReport(22, 443);
        List<PolicyEvaluator.PolicyViolation> v =
                PolicyEvaluator.evaluate(report, List.of(rule(443, "PASS_IF_PRESENT", "FAIL")));
        assertTrue(v.isEmpty());
    }

    @Test
    void violation_when_required_port_is_absent() {
        ScanReport report = buildReport(22, 80);
        List<PolicyEvaluator.PolicyViolation> v =
                PolicyEvaluator.evaluate(report, List.of(rule(443, "PASS_IF_PRESENT", "FAIL")));
        assertEquals(1, v.size());
        assertNull(v.get(0).port(), "port should be null for PASS_IF_PRESENT violation");
    }

    // ── Service filter ────────────────────────────────────────────────────────

    @Test
    void service_filter_prevents_match_when_service_differs() {
        ScanReport report = buildReport(22, 80);
        PolicyRule r = rule(22, "OPEN", "FAIL");
        r.setService("Telnet"); // port 22 is "SSH", not "Telnet"
        List<PolicyEvaluator.PolicyViolation> v = PolicyEvaluator.evaluate(report, List.of(r));
        assertTrue(v.isEmpty());
    }

    @Test
    void service_filter_matches_substring_case_insensitively() {
        ScanReport report = buildReport(23); // Telnet
        PolicyRule r = rule(23, "OPEN", "FAIL");
        r.setService("telnet");
        List<PolicyEvaluator.PolicyViolation> v = PolicyEvaluator.evaluate(report, List.of(r));
        assertEquals(1, v.size());
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    @Test
    void empty_rules_produces_no_violations() {
        ScanReport report = buildReport(22, 80);
        assertTrue(PolicyEvaluator.evaluate(report, List.of()).isEmpty());
    }

    @Test
    void empty_open_ports_with_open_rule_produces_no_violation() {
        ScanReport report = buildReport(); // no open ports
        List<PolicyEvaluator.PolicyViolation> v =
                PolicyEvaluator.evaluate(report, List.of(rule(23, "OPEN", "FAIL")));
        assertTrue(v.isEmpty());
    }

    @Test
    void has_fatal_returns_false_for_empty_list() {
        assertFalse(PolicyEvaluator.hasFatal(List.of()));
    }
}
