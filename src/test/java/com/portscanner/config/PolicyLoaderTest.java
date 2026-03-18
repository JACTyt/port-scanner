package com.portscanner.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PolicyLoaderTest {

    @TempDir
    Path tempDir;

    @Test
    void loads_single_fail_rule() throws Exception {
        Path policy = tempDir.resolve("policy.yaml");
        Files.writeString(policy, """
                rules:
                  - name: "No Telnet"
                    port: 23
                    state: OPEN
                    action: FAIL
                    message: "Telnet is insecure"
                """);

        List<PolicyRule> rules = PolicyLoader.load(policy);
        assertEquals(1, rules.size());
        PolicyRule r = rules.get(0);
        assertEquals("No Telnet", r.getName());
        assertEquals(23, r.getPort());
        assertEquals("OPEN", r.getState());
        assertEquals("FAIL", r.getAction());
        assertEquals("Telnet is insecure", r.getMessage());
    }

    @Test
    void loads_multiple_rules() throws Exception {
        Path policy = tempDir.resolve("policy.yaml");
        Files.writeString(policy, """
                rules:
                  - name: "No Telnet"
                    port: 23
                    state: OPEN
                    action: FAIL
                  - name: "Must have HTTPS"
                    port: 443
                    state: PASS_IF_PRESENT
                    action: FAIL
                  - name: "FTP warning"
                    port: 21
                    state: OPEN
                    action: WARN
                """);

        List<PolicyRule> rules = PolicyLoader.load(policy);
        assertEquals(3, rules.size());
        assertEquals(23, rules.get(0).getPort());
        assertEquals("PASS_IF_PRESENT", rules.get(1).getState());
        assertEquals("WARN", rules.get(2).getAction());
    }

    @Test
    void empty_rules_section_returns_empty_list() throws Exception {
        Path policy = tempDir.resolve("policy.yaml");
        Files.writeString(policy, "rules:\n");
        List<PolicyRule> rules = PolicyLoader.load(policy);
        assertTrue(rules.isEmpty());
    }

    @Test
    void missing_file_returns_empty_list() {
        List<PolicyRule> rules = PolicyLoader.load(Path.of("/nonexistent/policy.yaml"));
        assertNotNull(rules);
        assertTrue(rules.isEmpty());
    }

    @Test
    void malformed_yaml_returns_empty_list() throws Exception {
        Path policy = tempDir.resolve("bad.yaml");
        Files.writeString(policy, "rules: [this is not valid yaml: {{{");
        List<PolicyRule> rules = PolicyLoader.load(policy);
        assertNotNull(rules);
        assertTrue(rules.isEmpty());
    }

    @Test
    void optional_fields_are_null_when_absent() throws Exception {
        Path policy = tempDir.resolve("policy.yaml");
        Files.writeString(policy, """
                rules:
                  - port: 23
                    state: OPEN
                    action: FAIL
                """);
        List<PolicyRule> rules = PolicyLoader.load(policy);
        assertEquals(1, rules.size());
        assertNull(rules.get(0).getName());
        assertNull(rules.get(0).getService());
        assertNull(rules.get(0).getMessage());
    }
}
