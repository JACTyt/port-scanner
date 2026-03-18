package com.portscanner.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Loads a YAML policy file into a list of {@link PolicyRule} objects.
 *
 * <p>Example policy file:
 * <pre>
 * rules:
 *   - name: "No Telnet"
 *     port: 23
 *     state: OPEN
 *     action: FAIL
 *     message: "Telnet is unencrypted"
 *   - name: "Must have HTTPS"
 *     port: 443
 *     state: PASS_IF_PRESENT
 *     action: FAIL
 * </pre>
 */
public class PolicyLoader {

    private static final Logger log = LoggerFactory.getLogger(PolicyLoader.class);
    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());

    @Data
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class PolicyFile {
        private List<PolicyRule> rules;
    }

    /**
     * Load policy rules from a YAML file.
     *
     * @param path path to the policy YAML file
     * @return list of rules; empty list on parse error or missing file
     */
    public static List<PolicyRule> load(Path path) {
        try {
            PolicyFile file = YAML.readValue(Files.readString(path), PolicyFile.class);
            return file.getRules() != null ? file.getRules() : List.of();
        } catch (Exception e) {
            log.warn("Failed to load policy file {}: {}", path, e.getMessage());
            return List.of();
        }
    }
}
