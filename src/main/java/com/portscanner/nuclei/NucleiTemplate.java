package com.portscanner.nuclei;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Subset of the Nuclei YAML template schema we support.
 * Unknown fields are ignored — forward-compatible with real nuclei-templates.
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class NucleiTemplate {

    private String id;
    private Info info;
    private List<HttpRequest> http;

    @Data
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Info {
        private String name;
        private String severity;   // info, low, medium, high, critical
        @JsonProperty("cve-id")
        private String cveId;
        private String description;
    }

    @Data
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class HttpRequest {
        private String method;    // GET, POST, …
        private List<String> path;
        private List<Matcher> matchers;
        @JsonProperty("matchers-condition")
        private String matchersCondition; // "and" | "or" (default "or")
    }

    @Data
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Matcher {
        private String type;       // "regex" | "word" | "status"
        private List<String> regex;
        private List<String> words;
        private List<Integer> status;
        private String condition;  // "and" | "or"
        private boolean negative;
    }
}
