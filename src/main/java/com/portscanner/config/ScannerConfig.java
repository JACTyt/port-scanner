package com.portscanner.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * User-level configuration loaded from ~/.portscanner/config.yaml.
 * All fields are optional; null means "use CLI default".
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScannerConfig {
    private Integer timeout;
    private Integer threads;
    private String ports;
    private String outputDir;
    private Boolean banner;
    private Boolean showAll;
}
