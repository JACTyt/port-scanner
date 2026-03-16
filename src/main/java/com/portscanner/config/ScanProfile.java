package com.portscanner.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * A named scan profile that bundles frequently-used flag combinations.
 *
 * <p>Built-in profiles: {@code quick}, {@code web}, {@code db}, {@code full}, {@code stealth}.
 * Custom profiles are loaded from {@code ~/.portscanner/profiles.yaml}.
 *
 * <p>When a profile is applied, each field is used only if the corresponding CLI flag was
 * not explicitly set by the user (i.e. still at its default value). CLI flags always win.
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScanProfile {

    /** Port range or list, e.g. {@code "80,443,8080"} or {@code "1-1024"}. */
    private String ports;

    /** Enable banner grabbing. */
    private Boolean banner;

    /** Enable protocol-specific probes (requires banner). */
    private Boolean probes;

    /** Enable TLS certificate inspection. */
    private Boolean tls;

    /** Enable HTTP header analysis. */
    private Boolean http;

    /** Enable IP geolocation. */
    private Boolean geolocate;

    /** Use top-N ports (overrides {@code ports}). */
    private Integer topPorts;

    /** Timing profile alias, e.g. {@code "T4"} or {@code "AGGRESSIVE"}. */
    private String timing;

    /** Packets-per-second rate limit (0 = unlimited). */
    private Integer rate;
}
