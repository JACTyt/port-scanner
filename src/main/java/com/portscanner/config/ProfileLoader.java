package com.portscanner.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Loads scan profiles from built-in definitions and from the user's
 * {@code ~/.portscanner/profiles.yaml} file.
 *
 * <p>Custom profiles override built-ins with the same name. Profile names are
 * case-insensitive.
 *
 * <p>Built-in profiles:
 * <ul>
 *   <li>{@code quick}   — top-100 ports, T4 timing
 *   <li>{@code web}     — web ports (80,443,8080,8443,3000,5000), banner+TLS+HTTP
 *   <li>{@code db}      — database ports (1433,3306,5432,6379,27017,9042), banner+probes
 *   <li>{@code full}    — all 65535 ports, T3, banner+TLS+HTTP+geolocate
 *   <li>{@code stealth} — top-100 ports, T1 timing, rate=10 pps
 * </ul>
 */
public class ProfileLoader {

    private static final String PROFILES_FILE =
            System.getProperty("user.home") + "/.portscanner/profiles.yaml";

    private static final Map<String, ScanProfile> BUILT_INS;

    static {
        Map<String, ScanProfile> m = new LinkedHashMap<>();
        m.put("quick",   profile(null,                              null,  null,  null,  null,  null,  100, "T4", null));
        m.put("web",     profile("80,443,8080,8443,3000,5000",      true,  false, true,  true,  false, null, null, null));
        m.put("db",      profile("1433,3306,5432,6379,27017,9042",  true,  true,  false, false, false, null, null, null));
        m.put("full",    profile("1-65535",                         true,  false, true,  true,  true,  null, "T3", null));
        m.put("stealth", profile(null,                              null,  null,  null,  null,  null,  100, "T1", 10));
        BUILT_INS = Collections.unmodifiableMap(m);
    }

    private static ScanProfile profile(String ports, Boolean banner, Boolean probes,
                                        Boolean tls, Boolean http, Boolean geolocate,
                                        Integer topPorts, String timing, Integer rate) {
        ScanProfile p = new ScanProfile();
        p.setPorts(ports);
        p.setBanner(banner);
        p.setProbes(probes);
        p.setTls(tls);
        p.setHttp(http);
        p.setGeolocate(geolocate);
        p.setTopPorts(topPorts);
        p.setTiming(timing);
        p.setRate(rate);
        return p;
    }

    /**
     * Loads a profile by name. Custom profiles take precedence over built-ins.
     * Returns {@link Optional#empty()} if no profile with that name is found.
     */
    public static Optional<ScanProfile> load(String name) {
        if (name == null || name.isBlank()) return Optional.empty();
        String key = name.toLowerCase();

        Map<String, ScanProfile> custom = loadCustom();
        if (custom.containsKey(key)) return Optional.of(custom.get(key));

        return Optional.ofNullable(BUILT_INS.get(key));
    }

    /** Returns the names of all available profiles (built-in + custom). */
    public static List<String> listAll() {
        List<String> names = new ArrayList<>(BUILT_INS.keySet());
        for (String name : loadCustom().keySet()) {
            if (!names.contains(name)) names.add(name);
        }
        return names;
    }

    private static Map<String, ScanProfile> loadCustom() {
        Path file = Path.of(PROFILES_FILE);
        if (!Files.exists(file)) return Map.of();
        try {
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
            ProfilesYaml parsed = mapper.readValue(file.toFile(), ProfilesYaml.class);
            if (parsed == null || parsed.getProfiles() == null) return Map.of();
            // Normalise keys to lower-case
            Map<String, ScanProfile> result = new LinkedHashMap<>();
            parsed.getProfiles().forEach((k, v) -> result.put(k.toLowerCase(), v));
            return result;
        } catch (IOException e) {
            System.err.println("Warning: could not read profiles.yaml — " + e.getMessage());
            return Map.of();
        }
    }

    /** YAML top-level wrapper: {@code profiles: {name: ScanProfile, ...}}. */
    @Data
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class ProfilesYaml {
        private Map<String, ScanProfile> profiles;
    }
}
