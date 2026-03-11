package com.portscanner.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.IOException;
import java.nio.file.*;

public class ConfigLoader {

    private static final String CONFIG_FILE = System.getProperty("user.dir") + "/config.yaml";

    /**
     * Loads config from ~/.portscanner/config.yaml.
     * Returns an empty ScannerConfig (all nulls) if the file does not exist.
     */
    public static ScannerConfig load() {
        Path configPath = Path.of(CONFIG_FILE);
        if (!Files.exists(configPath)) return new ScannerConfig();
        try {
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
            return mapper.readValue(configPath.toFile(), ScannerConfig.class);
        } catch (IOException e) {
            System.err.println("Warning: could not read config file " + CONFIG_FILE + " — " + e.getMessage());
            return new ScannerConfig();
        }
    }

    /**
     * Creates ~/.portscanner/ and writes a sample config.yaml if none exists.
     */
    public static void createSampleIfAbsent() {
        Path file = Path.of(CONFIG_FILE);
        if (Files.exists(file)) return;
        try {
            String sample = """
                    # Port Scanner configuration (config.yaml — place next to the JAR)
                    # All settings are optional. CLI flags always override these values.
                    #
                    # timeout: 200       # connection timeout in ms (50-5000)
                    # threads: 100       # thread pool size (max 200)
                    # ports: 1-1024      # default port range
                    # banner: false      # enable banner grabbing by default
                    # showAll: false     # show all ports including closed
                    # outputDir: ~/scans # default directory for report files
                    """;
            Files.writeString(file, sample);
        } catch (IOException e) {
            // Config file is optional — silently ignore creation failure
        }
    }
}
