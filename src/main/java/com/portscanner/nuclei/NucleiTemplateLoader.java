package com.portscanner.nuclei;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Loads {@link NucleiTemplate} objects from a directory of YAML files.
 * Silently skips files that fail to parse (unsupported template types).
 */
public class NucleiTemplateLoader {

    private static final Logger log = LoggerFactory.getLogger(NucleiTemplateLoader.class);
    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());

    /**
     * Load all {@code *.yaml} files from {@code dir}, optionally filtered by severity tags.
     *
     * @param dir      directory to scan (non-recursive)
     * @param tags     severity filter, e.g. ["critical","high"]. Empty/null = load all.
     */
    public List<NucleiTemplate> load(Path dir, List<String> tags) throws IOException {
        List<NucleiTemplate> result = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, "*.yaml")) {
            for (Path file : ds) {
                try {
                    NucleiTemplate t = YAML.readValue(file.toFile(), NucleiTemplate.class);
                    if (t.getId() == null || t.getInfo() == null) continue;
                    if (t.getHttp() == null || t.getHttp().isEmpty()) continue; // TCP not yet supported
                    if (tags != null && !tags.isEmpty()) {
                        String sev = t.getInfo().getSeverity();
                        if (sev == null || !tags.contains(sev.toLowerCase())) continue;
                    }
                    result.add(t);
                } catch (Exception e) {
                    log.debug("Skipping unsupported template {}: {}", file.getFileName(), e.getMessage());
                }
            }
        }
        return result;
    }
}
