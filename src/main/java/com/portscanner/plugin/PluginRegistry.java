package com.portscanner.plugin;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Loads and manages {@link ScanPlugin} instances via {@link ServiceLoader}.
 * Plugins are registered in {@code META-INF/services/com.portscanner.plugin.ScanPlugin}.
 */
public class PluginRegistry {

    private final List<ScanPlugin> plugins;

    public PluginRegistry() {
        plugins = StreamSupport.stream(
                ServiceLoader.load(ScanPlugin.class).spliterator(), false)
                .collect(Collectors.toList());
    }

    /**
     * Returns an unmodifiable view of all loaded plugins.
     */
    public List<ScanPlugin> getAll() {
        return Collections.unmodifiableList(plugins);
    }

    /**
     * Finds a plugin by name (case-insensitive).
     *
     * @param name the plugin name to look up
     * @return an Optional containing the matching plugin, or empty if not found
     */
    public Optional<ScanPlugin> getByName(String name) {
        return plugins.stream()
                .filter(p -> p.name().equalsIgnoreCase(name))
                .findFirst();
    }
}
