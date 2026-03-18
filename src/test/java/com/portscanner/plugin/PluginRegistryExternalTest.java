package com.portscanner.plugin;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for external plugin loading (TASK-14).
 * Verifies that PluginRegistry loads built-in plugins and handles edge cases
 * for the external plugin directory gracefully.
 */
class PluginRegistryExternalTest {

    @Test
    void builtInPluginsAreAlwaysLoaded() {
        PluginRegistry registry = new PluginRegistry();
        List<ScanPlugin> all = registry.getAll();
        // Built-in plugins: http-title, ssl-cert, ssh-version (from META-INF/services)
        assertFalse(all.isEmpty(), "At least the built-in plugins should be loaded");
    }

    @Test
    void getByNameFindsBuiltInPlugin() {
        PluginRegistry registry = new PluginRegistry();
        // http-title is one of the built-in plugins
        assertTrue(registry.getByName("http-title").isPresent(), "http-title plugin should be found");
    }

    @Test
    void getByNameCaseInsensitive() {
        PluginRegistry registry = new PluginRegistry();
        assertTrue(registry.getByName("HTTP-TITLE").isPresent(), "Plugin lookup should be case-insensitive");
        assertTrue(registry.getByName("Http-Title").isPresent());
    }

    @Test
    void getByNameReturnsEmptyForUnknownPlugin() {
        PluginRegistry registry = new PluginRegistry();
        assertFalse(registry.getByName("does-not-exist").isPresent());
    }

    @Test
    void getAllReturnsUnmodifiableList() {
        PluginRegistry registry = new PluginRegistry();
        List<ScanPlugin> all = registry.getAll();
        assertThrows(UnsupportedOperationException.class, () -> all.add(null),
                "getAll() should return an unmodifiable list");
    }

    @Test
    void missingPluginDirDoesNotThrow() {
        // The plugin dir (~/.portscanner/plugins) may not exist in CI — must not throw
        assertDoesNotThrow(PluginRegistry::new,
                "PluginRegistry constructor must not throw even if plugin dir is absent");
    }

    @Test
    void emptyPluginDirLoadsOnlyBuiltIns(@TempDir Path dir) {
        // Temporarily override user.home to a tmp dir with no JARs in plugins/
        String oldHome = System.getProperty("user.home");
        try {
            System.setProperty("user.home", dir.toString());
            PluginRegistry registry = new PluginRegistry();
            // Should still have built-ins
            assertFalse(registry.getAll().isEmpty());
        } finally {
            System.setProperty("user.home", oldHome);
        }
    }

    @Test
    void invalidJarInPluginDirDoesNotThrow(@TempDir Path dir) throws Exception {
        // Create a fake (invalid) JAR file in the plugins directory
        Path pluginsDir = dir.resolve(".portscanner").resolve("plugins");
        Files.createDirectories(pluginsDir);
        Files.writeString(pluginsDir.resolve("broken.jar"), "this is not a real JAR file");

        String oldHome = System.getProperty("user.home");
        try {
            System.setProperty("user.home", dir.toString());
            // Must not throw — broken JARs are logged as warnings and skipped
            assertDoesNotThrow(PluginRegistry::new);
        } finally {
            System.setProperty("user.home", oldHome);
        }
    }
}
