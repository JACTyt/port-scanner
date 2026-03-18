package com.portscanner.plugin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.stream.StreamSupport;

/**
 * Loads and manages {@link ScanPlugin} instances.
 *
 * <p>Two sources are checked in order:
 * <ol>
 *   <li><b>Built-in plugins</b> — discovered via {@link ServiceLoader} from
 *       {@code META-INF/services/com.portscanner.plugin.ScanPlugin} inside
 *       the shaded JAR.</li>
 *   <li><b>External plugins</b> — every {@code *.jar} found in
 *       {@code ~/.portscanner/plugins/}. Each JAR must contain a
 *       {@code META-INF/services/com.portscanner.plugin.ScanPlugin} file
 *       listing one implementation class per line (standard ServiceLoader
 *       convention).</li>
 * </ol>
 *
 * External plugin JARs are loaded with a child-first {@link URLClassLoader}
 * whose parent is the current thread's context class loader, so plugins can
 * use the same Jackson/SLF4J/Lombok versions already on the classpath.
 */
public class PluginRegistry {

    private static final Logger log = LoggerFactory.getLogger(PluginRegistry.class);

    /** Directory scanned for external plugin JARs. */
    private static final Path PLUGIN_DIR =
            Path.of(System.getProperty("user.home"), ".portscanner", "plugins");

    private final List<ScanPlugin> plugins;

    public PluginRegistry() {
        List<ScanPlugin> all = new ArrayList<>();
        // 1. Built-in plugins
        ServiceLoader.load(ScanPlugin.class).forEach(all::add);
        log.debug("Loaded {} built-in plugin(s)", all.size());

        // 2. External JAR plugins
        all.addAll(loadExternalPlugins());

        plugins = Collections.unmodifiableList(all);
    }

    /** Returns an unmodifiable view of all loaded plugins (built-in + external). */
    public List<ScanPlugin> getAll() {
        return plugins;
    }

    /** Finds a plugin by name (case-insensitive). */
    public Optional<ScanPlugin> getByName(String name) {
        return plugins.stream()
                .filter(p -> p.name().equalsIgnoreCase(name))
                .findFirst();
    }

    // ── External JAR loading ──────────────────────────────────────────────────

    private static List<ScanPlugin> loadExternalPlugins() {
        List<ScanPlugin> external = new ArrayList<>();

        if (!Files.isDirectory(PLUGIN_DIR)) {
            log.debug("External plugin directory does not exist: {}", PLUGIN_DIR);
            return external;
        }

        File[] jars = PLUGIN_DIR.toFile().listFiles(f -> f.isFile() && f.getName().endsWith(".jar"));
        if (jars == null || jars.length == 0) {
            log.debug("No external plugin JARs found in {}", PLUGIN_DIR);
            return external;
        }

        for (File jar : jars) {
            try {
                URL[] urls = {jar.toURI().toURL()};
                // Child-first: plugins see their own classes first, then fall through to the
                // host classloader for shared dependencies (Jackson, SLF4J, etc.)
                URLClassLoader child = new URLClassLoader(urls,
                        Thread.currentThread().getContextClassLoader());

                List<ScanPlugin> fromJar = StreamSupport
                        .stream(ServiceLoader.load(ScanPlugin.class, child).spliterator(), false)
                        .toList();

                log.info("Loaded {} plugin(s) from external JAR: {}", fromJar.size(), jar.getName());
                external.addAll(fromJar);
            } catch (Exception e) {
                log.warn("Failed to load external plugin JAR {}: {}", jar.getName(), e.getMessage());
            }
        }
        return external;
    }
}
