package com.portscanner.plugin;

import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanResult;
import com.portscanner.plugin.builtin.HttpTitlePlugin;
import com.portscanner.plugin.builtin.SslCertPlugin;
import com.portscanner.plugin.builtin.SshVersionPlugin;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class PluginRegistryTest {

    private PluginRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new PluginRegistry();
    }

    @Test
    void getAllReturnsExactlyThreeBuiltInPlugins() {
        List<ScanPlugin> plugins = registry.getAll();
        assertEquals(3, plugins.size(), "Expected exactly 3 built-in plugins");
    }

    @Test
    void getByNameReturnsHttpTitlePlugin() {
        Optional<ScanPlugin> plugin = registry.getByName("http-title");
        assertTrue(plugin.isPresent(), "http-title plugin should be present");
        assertInstanceOf(HttpTitlePlugin.class, plugin.get());
    }

    @Test
    void getByNameReturnsSslCertPlugin() {
        Optional<ScanPlugin> plugin = registry.getByName("ssl-cert");
        assertTrue(plugin.isPresent(), "ssl-cert plugin should be present");
        assertInstanceOf(SslCertPlugin.class, plugin.get());
    }

    @Test
    void getByNameReturnsSshVersionPlugin() {
        Optional<ScanPlugin> plugin = registry.getByName("ssh-version");
        assertTrue(plugin.isPresent(), "ssh-version plugin should be present");
        assertInstanceOf(SshVersionPlugin.class, plugin.get());
    }

    @Test
    void getByNameReturnsEmptyForNonexistentPlugin() {
        Optional<ScanPlugin> plugin = registry.getByName("nonexistent");
        assertFalse(plugin.isPresent(), "nonexistent plugin should not be found");
    }

    @Test
    void httpTitlePluginAppliesToPort80() {
        ScanResult result = ScanResult.builder()
                .port(80)
                .status(PortStatus.OPEN)
                .build();
        HttpTitlePlugin plugin = new HttpTitlePlugin();
        assertTrue(plugin.appliesTo(result), "HttpTitlePlugin should apply to port 80");
    }

    @Test
    void httpTitlePluginDoesNotApplyToPort22() {
        ScanResult result = ScanResult.builder()
                .port(22)
                .status(PortStatus.OPEN)
                .build();
        HttpTitlePlugin plugin = new HttpTitlePlugin();
        assertFalse(plugin.appliesTo(result), "HttpTitlePlugin should not apply to port 22");
    }

    @Test
    void sshVersionPluginAppliesToPort22() {
        ScanResult result = ScanResult.builder()
                .port(22)
                .status(PortStatus.OPEN)
                .build();
        SshVersionPlugin plugin = new SshVersionPlugin();
        assertTrue(plugin.appliesTo(result), "SshVersionPlugin should apply to port 22");
    }

    @Test
    void sshVersionPluginDoesNotApplyToPort80() {
        ScanResult result = ScanResult.builder()
                .port(80)
                .status(PortStatus.OPEN)
                .build();
        SshVersionPlugin plugin = new SshVersionPlugin();
        assertFalse(plugin.appliesTo(result), "SshVersionPlugin should not apply to port 80");
    }

    @Test
    void getByNameIsCaseInsensitive() {
        Optional<ScanPlugin> plugin = registry.getByName("HTTP-TITLE");
        assertTrue(plugin.isPresent(), "getByName should be case-insensitive");
    }

    @Test
    void getAllReturnsUnmodifiableList() {
        List<ScanPlugin> plugins = registry.getAll();
        assertThrows(UnsupportedOperationException.class,
                () -> plugins.add(new HttpTitlePlugin()),
                "getAll() should return an unmodifiable list");
    }
}
