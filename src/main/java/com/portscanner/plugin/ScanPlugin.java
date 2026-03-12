package com.portscanner.plugin;

import com.portscanner.model.ScanResult;

/**
 * Plugin interface for enriching scan results, similar to Nmap NSE scripts.
 * Implementations are discovered via Java {@link java.util.ServiceLoader}.
 */
public interface ScanPlugin {

    /**
     * Returns the unique name of this plugin (e.g. "http-title").
     */
    String name();

    /**
     * Returns true if this plugin should run against the given scan result.
     */
    boolean appliesTo(ScanResult result);

    /**
     * Executes the plugin logic, potentially enriching the {@link ScanResult}
     * (e.g. setting banner, tlsInfo, etc.).
     *
     * @param result the scan result to enrich (mutated in place)
     * @param ctx    contextual information such as host, timeout, config
     */
    void execute(ScanResult result, PluginContext ctx);
}
