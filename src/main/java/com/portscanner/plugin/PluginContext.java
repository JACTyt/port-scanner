package com.portscanner.plugin;

import com.portscanner.config.ScannerConfig;

import java.io.PrintStream;

/**
 * Carries contextual information passed to each {@link ScanPlugin} during execution.
 */
public class PluginContext {

    private final String host;
    private final int timeoutMs;
    private final ScannerConfig config;
    private final PrintStream out;

    public PluginContext(String host, int timeoutMs, ScannerConfig config, PrintStream out) {
        this.host = host;
        this.timeoutMs = timeoutMs;
        this.config = config;
        this.out = out;
    }

    public String getHost() {
        return host;
    }

    public int getTimeoutMs() {
        return timeoutMs;
    }

    public ScannerConfig getConfig() {
        return config;
    }

    public PrintStream getOut() {
        return out;
    }
}
