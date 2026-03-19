package com.portscanner.scanner.probe;

import com.portscanner.model.UnauthResult;

import java.util.List;

/**
 * A probe that attempts to access a service without credentials to determine
 * whether it is openly accessible. Used by {@link com.portscanner.scanner.UnauthDetector}.
 */
public interface UnauthProbe {

    /** Port numbers this probe targets. */
    List<Integer> getApplicablePorts();

    /** Service name substrings this probe targets (case-insensitive match). */
    List<String> getApplicableServices();

    /**
     * Attempts unauthenticated access to the service at host:port.
     *
     * @param host      target hostname or IP
     * @param port      target port
     * @param timeoutMs connection and read timeout in milliseconds
     * @return result indicating whether unauthenticated access was possible
     */
    UnauthResult probe(String host, int port, int timeoutMs);
}
