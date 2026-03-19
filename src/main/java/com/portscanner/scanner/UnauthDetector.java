package com.portscanner.scanner;

import com.portscanner.model.ScanResult;
import com.portscanner.model.UnauthResult;
import com.portscanner.scanner.probe.ActuatorUnauthProbe;
import com.portscanner.scanner.probe.ElasticsearchUnauthProbe;
import com.portscanner.scanner.probe.FtpAnonProbe;
import com.portscanner.scanner.probe.MemcachedUnauthProbe;
import com.portscanner.scanner.probe.PromUnauthProbe;
import com.portscanner.scanner.probe.RedisUnauthProbe;
import com.portscanner.scanner.probe.UnauthProbe;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Dispatches {@link UnauthProbe} implementations against open ports to detect
 * services that accept connections without credentials.
 */
public class UnauthDetector {

    private static final Logger log = LoggerFactory.getLogger(UnauthDetector.class);

    private final List<UnauthProbe> probes;

    public UnauthDetector() {
        this.probes = List.of(
                new RedisUnauthProbe(),
                new MemcachedUnauthProbe(),
                new ElasticsearchUnauthProbe(),
                new FtpAnonProbe(),
                new PromUnauthProbe(),
                new ActuatorUnauthProbe()
        );
    }

    /**
     * Tests a scan result for unauthenticated service access.
     * Returns the first positive {@link UnauthResult}, or empty if no probe matched
     * or the service requires authentication.
     */
    public Optional<UnauthResult> detect(String host, ScanResult result, int timeoutMs) {
        int port = result.getPort();
        String serviceName = result.getServiceName() != null
                ? result.getServiceName().toLowerCase() : "";

        for (UnauthProbe probe : probes) {
            boolean portMatches = probe.getApplicablePorts().contains(port);
            boolean serviceMatches = probe.getApplicableServices().stream()
                    .anyMatch(serviceName::contains);

            if (portMatches || serviceMatches) {
                try {
                    UnauthResult r = probe.probe(host, port, timeoutMs);
                    if (r.isUnauthenticated()) {
                        log.info("Unauthenticated {} detected at {}:{}", r.getService(), host, port);
                        return Optional.of(r);
                    }
                } catch (Exception e) {
                    log.debug("Unauth probe {} failed for {}:{} — {}",
                            probe.getClass().getSimpleName(), host, port, e.getMessage());
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Returns all probes that apply to a given port/service combination, for reporting.
     */
    public List<UnauthProbe> getApplicableProbes(int port, String serviceName) {
        String svcLower = serviceName != null ? serviceName.toLowerCase() : "";
        List<UnauthProbe> applicable = new ArrayList<>();
        for (UnauthProbe probe : probes) {
            if (probe.getApplicablePorts().contains(port)
                    || probe.getApplicableServices().stream().anyMatch(svcLower::contains)) {
                applicable.add(probe);
            }
        }
        return applicable;
    }
}
