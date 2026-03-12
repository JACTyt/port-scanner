package com.portscanner.scanner;

import com.portscanner.model.SubdomainResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Performs parallel DNS subdomain brute-force using dnsjava and Java 21 virtual threads.
 *
 * <p>Wildcard DNS detection is performed before enumeration: if a random subdomain resolves,
 * its address is recorded and subsequent matches are silently dropped.
 */
public class DnsBruteForcer {

    private static final Logger log = LoggerFactory.getLogger(DnsBruteForcer.class);
    private static final int MAX_CONCURRENT = 200;

    private final String baseDomain;
    private final int timeoutMs;
    private final Resolver resolver;

    public DnsBruteForcer(String baseDomain, int timeoutMs) throws TextParseException, java.net.UnknownHostException {
        this.baseDomain = baseDomain.endsWith(".") ? baseDomain : baseDomain + ".";
        this.timeoutMs = timeoutMs;
        SimpleResolver sr = new SimpleResolver();
        sr.setTimeout(Duration.ofMillis(Math.max(timeoutMs, 2000)));
        this.resolver = sr;
    }

    /** Package-private constructor for testing with a mock resolver. */
    DnsBruteForcer(String baseDomain, int timeoutMs, Resolver resolver) {
        this.baseDomain = baseDomain.endsWith(".") ? baseDomain : baseDomain + ".";
        this.timeoutMs = timeoutMs;
        this.resolver = resolver;
    }

    /**
     * Loads a wordlist from {@code customPath}, or from the bundled resource
     * ({@code /top-1000-subdomains.txt}) if {@code customPath} is null or absent.
     */
    public List<String> loadWordlist(Path customPath) throws IOException {
        if (customPath != null && Files.exists(customPath)) {
            try (var lines = Files.lines(customPath)) {
                return lines.map(String::trim)
                        .filter(l -> !l.isEmpty() && !l.startsWith("#"))
                        .collect(Collectors.toList());
            }
        }
        InputStream is = getClass().getResourceAsStream("/top-1000-subdomains.txt");
        if (is == null) throw new IOException("Bundled wordlist not found on classpath");
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            return reader.lines()
                    .map(String::trim)
                    .filter(l -> !l.isEmpty() && !l.startsWith("#"))
                    .collect(Collectors.toList());
        }
    }

    /**
     * Brute-forces subdomains from the given wordlist in parallel.
     * Returns only successfully resolved entries.
     */
    public List<SubdomainResult> bruteForce(List<String> wordlist) {
        if (wordlist.isEmpty()) return List.of();

        // Wildcard detection: probe a random nonexistent subdomain first
        Set<String> wildcardAddresses = detectWildcard();
        if (!wildcardAddresses.isEmpty()) {
            log.warn("Wildcard DNS detected for {} — {} IPs will be filtered as false positives",
                    baseDomain, wildcardAddresses.size());
        }

        List<SubdomainResult> results = new CopyOnWriteArrayList<>();
        Semaphore sem = new Semaphore(MAX_CONCURRENT);

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<?>> futures = new ArrayList<>(wordlist.size());
            for (String word : wordlist) {
                if (word.isBlank()) continue;
                String fqdn = word + "." + baseDomain;
                futures.add(executor.submit(() -> {
                    try {
                        sem.acquire();
                        try {
                            resolve(fqdn).ifPresent(r -> {
                                // Drop wildcard matches
                                if (r.getAddresses() != null &&
                                        r.getAddresses().stream().noneMatch(wildcardAddresses::contains)) {
                                    results.add(r);
                                }
                            });
                        } finally {
                            sem.release();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    return null;
                }));
            }
            for (Future<?> f : futures) {
                try { f.get(); } catch (Exception ignored) {}
            }
        }

        results.sort(Comparator.comparing(SubdomainResult::getSubdomain));
        return results;
    }

    private Set<String> detectWildcard() {
        String randomLabel = "this-should-not-exist-" + UUID.randomUUID().toString().substring(0, 8);
        String probeFqdn = randomLabel + "." + baseDomain;
        return resolve(probeFqdn)
                .map(r -> r.getAddresses() != null ? new HashSet<>(r.getAddresses()) : Collections.<String>emptySet())
                .orElse(Collections.emptySet());
    }

    Optional<SubdomainResult> resolve(String fqdn) {
        try {
            // Try A record
            List<String> addresses = new ArrayList<>();
            String cname = null;

            Lookup lookup = new Lookup(fqdn, Type.A);
            lookup.setResolver(resolver);
            org.xbill.DNS.Record[] records = lookup.run();

            if (records != null) {
                for (org.xbill.DNS.Record rec : records) {
                    if (rec instanceof ARecord a) addresses.add(a.getAddress().getHostAddress());
                    if (rec instanceof CNAMERecord c) cname = c.getTarget().toString(true);
                }
            }

            // Try AAAA if no A records
            if (addresses.isEmpty()) {
                Lookup aaaaLookup = new Lookup(fqdn, Type.AAAA);
                aaaaLookup.setResolver(resolver);
                org.xbill.DNS.Record[] aaaaRecords = aaaaLookup.run();
                if (aaaaRecords != null) {
                    for (org.xbill.DNS.Record rec : aaaaRecords) {
                        if (rec instanceof AAAARecord aaaa) addresses.add(aaaa.getAddress().getHostAddress());
                    }
                }
            }

            if (addresses.isEmpty() && cname == null) return Optional.empty();

            // Strip trailing dot from FQDN for display
            String display = fqdn.endsWith(".") ? fqdn.substring(0, fqdn.length() - 1) : fqdn;
            return Optional.of(SubdomainResult.builder()
                    .subdomain(display)
                    .addresses(addresses.isEmpty() ? null : addresses)
                    .cname(cname)
                    .build());

        } catch (Exception e) {
            log.debug("DNS lookup failed for {}: {}", fqdn, e.getMessage());
            return Optional.empty();
        }
    }
}
