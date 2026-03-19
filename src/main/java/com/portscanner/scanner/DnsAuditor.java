package com.portscanner.scanner;

import com.portscanner.model.DnsAuditResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;
import org.xbill.DNS.ZoneTransferIn;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * DNS security auditor using dnsjava.
 * Checks for: AXFR zone transfer misconfiguration, open recursive resolver,
 * DNSSEC presence, and TCP DNS support.
 */
public class DnsAuditor {

    private static final Logger log = LoggerFactory.getLogger(DnsAuditor.class);

    /**
     * Runs all DNS security checks against the target.
     *
     * @param targetIp  the IP address of the DNS server (used for open resolver + TCP tests)
     * @param domain    the domain name to use for zone transfer and DNSSEC checks;
     *                  if null or an IP address, zone transfer and DNSSEC are skipped
     * @param timeoutMs connection and query timeout in milliseconds
     */
    public static Optional<DnsAuditResult> audit(String targetIp, String domain, int timeoutMs) {
        boolean zoneTransferAllowed = false;
        List<String> leakedRecords = new ArrayList<>();
        boolean openResolver = false;
        boolean dnssecEnabled = false;
        boolean tcpEnabled = false;

        boolean hasDomain = domain != null && !domain.isBlank() && !domain.matches("\\d+\\.\\d+\\.\\d+\\.\\d+");

        // ── Zone transfer (AXFR) ────────────────────────────────────────────
        if (hasDomain) {
            try {
                // Find authoritative nameservers for the domain
                Lookup nsLookup = new Lookup(domain, Type.NS);
                Record[] nsRecords = nsLookup.run();

                if (nsRecords != null) {
                    for (Record rec : nsRecords) {
                        if (!(rec instanceof NSRecord nsRec)) continue;
                        String nsName = nsRec.getTarget().toString(true);
                        // Resolve nameserver IP
                        Lookup aLookup = new Lookup(nsName, Type.A);
                        Record[] aRecords = aLookup.run();
                        if (aRecords == null || aRecords.length == 0) continue;
                        String nsIp = ((ARecord) aRecords[0]).getAddress().getHostAddress();

                        // Attempt AXFR against this nameserver
                        try {
                            SimpleResolver resolver = new SimpleResolver(nsIp);
                            resolver.setTimeout(Duration.ofMillis(Math.min(timeoutMs, 5000)));
                            Name zoneName = Name.fromString(domain.endsWith(".") ? domain : domain + ".");
                            ZoneTransferIn xfr = ZoneTransferIn.newAXFR(zoneName, resolver);
                            List<Record> zoneRecords = xfr.run();
                            if (!zoneRecords.isEmpty()) {
                                zoneTransferAllowed = true;
                                int limit = Math.min(zoneRecords.size(), 50);
                                for (int i = 0; i < limit; i++) {
                                    leakedRecords.add(zoneRecords.get(i).toString());
                                }
                                log.warn("Zone transfer ALLOWED for {} from {}", domain, nsIp);
                                break; // One successful AXFR is enough to report the issue
                            }
                        } catch (Exception xfrEx) {
                            log.debug("AXFR refused by {} for {} — {}", nsIp, domain, xfrEx.getMessage());
                        }
                    }
                }
            } catch (Exception e) {
                log.debug("Zone transfer check failed for {} — {}", domain, e.getMessage());
            }
        }

        // ── Open resolver detection ─────────────────────────────────────────
        try {
            SimpleResolver resolver = new SimpleResolver(targetIp);
            resolver.setPort(53);
            resolver.setTimeout(Duration.ofMillis(Math.min(timeoutMs, 3000)));
            // Query for an external domain — if the server resolves it, it's an open resolver
            Lookup testLookup = new Lookup("dns.google.", Type.A);
            testLookup.setResolver(resolver);
            testLookup.setCache(null);
            testLookup.run();
            openResolver = (testLookup.getResult() == Lookup.SUCCESSFUL);
        } catch (Exception e) {
            log.debug("Open resolver test failed for {} — {}", targetIp, e.getMessage());
        }

        // ── DNSSEC presence ─────────────────────────────────────────────────
        if (hasDomain) {
            try {
                Record[] dsRecords = new Lookup(domain, Type.DS).run();
                Record[] dnskeyRecords = new Lookup(domain, Type.DNSKEY).run();
                dnssecEnabled = (dsRecords != null && dsRecords.length > 0)
                        || (dnskeyRecords != null && dnskeyRecords.length > 0);
            } catch (Exception e) {
                log.debug("DNSSEC check failed for {} — {}", domain, e.getMessage());
            }
        }

        // ── TCP DNS support ─────────────────────────────────────────────────
        try (Socket tcpSocket = new Socket()) {
            tcpSocket.connect(new InetSocketAddress(targetIp, 53), timeoutMs);
            tcpEnabled = true;
        } catch (Exception e) {
            tcpEnabled = false;
        }

        return Optional.of(DnsAuditResult.builder()
                .zoneTransferAllowed(zoneTransferAllowed)
                .leakedRecords(leakedRecords.isEmpty() ? null : leakedRecords)
                .openResolver(openResolver)
                .dnssecEnabled(dnssecEnabled)
                .tcpEnabled(tcpEnabled)
                .build());
    }
}
