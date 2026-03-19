package com.portscanner.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Result of a DNS security audit covering zone transfer, open resolver,
 * DNSSEC, and TCP DNS support checks.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DnsAuditResult {
    /** True if an AXFR zone transfer was accepted by this nameserver. Severity: HIGH. */
    private boolean zoneTransferAllowed;

    /** DNS records leaked via zone transfer (first 50). Non-null only when zoneTransferAllowed is true. */
    private List<String> leakedRecords;

    /** True if this server resolves external domains (open recursive resolver). Severity: MEDIUM. */
    private boolean openResolver;

    /** True if DNSSEC (DS / DNSKEY records) are present for this domain. */
    private boolean dnssecEnabled;

    /** True if the server accepts DNS queries on TCP port 53 (RFC 7766 compliance). */
    private boolean tcpEnabled;
}
