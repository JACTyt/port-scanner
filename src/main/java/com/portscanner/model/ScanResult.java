package com.portscanner.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScanResult {
    private int port;
    private PortStatus status;
    private String serviceName;
    private String banner;
    /** Version string extracted from the banner by {@code VersionExtractor}. */
    private String version;
    private long responseTimeMs;
    private List<CveEntry> cves;
    private String hostname;
    private TlsInfo tlsInfo;
    private TlsAuditResult tlsAuditResult;
    private SshAuditResult sshAuditResult;
    private HttpInfo httpInfo;
    private HttpSecurityAuditResult httpSecurityAuditResult;
    private SnmpInfo snmpInfo;
    private UnauthResult unauthResult;
    private DnsAuditResult dnsAuditResult;
    private List<NucleiResult> nucleiFindings;
}
