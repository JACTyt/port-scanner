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
    private List<String> cves;
    private String hostname;
    private TlsInfo tlsInfo;
    private HttpInfo httpInfo;
    private SnmpInfo snmpInfo;
}
