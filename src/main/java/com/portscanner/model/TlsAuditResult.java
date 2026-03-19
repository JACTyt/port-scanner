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
public class TlsAuditResult {
    private List<String> supportedProtocols;
    private List<String> acceptedCiphers;
    private List<String> weakCiphers;
    private List<TlsVulnerability> vulnerabilities;
}
