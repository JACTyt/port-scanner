package com.portscanner.api.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScanRequest {
    private String host;
    private String ports = "1-1024";
    private String timing = "NORMAL";
    private int timeout = 200;
    private int threads = 100;
    private boolean banner;
    private boolean tls;
    private boolean http;
    private boolean cve;
    private String protocol = "tcp";
}
