package com.portscanner.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ThreatInfo {
    private int abuseConfidenceScore;
    private int abuseReportCount;
    private String isp;
    private String greynoiseClassification;
    private boolean greynoiseIsScanner;
}
