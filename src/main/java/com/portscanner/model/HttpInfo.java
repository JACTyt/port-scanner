package com.portscanner.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class HttpInfo {
    private int statusCode;
    private String serverHeader;
    private String poweredBy;
    private String detectedTechnology;
    private String redirectsTo;
    private Map<String, Boolean> securityHeaders;
}
