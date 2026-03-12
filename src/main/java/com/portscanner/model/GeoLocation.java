package com.portscanner.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GeoLocation {
    private String ip;
    private String hostname;
    private String city;
    private String region;
    private String country;
    private String org;
    private String timezone;
}
