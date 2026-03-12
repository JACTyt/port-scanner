package com.portscanner.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AsnInfo {
    private String asn;
    private String prefix;
    private String country;
    private String registry;
    private String name;
}
