package com.portscanner.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class CtLogEntry {
    @JsonProperty("name_value")
    private String nameValue;
    @JsonProperty("not_before")
    private String notBefore;
    @JsonProperty("not_after")
    private String notAfter;
    @JsonProperty("issuer_ca_id")
    private Long issuerCaId;
}
