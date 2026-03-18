package com.portscanner.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Response from the Shodan InternetDB free API ({@code https://internetdb.shodan.io/{ip}}).
 * No API key required.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ShodanResult {
    private String ip;
    private List<Integer> ports;
    private List<String> cpes;
    private List<String> hostnames;
    private List<String> tags;
    private List<String> vulns;
}
