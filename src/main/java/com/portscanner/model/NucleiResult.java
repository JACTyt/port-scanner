package com.portscanner.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class NucleiResult {
    private String templateId;
    private String name;
    private String severity;   // info, low, medium, high, critical
    private boolean matched;
    private String matchedAt;  // URL or address that matched
    private List<String> extractedValues;
}
