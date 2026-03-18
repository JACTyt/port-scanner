package com.portscanner.api.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.portscanner.model.ScanReport;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScanResponse {
    private String id;
    private String status; // PENDING, RUNNING, DONE, FAILED, CANCELLED
    private String host;
    private String submittedAt;
    private String completedAt;
    private String error;
    private ScanReport result;
}
