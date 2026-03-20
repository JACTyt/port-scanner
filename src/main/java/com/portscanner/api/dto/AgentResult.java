package com.portscanner.api.dto;

import com.portscanner.model.ScanReport;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class AgentResult {
    private String workId;
    private String agentId;
    private ScanReport report;
    private String error;   // null on success
}
