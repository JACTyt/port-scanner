package com.portscanner.api.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class AgentRegistration {
    private String agentId;
    private String label;
    // token is NOT included — authentication is done via the Authorization header only
}
