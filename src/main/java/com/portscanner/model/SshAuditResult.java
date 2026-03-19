package com.portscanner.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SshAuditResult {
    private String serverVersion;
    private List<String> kexAlgorithms;
    private List<String> hostKeyAlgorithms;
    private List<String> encryptionAlgorithms;
    private List<String> macAlgorithms;
    private List<String> weakAlgorithms;
    private List<String> recommendations;
}
