package com.portscanner.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDate;
import java.util.List;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TlsInfo {
    private String protocol;
    private String cipherSuite;
    private String certSubject;
    private String certIssuer;
    private LocalDate certExpiry;
    private List<String> subjectAltNames;
    private boolean expired;
    private boolean expiresSoon;
    private boolean selfSigned;
    private boolean weakCipher;
    private boolean deprecatedProtocol;
}
