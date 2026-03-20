package com.portscanner.api.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class WorkItem {
    private String workId;
    private String target;    // host or CIDR
    private String ports;     // e.g. "1-1024"
    private int    timeout;
    private int    threads;
    private boolean banner;
}
