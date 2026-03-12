package com.portscanner.scanner.probe;

import java.nio.charset.StandardCharsets;

public class MemcachedProbe implements Probe {

    private static final byte[] PAYLOAD = "version\r\n".getBytes(StandardCharsets.UTF_8);

    @Override
    public byte[] getPayload() {
        return PAYLOAD;
    }

    @Override
    public String getName() {
        return "Memcached";
    }
}
