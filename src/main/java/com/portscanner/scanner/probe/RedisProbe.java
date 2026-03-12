package com.portscanner.scanner.probe;

import java.nio.charset.StandardCharsets;

public class RedisProbe implements Probe {

    private static final byte[] PAYLOAD = "*1\r\n$4\r\nPING\r\n".getBytes(StandardCharsets.UTF_8);

    @Override
    public byte[] getPayload() {
        return PAYLOAD;
    }

    @Override
    public String getName() {
        return "Redis";
    }
}
