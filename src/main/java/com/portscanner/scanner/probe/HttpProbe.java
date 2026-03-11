package com.portscanner.scanner.probe;

import java.nio.charset.StandardCharsets;

public class HttpProbe implements Probe {

    private static final byte[] PAYLOAD = "GET / HTTP/1.0\r\n\r\n".getBytes(StandardCharsets.UTF_8);

    @Override
    public byte[] getPayload() {
        return PAYLOAD;
    }

    @Override
    public String getName() {
        return "HTTP";
    }
}
