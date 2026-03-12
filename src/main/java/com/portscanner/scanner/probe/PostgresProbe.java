package com.portscanner.scanner.probe;

public class PostgresProbe implements Probe {

    // SSLRequest message: \x00\x00\x00\x08\x04\xD2\x16\x2F
    private static final byte[] PAYLOAD = new byte[]{0x00, 0x00, 0x00, 0x08, 0x04, (byte) 0xD2, 0x16, 0x2F};

    @Override
    public byte[] getPayload() {
        return PAYLOAD;
    }

    @Override
    public String getName() {
        return "PostgreSQL";
    }
}
