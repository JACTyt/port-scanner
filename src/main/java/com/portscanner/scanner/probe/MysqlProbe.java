package com.portscanner.scanner.probe;

public class MysqlProbe implements Probe {

    @Override
    public byte[] getPayload() {
        // MySQL server sends handshake on connect — we passively read
        return null;
    }

    @Override
    public String getName() {
        return "MySQL";
    }
}
