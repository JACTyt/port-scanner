package com.portscanner.scanner.probe;

public class SshProbe implements Probe {

    @Override
    public byte[] getPayload() {
        return null; // SSH sends banner automatically
    }

    @Override
    public String getName() {
        return "SSH";
    }
}
