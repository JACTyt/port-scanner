package com.portscanner.scanner.probe;

public class GenericProbe implements Probe {

    @Override
    public byte[] getPayload() {
        return null; // Passive read only
    }

    @Override
    public String getName() {
        return "Generic";
    }
}
