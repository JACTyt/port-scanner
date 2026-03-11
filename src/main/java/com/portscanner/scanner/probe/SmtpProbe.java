package com.portscanner.scanner.probe;

public class SmtpProbe implements Probe {

    @Override
    public byte[] getPayload() {
        return null; // SMTP sends banner automatically
    }

    @Override
    public String getName() {
        return "SMTP";
    }
}
