package com.portscanner.scanner.probe;

public class FtpProbe implements Probe {

    @Override
    public byte[] getPayload() {
        return null; // FTP sends banner automatically
    }

    @Override
    public String getName() {
        return "FTP";
    }
}
