package com.portscanner.scanner.probe;

public interface Probe {
    /** Bytes to send to the port to elicit a response. Null means just read passively. */
    byte[] getPayload();
    /** Display name of this probe. */
    String getName();
}
