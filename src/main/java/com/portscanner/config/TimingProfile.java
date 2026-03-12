package com.portscanner.config;

/**
 * nmap-style timing profiles for controlling scan aggressiveness.
 * T0=PARANOID (slowest, IDS-evasive) through T5=INSANE (fastest).
 */
public enum TimingProfile {
    PARANOID,   // T0 — one port at a time, 5-minute timeout, 5-minute delay between ports
    SNEAKY,     // T1 — one port at a time, 15-second timeout, 15-second delay
    POLITE,     // T2 — one port at a time, 10-second timeout, 400ms delay
    NORMAL,     // T3 — 100 parallel, 1-second timeout, no delay (default)
    AGGRESSIVE, // T4 — 200 parallel, 1.25-second timeout, no delay
    INSANE;     // T5 — 500 parallel, 300ms timeout, no delay

    /**
     * Parse a timing profile from either a name ("NORMAL", "INSANE") or
     * an integer alias ("0" through "5").
     */
    public static TimingProfile fromString(String value) {
        if (value == null) return NORMAL;
        return switch (value.trim()) {
            case "0" -> PARANOID;
            case "1" -> SNEAKY;
            case "2" -> POLITE;
            case "3" -> NORMAL;
            case "4" -> AGGRESSIVE;
            case "5" -> INSANE;
            default  -> TimingProfile.valueOf(value.toUpperCase());
        };
    }
}
