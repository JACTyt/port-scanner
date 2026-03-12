package com.portscanner.config;

/**
 * Bundles timeout, delay, and parallelism settings for a scan.
 * Created from a {@link TimingProfile} via {@link #forProfile(TimingProfile)}.
 */
public record ScanTimingConfig(
        long connectTimeoutMs,
        int  maxRetries,
        long scanDelayMs,
        int  maxParallelism
) {
    /**
     * Returns the recommended timing configuration for the given profile.
     *
     * <pre>
     * Profile    | timeout    | retries | delay      | parallelism
     * -----------|------------|---------|------------|------------
     * PARANOID   | 300,000 ms | 10      | 300,000 ms | 1
     * SNEAKY     |  15,000 ms | 10      |  15,000 ms | 1
     * POLITE     |  10,000 ms | 10      |     400 ms | 1
     * NORMAL     |   1,000 ms |  6      |       0 ms | 100
     * AGGRESSIVE |   1,250 ms |  6      |       0 ms | 200
     * INSANE     |     300 ms |  2      |       0 ms | 500
     * </pre>
     */
    public static ScanTimingConfig forProfile(TimingProfile profile) {
        return switch (profile) {
            case PARANOID   -> new ScanTimingConfig(300_000, 10, 300_000, 1);
            case SNEAKY     -> new ScanTimingConfig(15_000,  10,  15_000, 1);
            case POLITE     -> new ScanTimingConfig(10_000,  10,     400, 1);
            case NORMAL     -> new ScanTimingConfig(1_000,    6,       0, 100);
            case AGGRESSIVE -> new ScanTimingConfig(1_250,    6,       0, 200);
            case INSANE     -> new ScanTimingConfig(300,      2,       0, 500);
        };
    }
}
