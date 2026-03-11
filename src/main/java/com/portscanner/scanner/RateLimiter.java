package com.portscanner.scanner;

/**
 * Simple token-bucket rate limiter for controlling scan packet rate.
 * Thread-safe: multiple scanner threads can call acquire() concurrently.
 */
public class RateLimiter {

    private final long intervalNanos;
    private long nextAllowedTime;

    public RateLimiter(int packetsPerSecond) {
        this.intervalNanos = 1_000_000_000L / packetsPerSecond;
        this.nextAllowedTime = System.nanoTime();
    }

    /** Block until the next token is available, then consume it. */
    public synchronized void acquire() {
        long now = System.nanoTime();
        if (now < nextAllowedTime) {
            long sleepNanos = nextAllowedTime - now;
            try {
                Thread.sleep(sleepNanos / 1_000_000, (int) (sleepNanos % 1_000_000));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        nextAllowedTime = Math.max(nextAllowedTime, System.nanoTime()) + intervalNanos;
    }
}
