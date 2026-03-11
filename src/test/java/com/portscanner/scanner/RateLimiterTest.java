package com.portscanner.scanner;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RateLimiterTest {

    @Test
    void acquire_does_not_throw() {
        RateLimiter limiter = new RateLimiter(1000);
        assertDoesNotThrow(limiter::acquire);
    }

    @Test
    void first_acquire_is_immediate() {
        RateLimiter limiter = new RateLimiter(1); // 1 pps = 1s interval, but first is free
        long start = System.currentTimeMillis();
        limiter.acquire();
        long elapsed = System.currentTimeMillis() - start;
        assertTrue(elapsed < 200, "First acquire should be immediate, took " + elapsed + "ms");
    }

    @Test
    void high_rate_allows_rapid_acquisition() {
        RateLimiter limiter = new RateLimiter(10_000); // 10k pps = 100µs interval
        long start = System.currentTimeMillis();
        for (int i = 0; i < 10; i++) {
            limiter.acquire();
        }
        long elapsed = System.currentTimeMillis() - start;
        assertTrue(elapsed < 500, "Expected <500ms for 10 acquires at 10k pps, got " + elapsed + "ms");
    }

    @Test
    void rate_is_approximately_respected() {
        // 100 pps = 10ms per token. Acquire 5 tokens after warm-up; expect ~40ms minimum.
        RateLimiter limiter = new RateLimiter(100);
        limiter.acquire(); // first call is immediate
        long start = System.currentTimeMillis();
        for (int i = 0; i < 4; i++) {
            limiter.acquire();
        }
        long elapsed = System.currentTimeMillis() - start;
        assertTrue(elapsed >= 30, "Expected >=30ms for 4 acquires at 100 pps, got " + elapsed + "ms");
    }

    @Test
    void is_thread_safe() throws InterruptedException {
        RateLimiter limiter = new RateLimiter(10_000);
        boolean[] threw = {false};
        Thread[] threads = new Thread[10];
        for (int i = 0; i < threads.length; i++) {
            threads[i] = new Thread(() -> {
                try {
                    limiter.acquire();
                } catch (Exception e) {
                    threw[0] = true;
                }
            });
        }
        for (Thread t : threads) t.start();
        for (Thread t : threads) t.join(3000);
        assertFalse(threw[0], "RateLimiter threw under concurrent access");
    }
}
