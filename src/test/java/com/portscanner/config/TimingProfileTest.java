package com.portscanner.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for TimingProfile.fromString() and ScanTimingConfig.forProfile().
 */
class TimingProfileTest {

    // ── fromString: integer aliases ───────────────────────────────────────

    @ParameterizedTest
    @CsvSource({"0,PARANOID", "1,SNEAKY", "2,POLITE", "3,NORMAL", "4,AGGRESSIVE", "5,INSANE"})
    void integerAliasesMapCorrectly(String alias, String expected) {
        assertEquals(TimingProfile.valueOf(expected), TimingProfile.fromString(alias));
    }

    // ── fromString: named strings ─────────────────────────────────────────

    @Test
    void namedProfileCaseInsensitive() {
        assertEquals(TimingProfile.INSANE, TimingProfile.fromString("insane"));
        assertEquals(TimingProfile.NORMAL, TimingProfile.fromString("Normal"));
        assertEquals(TimingProfile.PARANOID, TimingProfile.fromString("PARANOID"));
    }

    @Test
    void nullReturnsNormal() {
        assertEquals(TimingProfile.NORMAL, TimingProfile.fromString(null));
    }

    @Test
    void unknownValueThrows() {
        assertThrows(IllegalArgumentException.class, () -> TimingProfile.fromString("TURBO"));
    }

    // ── ScanTimingConfig.forProfile: values ───────────────────────────────

    @Test
    void paranoidProfile() {
        ScanTimingConfig c = ScanTimingConfig.forProfile(TimingProfile.PARANOID);
        assertEquals(300_000, c.connectTimeoutMs());
        assertEquals(300_000, c.scanDelayMs());
        assertEquals(1,       c.maxParallelism());
        assertEquals(10,      c.maxRetries());
    }

    @Test
    void sneakyProfile() {
        ScanTimingConfig c = ScanTimingConfig.forProfile(TimingProfile.SNEAKY);
        assertEquals(15_000, c.connectTimeoutMs());
        assertEquals(15_000, c.scanDelayMs());
        assertEquals(1,      c.maxParallelism());
    }

    @Test
    void politeProfile() {
        ScanTimingConfig c = ScanTimingConfig.forProfile(TimingProfile.POLITE);
        assertEquals(10_000, c.connectTimeoutMs());
        assertEquals(400,    c.scanDelayMs());
        assertEquals(1,      c.maxParallelism());
    }

    @Test
    void normalProfile() {
        ScanTimingConfig c = ScanTimingConfig.forProfile(TimingProfile.NORMAL);
        assertEquals(1_000, c.connectTimeoutMs());
        assertEquals(0,     c.scanDelayMs());
        assertEquals(100,   c.maxParallelism());
        assertEquals(6,     c.maxRetries());
    }

    @Test
    void aggressiveProfile() {
        ScanTimingConfig c = ScanTimingConfig.forProfile(TimingProfile.AGGRESSIVE);
        assertEquals(1_250, c.connectTimeoutMs());
        assertEquals(0,     c.scanDelayMs());
        assertEquals(200,   c.maxParallelism());
    }

    @Test
    void insaneProfile() {
        ScanTimingConfig c = ScanTimingConfig.forProfile(TimingProfile.INSANE);
        assertEquals(300, c.connectTimeoutMs());
        assertEquals(0,   c.scanDelayMs());
        assertEquals(500, c.maxParallelism());
        assertEquals(2,   c.maxRetries());
    }

    @Test
    void allProfilesCovered() {
        // Ensure forProfile() handles every enum value without throwing
        for (TimingProfile p : TimingProfile.values()) {
            assertDoesNotThrow(() -> ScanTimingConfig.forProfile(p),
                    "forProfile() threw for " + p);
        }
    }
}
