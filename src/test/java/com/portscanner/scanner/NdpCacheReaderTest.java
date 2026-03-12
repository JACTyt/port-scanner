package com.portscanner.scanner;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class NdpCacheReaderTest {

    @Test
    void readNeighbors_does_not_throw_when_command_unavailable() {
        // On any OS, readNeighbors() must not throw — it returns empty on failure
        NdpCacheReader reader = new NdpCacheReader();
        assertDoesNotThrow(reader::readNeighbors);
    }

    @Test
    void readNeighbors_returns_list_instance() {
        NdpCacheReader reader = new NdpCacheReader();
        List<NdpCacheReader.NeighborEntry> result = reader.readNeighbors();
        assertNotNull(result);
    }

    @Test
    void neighborEntry_record_holds_fields() {
        NdpCacheReader.NeighborEntry entry =
                new NdpCacheReader.NeighborEntry("fe80::1", "aa:bb:cc:dd:ee:ff", "REACHABLE");
        assertEquals("fe80::1", entry.ip());
        assertEquals("aa:bb:cc:dd:ee:ff", entry.mac());
        assertEquals("REACHABLE", entry.state());
    }
}
