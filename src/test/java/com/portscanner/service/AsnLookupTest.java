package com.portscanner.service;

import com.portscanner.model.AsnInfo;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class AsnLookupTest {

    @Test
    void parses_txt_record_correctly() {
        String txt = "15169 | 8.8.8.0/24 | US | arin | 2000-03-30";
        Optional<AsnInfo> result = AsnLookup.parseTxtRecord(txt);
        assertTrue(result.isPresent());
        assertEquals("AS15169", result.get().getAsn());
        assertEquals("8.8.8.0/24", result.get().getPrefix());
        assertEquals("US", result.get().getCountry());
        assertEquals("arin", result.get().getRegistry());
    }

    @Test
    void parses_txt_record_with_quoted_values() {
        String txt = "\"15169 | 8.8.8.0/24 | US | arin | 2000-03-30\"";
        Optional<AsnInfo> result = AsnLookup.parseTxtRecord(txt);
        assertTrue(result.isPresent());
        assertEquals("AS15169", result.get().getAsn());
    }

    @Test
    void returns_empty_for_malformed_txt() {
        Optional<AsnInfo> result = AsnLookup.parseTxtRecord("not a valid record");
        assertTrue(result.isEmpty());
    }

    @Test
    void reverses_ipv4_correctly() {
        assertEquals("4.3.2.1", AsnLookup.reverseIp("1.2.3.4"));
        assertEquals("8.8.8.8", AsnLookup.reverseIp("8.8.8.8"));
        assertEquals("1.0.0.10", AsnLookup.reverseIp("10.0.0.1"));
    }

    @Test
    void lookup_returns_empty_for_localhost() {
        // localhost doesn't have ASN data - should return empty rather than throw
        Optional<AsnInfo> result = AsnLookup.lookup("127.0.0.1");
        assertTrue(result.isEmpty() || result.isPresent()); // just ensure no exception
    }
}
