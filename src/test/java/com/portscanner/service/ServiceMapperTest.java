package com.portscanner.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

class ServiceMapperTest {

    private ServiceMapper mapper;

    @BeforeEach
    void setUp() {
        mapper = new ServiceMapper();
    }

    @ParameterizedTest(name = "port {0} maps to {1}")
    @CsvSource({
            "22, SSH",
            "80, HTTP",
            "443, HTTPS",
            "21, FTP",
            "3306, MySQL",
            "3389, RDP",
            "5432, PostgreSQL",
            "6379, Redis",
            "27017, MongoDB"
    })
    void getService_knownPort_returnsCorrectName(int port, String expected) {
        assertEquals(expected, mapper.getService(port));
    }

    @Test
    void getService_unknownPort_returnsUnknown() {
        assertEquals("Unknown", mapper.getService(19999));
        assertEquals("Unknown", mapper.getService(29999));
    }

    @Test
    void isKnown_knownPort_returnsTrue() {
        assertTrue(mapper.isKnown(22));
        assertTrue(mapper.isKnown(80));
        assertTrue(mapper.isKnown(443));
    }

    @Test
    void isKnown_unknownPort_returnsFalse() {
        assertFalse(mapper.isKnown(19999));
        assertFalse(mapper.isKnown(29999));
    }
}
