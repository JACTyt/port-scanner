package com.portscanner.scanner;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TopPortsTest {

    @Test
    void get10ReturnsTenEntries() {
        int[] ports = TopPorts.get(10);
        assertEquals(10, ports.length);
    }

    @Test
    void port80IsAlwaysFirst() {
        int[] ports = TopPorts.get(100);
        assertEquals(80, ports[0]);
    }

    @Test
    void get0ReturnsEmptyArray() {
        int[] ports = TopPorts.get(0);
        assertEquals(0, ports.length);
    }

    @Test
    void get1001CapsAt1000() {
        int[] ports = TopPorts.get(1001);
        assertEquals(1000, ports.length);
    }

    @Test
    void getNegativeReturnsEmptyArray() {
        int[] ports = TopPorts.get(-5);
        assertEquals(0, ports.length);
    }

    @Test
    void get1000ReturnsExactly1000() {
        int[] ports = TopPorts.get(1000);
        assertEquals(1000, ports.length);
    }
}
