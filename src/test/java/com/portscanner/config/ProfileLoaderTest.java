package com.portscanner.config;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class ProfileLoaderTest {

    @Test
    void quick_profile_has_top_ports_and_t4_timing() {
        ScanProfile p = ProfileLoader.load("quick").orElseThrow();
        assertEquals(100, p.getTopPorts());
        assertEquals("T4", p.getTiming());
    }

    @Test
    void web_profile_enables_banner_tls_http() {
        ScanProfile p = ProfileLoader.load("web").orElseThrow();
        assertTrue(p.getBanner());
        assertTrue(p.getTls());
        assertTrue(p.getHttp());
        assertEquals("80,443,8080,8443,3000,5000", p.getPorts());
    }

    @Test
    void db_profile_targets_database_ports_with_probes() {
        ScanProfile p = ProfileLoader.load("db").orElseThrow();
        assertTrue(p.getBanner());
        assertTrue(p.getProbes());
        assertNotNull(p.getPorts());
        assertTrue(p.getPorts().contains("3306"), "Expected MySQL port in db profile");
    }

    @Test
    void full_profile_scans_all_ports_with_geo() {
        ScanProfile p = ProfileLoader.load("full").orElseThrow();
        assertEquals("1-65535", p.getPorts());
        assertTrue(p.getGeolocate());
        assertTrue(p.getBanner());
        assertTrue(p.getTls());
        assertTrue(p.getHttp());
    }

    @Test
    void stealth_profile_has_low_rate_and_t1_timing() {
        ScanProfile p = ProfileLoader.load("stealth").orElseThrow();
        assertEquals("T1", p.getTiming());
        assertEquals(10, p.getRate());
        assertEquals(100, p.getTopPorts());
    }

    @Test
    void unknown_profile_returns_empty() {
        Optional<ScanProfile> result = ProfileLoader.load("nosuchprofile_xyz");
        assertFalse(result.isPresent());
    }

    @Test
    void null_name_returns_empty() {
        assertFalse(ProfileLoader.load(null).isPresent());
    }

    @Test
    void blank_name_returns_empty() {
        assertFalse(ProfileLoader.load("   ").isPresent());
    }

    @Test
    void profile_lookup_is_case_insensitive() {
        assertTrue(ProfileLoader.load("QUICK").isPresent());
        assertTrue(ProfileLoader.load("Web").isPresent());
        assertTrue(ProfileLoader.load("DB").isPresent());
    }

    @Test
    void listAll_includes_all_builtin_profiles() {
        List<String> names = ProfileLoader.listAll();
        assertTrue(names.contains("quick"));
        assertTrue(names.contains("web"));
        assertTrue(names.contains("db"));
        assertTrue(names.contains("full"));
        assertTrue(names.contains("stealth"));
    }
}
