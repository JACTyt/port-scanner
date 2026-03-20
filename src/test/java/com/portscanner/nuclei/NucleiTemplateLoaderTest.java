package com.portscanner.nuclei;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class NucleiTemplateLoaderTest {

    private Path testTemplateDir() throws Exception {
        URI uri = getClass().getClassLoader()
                .getResource("nuclei-test-templates").toURI();
        return Paths.get(uri);
    }

    @Test
    void loadsAllTemplates() throws Exception {
        List<NucleiTemplate> templates = new NucleiTemplateLoader()
                .load(testTemplateDir(), null);
        assertEquals(3, templates.size());
    }

    @Test
    void filtersBySeverity() throws Exception {
        List<NucleiTemplate> templates = new NucleiTemplateLoader()
                .load(testTemplateDir(), List.of("high"));
        assertEquals(1, templates.size());
        assertEquals("test-regex-match", templates.get(0).getId());
    }

    @Test
    void templateHasExpectedFields() throws Exception {
        List<NucleiTemplate> templates = new NucleiTemplateLoader()
                .load(testTemplateDir(), List.of("info"));
        NucleiTemplate t = templates.get(0);
        assertEquals("info", t.getInfo().getSeverity());
        assertEquals("status", t.getHttp().get(0).getMatchers().get(0).getType());
    }
}
