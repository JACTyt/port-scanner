package com.portscanner.scanner;

import com.portscanner.model.SubdomainResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class DnsBruteForceTest {

    @Test
    void loadWordlist_bundled_resource_returns_nonempty_list() throws Exception {
        DnsBruteForcer bruteForcer = new DnsBruteForcer("example.com", 2000);
        List<String> words = bruteForcer.loadWordlist(null);
        assertFalse(words.isEmpty(), "Bundled wordlist should not be empty");
        assertTrue(words.contains("www"), "Bundled wordlist should contain 'www'");
    }

    @Test
    void loadWordlist_custom_file_overrides_bundled(@TempDir Path tmp) throws Exception {
        Path wordlist = tmp.resolve("words.txt");
        Files.writeString(wordlist, "foo\nbar\nbaz\n");
        DnsBruteForcer bruteForcer = new DnsBruteForcer("example.com", 2000);
        List<String> words = bruteForcer.loadWordlist(wordlist);
        assertEquals(List.of("foo", "bar", "baz"), words);
    }

    @Test
    void loadWordlist_custom_file_strips_comments_and_blanks(@TempDir Path tmp) throws Exception {
        Path wordlist = tmp.resolve("words.txt");
        Files.writeString(wordlist, "# comment\nwww\n\nmail\n");
        DnsBruteForcer bruteForcer = new DnsBruteForcer("example.com", 2000);
        List<String> words = bruteForcer.loadWordlist(wordlist);
        assertEquals(List.of("www", "mail"), words);
    }

    @Test
    void bruteForce_empty_wordlist_returns_empty() throws Exception {
        DnsBruteForcer bruteForcer = new DnsBruteForcer("example.com", 2000);
        List<SubdomainResult> results = bruteForcer.bruteForce(List.of());
        assertTrue(results.isEmpty());
    }

    @Test
    void bruteForce_nonexistent_tld_returns_empty() throws Exception {
        // .invalid is a reserved TLD that MUST NOT resolve
        DnsBruteForcer bruteForcer = new DnsBruteForcer("thisisnotarealdomain12345xyz.invalid", 2000);
        List<SubdomainResult> results = bruteForcer.bruteForce(List.of("www", "mail"));
        assertTrue(results.isEmpty(), "No subdomains should resolve for a .invalid domain");
    }

    @Test
    void subdomainResult_builder_sets_all_fields() {
        SubdomainResult r = SubdomainResult.builder()
                .subdomain("www.example.com")
                .addresses(List.of("93.184.216.34"))
                .cname("example.com.")
                .build();
        assertEquals("www.example.com", r.getSubdomain());
        assertEquals(List.of("93.184.216.34"), r.getAddresses());
        assertEquals("example.com.", r.getCname());
    }

    @Test
    void resolve_uses_mock_resolver_and_returns_address() throws Exception {
        // Create a mock Resolver that returns a fake A record
        Resolver mockResolver = mock(Resolver.class);
        Message response = new Message();
        response.getHeader().setFlag(Flags.QR);
        response.getHeader().setFlag(Flags.AA);
        Name name = Name.fromString("www.example.com.");
        org.xbill.DNS.Record question = org.xbill.DNS.Record.newRecord(name, Type.A, DClass.IN);
        response.addRecord(question, Section.QUESTION);
        ARecord answer = new ARecord(name, DClass.IN, 300,
                java.net.InetAddress.getByName("1.2.3.4"));
        response.addRecord(answer, Section.ANSWER);
        when(mockResolver.send(any(Message.class))).thenReturn(response);

        DnsBruteForcer bruteForcer = new DnsBruteForcer("example.com", 1000, mockResolver);
        Optional<SubdomainResult> result = bruteForcer.resolve("www.example.com");
        assertTrue(result.isPresent());
        assertEquals("www.example.com", result.get().getSubdomain());
        assertTrue(result.get().getAddresses().contains("1.2.3.4"));
    }
}
