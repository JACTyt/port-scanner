package com.portscanner.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ReplCommandTest {

    // ── tokenize — basic splitting ────────────────────────────────────────────

    @Test
    void tokenize_empty_string_returns_empty_array() {
        assertArrayEquals(new String[0], ReplCommand.tokenize(""));
    }

    @Test
    void tokenize_blank_string_returns_empty_array() {
        assertArrayEquals(new String[0], ReplCommand.tokenize("   "));
    }

    @Test
    void tokenize_single_token() {
        assertArrayEquals(new String[]{"scan"}, ReplCommand.tokenize("scan"));
    }

    @Test
    void tokenize_multiple_tokens() {
        assertArrayEquals(new String[]{"scan", "example.com", "--banner"},
                ReplCommand.tokenize("scan example.com --banner"));
    }

    @Test
    void tokenize_extra_whitespace_collapsed() {
        assertArrayEquals(new String[]{"scan", "host"},
                ReplCommand.tokenize("scan    host"));
    }

    @Test
    void tokenize_leading_trailing_whitespace() {
        assertArrayEquals(new String[]{"scan", "host"},
                ReplCommand.tokenize("  scan host  "));
    }

    // ── tokenize — quoted strings ─────────────────────────────────────────────

    @Test
    void tokenize_double_quoted_string_with_spaces() {
        assertArrayEquals(new String[]{"scan", "my host.com"},
                ReplCommand.tokenize("scan \"my host.com\""));
    }

    @Test
    void tokenize_single_quoted_string_with_spaces() {
        assertArrayEquals(new String[]{"scan", "my host.com"},
                ReplCommand.tokenize("scan 'my host.com'"));
    }

    @Test
    void tokenize_quoted_option_value() {
        assertArrayEquals(new String[]{"set", "ports", "80,443,8080"},
                ReplCommand.tokenize("set ports \"80,443,8080\""));
    }

    @Test
    void tokenize_quotes_stripped_from_token() {
        assertArrayEquals(new String[]{"diff", "file one.json", "file two.json"},
                ReplCommand.tokenize("diff \"file one.json\" \"file two.json\""));
    }

    @Test
    void tokenize_mixed_quoted_and_unquoted() {
        assertArrayEquals(new String[]{"scan", "host", "--ports", "1-1024"},
                ReplCommand.tokenize("scan host --ports \"1-1024\""));
    }

    // ── tokenize — tab character treated as whitespace ────────────────────────

    @Test
    void tokenize_tab_separated_tokens() {
        assertArrayEquals(new String[]{"scan", "host"},
                ReplCommand.tokenize("scan\thost"));
    }
}
