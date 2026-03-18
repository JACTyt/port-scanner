package com.portscanner.cli;

import com.portscanner.config.ProfileLoader;
import com.portscanner.db.ScanHistoryDao;
import com.portscanner.model.ScanReport;
import com.portscanner.report.DiffReport;
import com.portscanner.report.ReportDiffer;
import org.jline.reader.Completer;
import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.UserInterruptException;
import org.jline.reader.impl.completer.AggregateCompleter;
import org.jline.reader.impl.completer.ArgumentCompleter;
import org.jline.reader.impl.completer.NullCompleter;
import org.jline.reader.impl.completer.StringsCompleter;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;

/**
 * Interactive REPL mode: {@code portscanner shell}.
 *
 * <p>Supported commands:
 * <pre>
 *   scan &lt;host&gt; [--ports &lt;range&gt;] [--banner] [--tls] [--os] ...
 *   history --host &lt;host&gt; [--last N] [--diff]
 *   diff &lt;file1.json&gt; &lt;file2.json&gt;
 *   set timeout|threads|ports &lt;value&gt;
 *   profiles
 *   help
 *   exit | quit
 * </pre>
 *
 * <p>JLine3 provides readline-style editing, persistent history at
 * {@code ~/.portscanner/repl_history}, and tab-completion.
 */
@Command(
        name = "shell",
        mixinStandardHelpOptions = true,
        description = "Start an interactive REPL session (type 'help' for commands)"
)
public class ReplCommand implements Callable<Integer> {

    private static final Logger log = LoggerFactory.getLogger(ReplCommand.class);

    // Mutable session-level defaults (overridden by 'set' command)
    private String sessionTimeout = "200";
    private String sessionThreads = "100";
    private String sessionPorts   = "1-1024";

    @Override
    public Integer call() {
        try {
            Terminal terminal = TerminalBuilder.builder().system(true).dumb(true).build();
            LineReader reader = LineReaderBuilder.builder()
                    .terminal(terminal)
                    .completer(buildCompleter())
                    .variable(LineReader.HISTORY_FILE,
                            Path.of(System.getProperty("user.home"), ".portscanner", "repl_history"))
                    .variable(LineReader.HISTORY_SIZE, 500)
                    .build();

            printBanner(terminal);

            while (true) {
                String line;
                try {
                    line = reader.readLine("portscanner> ").trim();
                } catch (UserInterruptException e) {
                    terminal.writer().println("(Ctrl+C — type 'exit' to quit)");
                    terminal.writer().flush();
                    continue;
                } catch (EndOfFileException e) {
                    break; // Ctrl+D
                }

                if (line.isBlank()) continue;
                if (line.equalsIgnoreCase("exit") || line.equalsIgnoreCase("quit")) break;

                dispatch(line, terminal);
            }

            terminal.writer().println("Bye.");
            terminal.writer().flush();
            terminal.close();
        } catch (Exception e) {
            System.err.println("REPL error: " + e.getMessage());
            log.debug("REPL error", e);
            return 1;
        }
        return 0;
    }

    // ── Command dispatcher ────────────────────────────────────────────────────

    private void dispatch(String line, Terminal terminal) {
        String[] tokens = tokenize(line);
        if (tokens.length == 0) return;
        String cmd = tokens[0].toLowerCase();

        switch (cmd) {
            case "scan"     -> runScan(tokens, terminal);
            case "history"  -> runHistory(tokens, terminal);
            case "diff"     -> runDiff(tokens, terminal);
            case "set"      -> runSet(tokens, terminal);
            case "profiles" -> runProfiles(terminal);
            case "help"     -> printHelp(terminal);
            default -> terminal.writer().println("Unknown command: '" + cmd + "'. Type 'help' for available commands.");
        }
        terminal.writer().flush();
    }

    // ── scan <host> [opts...] ─────────────────────────────────────────────────

    private void runScan(String[] tokens, Terminal terminal) {
        if (tokens.length < 2) {
            terminal.writer().println("Usage: scan <host> [--ports <range>] [--banner] [--tls] [--os] [--timeout <ms>] [--threads <n>]");
            return;
        }
        // Build args list: inject session defaults for unset options
        List<String> args = new ArrayList<>();
        args.add("--host");
        args.add(tokens[1]);

        // Remaining tokens from the scan command
        List<String> rest = new ArrayList<>(Arrays.asList(tokens).subList(2, tokens.length));

        // Inject session defaults if not already provided
        if (rest.stream().noneMatch(t -> t.startsWith("--ports") || t.startsWith("-p"))) {
            args.add("--ports"); args.add(sessionPorts);
        }
        if (rest.stream().noneMatch(t -> t.startsWith("--timeout") || t.startsWith("-t"))) {
            args.add("--timeout"); args.add(sessionTimeout);
        }
        if (rest.stream().noneMatch(t -> t.startsWith("--threads"))) {
            args.add("--threads"); args.add(sessionThreads);
        }
        // Skip discovery for REPL convenience (avoids long wait on closed hosts)
        args.add("--skip-discovery");

        args.addAll(rest);

        terminal.writer().printf("Scanning %s ...%n", tokens[1]);
        terminal.writer().flush();

        int exit = new CommandLine(new ScanCommand()).execute(args.toArray(new String[0]));
        if (exit != 0) terminal.writer().println("(scan exited with code " + exit + ")");
    }

    // ── history [--host <h>] [--last N] [--diff] ──────────────────────────────

    private void runHistory(String[] tokens, Terminal terminal) {
        // Delegate to HistoryCommand via picocli
        String[] args = Arrays.copyOfRange(tokens, 1, tokens.length);
        if (args.length == 0) {
            terminal.writer().println("Usage: history --host <host> [--last N] [--diff]");
            return;
        }
        new CommandLine(new HistoryCommand()).execute(args);
    }

    // ── diff <file1> <file2> ──────────────────────────────────────────────────

    private void runDiff(String[] tokens, Terminal terminal) {
        if (tokens.length < 3) {
            terminal.writer().println("Usage: diff <file1.json> <file2.json>");
            return;
        }
        try {
            ReportDiffer differ = new ReportDiffer();
            ScanReport r1 = differ.loadReport(Path.of(tokens[1]));
            ScanReport r2 = differ.loadReport(Path.of(tokens[2]));
            DiffReport diff = differ.diff(r1, r2, tokens[1], tokens[2]);
            differ.printDiff(diff);
        } catch (Exception e) {
            terminal.writer().println("Error: " + e.getMessage());
        }
    }

    // ── set <key> <value> ─────────────────────────────────────────────────────

    private void runSet(String[] tokens, Terminal terminal) {
        if (tokens.length < 3) {
            terminal.writer().println("Usage: set timeout|threads|ports <value>");
            terminal.writer().printf("Current: timeout=%s  threads=%s  ports=%s%n",
                    sessionTimeout, sessionThreads, sessionPorts);
            return;
        }
        switch (tokens[1].toLowerCase()) {
            case "timeout" -> { sessionTimeout = tokens[2]; terminal.writer().println("timeout = " + sessionTimeout); }
            case "threads" -> { sessionThreads = tokens[2]; terminal.writer().println("threads = " + sessionThreads); }
            case "ports"   -> { sessionPorts   = tokens[2]; terminal.writer().println("ports = " + sessionPorts); }
            default        -> terminal.writer().println("Unknown setting '" + tokens[1] + "'. Use: timeout, threads, ports");
        }
    }

    // ── profiles ──────────────────────────────────────────────────────────────

    private void runProfiles(Terminal terminal) {
        List<String> names = ProfileLoader.listAll();
        terminal.writer().println("Available profiles (use with --profile in scan command):");
        names.forEach(n -> terminal.writer().println("  " + n));
    }

    // ── help ──────────────────────────────────────────────────────────────────

    private void printHelp(Terminal terminal) {
        terminal.writer().println("""
                Commands:
                  scan <host> [options]         Run a port scan. Accepts the same flags as the CLI.
                    --ports <range|list>         e.g. 1-1024 or 80,443,8080  (default: session port range)
                    --banner                     Grab service banners
                    --tls                        Inspect TLS certificates
                    --http                       Analyse HTTP headers
                    --os                         OS fingerprinting
                    --profile <name>             Apply a scan profile
                    --timeout <ms>               Per-port timeout (default: session timeout)
                    --threads <n>                Concurrency (default: session threads)
                    --save-history               Persist to history DB

                  history --host <host>          Show scan history for a host
                    --last N                     Show last N scans (default: 10)
                    --diff                       Show port changes between scans

                  diff <file1.json> <file2.json> Compare two JSON scan reports

                  set timeout <ms>               Set default timeout for this session
                  set threads <n>                Set default thread count for this session
                  set ports <range>              Set default port range for this session

                  profiles                       List available scan profiles

                  help                           Show this message
                  exit | quit                    Exit the REPL""");
    }

    // ── Banner ────────────────────────────────────────────────────────────────

    private static void printBanner(Terminal terminal) {
        terminal.writer().println("""
                ┌─────────────────────────────────────────┐
                │  port-scanner  interactive shell  v2.0   │
                │  Type 'help' for commands, 'exit' to quit│
                └─────────────────────────────────────────┘""");
        terminal.writer().flush();
    }

    // ── Tab completion ────────────────────────────────────────────────────────

    private static Completer buildCompleter() {
        // command-level completions
        return new AggregateCompleter(
                new ArgumentCompleter(new StringsCompleter("scan"),     NullCompleter.INSTANCE),
                new ArgumentCompleter(new StringsCompleter("history"),  NullCompleter.INSTANCE),
                new ArgumentCompleter(new StringsCompleter("diff"),     NullCompleter.INSTANCE),
                new ArgumentCompleter(new StringsCompleter("set"),
                        new StringsCompleter("timeout", "threads", "ports"), NullCompleter.INSTANCE),
                new ArgumentCompleter(new StringsCompleter("profiles"), NullCompleter.INSTANCE),
                new ArgumentCompleter(new StringsCompleter("help"),     NullCompleter.INSTANCE),
                new ArgumentCompleter(new StringsCompleter("exit", "quit"), NullCompleter.INSTANCE)
        );
    }

    // ── Tokenizer (handles quoted strings) ───────────────────────────────────

    static String[] tokenize(String line) {
        List<String> tokens = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inQuote = false;
        char quoteChar = '"';

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (inQuote) {
                if (c == quoteChar) { inQuote = false; }
                else { cur.append(c); }
            } else if (c == '"' || c == '\'') {
                inQuote = true; quoteChar = c;
            } else if (c == ' ' || c == '\t') {
                if (!cur.isEmpty()) { tokens.add(cur.toString()); cur.setLength(0); }
            } else {
                cur.append(c);
            }
        }
        if (!cur.isEmpty()) tokens.add(cur.toString());
        return tokens.toArray(new String[0]);
    }
}
