# TUI & Output Enhancement Findings
## Port Scanner — Interactive Terminal UI Research

**Research Date:** 2026-03-11
**Scope:** Java TUI libraries, progress display, interactive modes, and web dashboard options
**Target:** Picocli-based Java 17+ CLI tool (Maven build)

---

## 1. Lanterna — Full Java TUI Framework

### Overview
Lanterna (https://github.com/mabe02/lanterna) is the most mature Java TUI library, modeled after the C `ncurses` library. It provides a complete widget toolkit for building full-screen terminal applications with panels, windows, text boxes, and real-time updating grids. Version 3.x is the current stable line.

### Maven Dependency
```xml
<dependency>
    <groupId>com.googlecode.lanterna</groupId>
    <artifactId>lanterna</artifactId>
    <version>3.1.2</version>
</dependency>
```

### Key Features
- **Terminal abstraction layer** — works on UNIX, Windows (via native or Cygwin), and within CI (auto-detects dumb terminals).
- **`TextGUI` system** — `MultiWindowTextGUI` with `BasicWindow`, `Panel`, `Label`, `Table`, `ActionListBox`.
- **`AnimatedLabel`** — built-in spinner animation (cycles through character frames at configurable intervals).
- **`Table<String>`** — scrollable table widget; rows can be added from a background thread while the GUI event loop runs on a separate thread.
- **`ProgressBar`** — horizontal progress bar widget with configurable width and value range.
- **Thread model** — GUI runs on its own thread via `gui.getGUIThread().invokeAndWait()`; scan workers post results via `gui.getGUIThread().invokeLater()`.
- **Color/theme system** — `SimpleTheme`, `BlueTheme`, `BigBlockTheme`; supports 256-color terminals and true-color via `SGR` attributes.

### Port Scanner Integration Pattern
```java
// 1. Start Lanterna in a background GUI thread
DefaultTerminalFactory factory = new DefaultTerminalFactory();
Screen screen = factory.createScreen();
screen.startScreen();
MultiWindowTextGUI gui = new MultiWindowTextGUI(screen);

// 2. Build a panel with progress + live results table
Panel panel = new Panel(new LinearLayout(Direction.VERTICAL));
ProgressBar bar = new ProgressBar(0, totalPorts, 40);
Table<String> resultsTable = new Table<>("Port", "State", "Service", "Banner");
panel.addComponent(bar);
panel.addComponent(resultsTable);

// 3. From scan worker thread, post UI updates
gui.getGUIThread().invokeLater(() -> {
    bar.setValue(scannedSoFar);
    resultsTable.getTableModel().addRow(port, status, service, banner);
});
```

### Strengths & Limitations
- Best option for a full-screen "dashboard" mode that replaces the normal scrolling output.
- Adds ~400 KB to the JAR (pure Java, no native libs needed).
- Learning curve is moderate — the widget API is well-documented via Javadoc and GitHub examples.
- Not ideal for simple one-liner progress — overkill if you only want a progress bar.
- Windows support is functional but occasionally has rendering glitches in stock `cmd.exe`; Windows Terminal (WT) works well.

### Reference
- GitHub: https://github.com/mabe02/lanterna
- Tutorial examples in `lanterna/src/test/java/com/googlecode/lanterna/gui2/`

---

## 2. Picocli Built-in Progress & Status Support

### Overview
Picocli 4.6+ ships with `picocli.shell.jline3` integration and a dedicated progress utilities module. It is the most natural fit since the port scanner already uses Picocli for CLI parsing.

### Maven Dependency (extra module)
```xml
<!-- Core picocli already present; add the extras module for progress -->
<dependency>
    <groupId>info.picocli</groupId>
    <artifactId>picocli-shell-jline3</artifactId>
    <version>4.7.6</version>
</dependency>
```
Note: Pure ANSI progress (without JLine3) requires no extra dependency — just use `System.err.print()` with `\r`.

### Built-in Spinner / Status Line Pattern
Picocli itself does not ship a `ProgressBar` class in its core — this is a common misconception. What Picocli provides is:
1. **`@Spec CommandSpec spec`** — access to `spec.commandLine().getErr()` for writing status to stderr without mixing with stdout output.
2. **`ExecutionStrategy` hooks** — `RunLast`, `RunFirst`, `RunAll` for pipeline control.
3. **Integration with JLine3's `TerminalWriter`** — when using `picocli-shell-jline3`, you get access to JLine's progress reporting.

### Practical Picocli Spinner (no extra library)
```java
// In ScanCommand.call(), run a daemon spinner thread writing to stderr
private static final String[] SPINNER = {"|", "/", "-", "\\"};
volatile int scanned = 0, total = 0;

Thread spinner = new Thread(() -> {
    int frame = 0;
    while (!Thread.currentThread().isInterrupted()) {
        int pct = total > 0 ? (scanned * 100 / total) : 0;
        spec.commandLine().getErr().printf("\r  %s Scanning... %d/%d (%d%%)   ",
            SPINNER[frame++ % 4], scanned, total, pct);
        try { Thread.sleep(100); } catch (InterruptedException e) { break; }
    }
    spec.commandLine().getErr().print("\r" + " ".repeat(60) + "\r"); // clear line
}, "spinner");
spinner.setDaemon(true);
spinner.start();
```

### Picocli Interactive Shell
`picocli-shell-jline3` enables building a REPL loop where the user can type scan commands interactively. This is relevant for the "interactive mode" idea (see Section 7).

### Reference
- https://picocli.info/
- https://github.com/remkop/picocli/tree/main/picocli-shell-jline3
- Picocli examples: https://github.com/remkop/picocli/tree/main/picocli-examples

---

## 3. JLine3 — Terminal Handling, Colors, and Progress

### Overview
JLine3 (https://github.com/jline/jline3) is the standard Java library for terminal control, used internally by Groovy REPL, Spring Shell, and Picocli's shell module. It handles terminal raw mode, ANSI escape sequences, line editing, completion, and progress display across all platforms.

### Maven Dependency
```xml
<dependency>
    <groupId>org.jline</groupId>
    <artifactId>jline</artifactId>
    <version>3.26.3</version>
</dependency>
<!-- Or use individual modules: jline-terminal, jline-reader, jline-builtins -->
<dependency>
    <groupId>org.jline</groupId>
    <artifactId>jline-builtins</artifactId>
    <version>3.26.3</version>
</dependency>
```

### Key Features Relevant to Port Scanner

#### Terminal Detection and Colors
```java
Terminal terminal = TerminalBuilder.builder()
    .system(true)         // connect to actual terminal
    .jansi(true)          // use Jansi on Windows for ANSI
    .build();
PrintWriter writer = terminal.writer();
// Use AttributedString for colors
AttributedString colored = new AttributedStringBuilder()
    .style(AttributedStyle.DEFAULT.foreground(AttributedStyle.GREEN))
    .append("OPEN")
    .style(AttributedStyle.DEFAULT)
    .toAttributedString();
colored.println(terminal);
```

#### `jline-builtins` Progress Bar
JLine3's `jline-builtins` module includes a `ProgressBar` class and `Status` line mechanism:
```java
// Status line — a persistent line at the bottom of the terminal
Status status = Status.getStatus(terminal);
status.update(Collections.singletonList(
    new AttributedString("Scanning 192.168.1.1 | 342/1024 ports | 87 open | ETA: 4s")
));
```
The `Status` class hooks into JLine's terminal machinery to keep one line "sticky" at the bottom while normal output scrolls above it — this is exactly the right UX for a port scanner.

#### `LineReader` for Interactive Input
```java
LineReader reader = LineReaderBuilder.builder()
    .terminal(terminal)
    .build();
String line = reader.readLine("Command (pause/resume/quit): ");
```

### JLine3 Advantages Over Raw ANSI
- Correctly handles terminal width (via `terminal.getWidth()`) for progress bar sizing.
- Properly resets cursor and clears lines even when output is piped or redirected.
- Handles Windows via Jansi fallback automatically.
- `Status` line survives concurrent writes from multiple threads when using `terminal.writer()` synchronized.

### Reference
- GitHub: https://github.com/jline/jline3
- JLine3 Wiki: https://github.com/jline/jline3/wiki
- Demo classes: `jline-builtins/src/main/java/org/jline/builtins/`

---

## 4. ANSI Escape Codes — Raw Terminal Control

### Overview
For maximum control with zero dependencies, raw ANSI escape codes via `System.err.print()` work in any POSIX terminal and in Windows Terminal / modern Windows 10+. This is the lightest-weight approach.

### Essential ANSI Sequences for Port Scanner
```java
public final class Ansi {
    // Cursor movement
    public static final String CLEAR_LINE  = "\r\033[2K";      // go to col 0, erase line
    public static final String CURSOR_UP   = "\033[1A";        // move cursor up 1 line
    public static final String HIDE_CURSOR = "\033[?25l";      // hide blinking cursor
    public static final String SHOW_CURSOR = "\033[?25h";      // restore cursor

    // Colors (foreground)
    public static final String RED    = "\033[31m";
    public static final String GREEN  = "\033[32m";
    public static final String YELLOW = "\033[33m";
    public static final String CYAN   = "\033[36m";
    public static final String BOLD   = "\033[1m";
    public static final String RESET  = "\033[0m";

    // 256-color: \033[38;5;<n>m  (foreground)
    public static final String ORANGE = "\033[38;5;208m";
}
```

### Carriage-Return Progress Bar Pattern
The most common pattern for a single-line updating progress display:
```java
void printProgress(int done, int total, int openCount, long elapsedMs) {
    int width = 40;
    int filled = (int)((double)done / total * width);
    String bar = "=".repeat(filled) + ">" + " ".repeat(Math.max(0, width - filled - 1));
    double rate = done / (elapsedMs / 1000.0);
    long etaSec = rate > 0 ? (long)((total - done) / rate) : 0;
    System.err.printf(Ansi.CLEAR_LINE + "[%s] %d/%d | %s%d open%s | %.0f p/s | ETA %ds",
        bar, done, total,
        Ansi.GREEN, openCount, Ansi.RESET,
        rate, etaSec);
}
```

### Multi-Line Real-Time Display (Cursor Movement)
To maintain a 2–3 line "HUD" that updates in place:
```java
// First render: print the lines
System.err.println("Host: 192.168.1.1");
System.err.println("Progress: [=====>    ] 54%");
System.err.println("Open ports: 22, 80, 443");

// On each update: go up N lines, rewrite
System.err.print(Ansi.CURSOR_UP.repeat(3));
System.err.println("Host: 192.168.1.1");
System.err.println("Progress: [=========] 100%");
System.err.println("Open ports: 22, 80, 443, 8080");
```

### Windows Compatibility
Windows 10 build 1511+ supports ANSI in `cmd.exe` and PowerShell, but it must be enabled:
```java
// Enable ANSI on Windows via Jansi (see Section 5)
// Or programmatically:
// ProcessBuilder("cmd", "/c", "").inheritIO(); doesn't help
// Safest: use Jansi or check os.name and skip colors if Windows pre-1511
boolean isWindows = System.getProperty("os.name").toLowerCase().startsWith("win");
```

### Spinner Frames
Common spinner character sets:
```java
// Braille dots (Unicode) — smooth animation
String[] BRAILLE = {"⣾","⣽","⣻","⢿","⡿","⣟","⣯","⣷"};

// Classic ASCII — works everywhere
String[] ASCII   = {"|", "/", "-", "\\"};

// Block fill
String[] BLOCKS  = {"▏","▎","▍","▌","▋","▊","▉","█"};

// Bouncing ball
String[] BOUNCE  = {"⠁","⠂","⠄","⠂"};
```

---

## 5. ASCII Table & Color Libraries

### 5a. Jansi
**Jansi** (https://github.com/fusesource/jansi) is the de-facto standard for ANSI color support on Windows in Java. It wraps native Windows Console API calls so that ANSI sequences work transparently.

```xml
<dependency>
    <groupId>org.fusesource.jansi</groupId>
    <artifactId>jansi</artifactId>
    <version>2.4.1</version>
</dependency>
```
```java
AnsiConsole.systemInstall(); // redirect System.out/err through Jansi
System.out.println(ansi().fgGreen().a("OPEN").reset() + "  22/tcp  SSH");
AnsiConsole.systemUninstall(); // restore on exit
```
Jansi's `Ansi` builder is a fluent API: `.fgRed()`, `.fgBrightGreen()`, `.bg(Color.BLUE)`, `.bold()`, `.reset()`.

### 5b. AsciiTable (de.vandermeer)
**AsciiTable** (https://github.com/vdmeer/asciitable) generates formatted ASCII/Unicode tables for static report rendering.

```xml
<dependency>
    <groupId>de.vandermeer</groupId>
    <artifactId>asciitable</artifactId>
    <version>0.3.2</version>
</dependency>
```
```java
AsciiTable at = new AsciiTable();
at.addRule();
at.addRow("Port", "State", "Service", "Banner");
at.addRule();
at.addRow("22", "OPEN", "SSH", "OpenSSH 8.9");
at.addRow("80", "OPEN", "HTTP", "nginx/1.24");
at.addRule();
at.setTextAlignment(TextAlignment.LEFT);
System.out.println(at.render(80));
```
Supports Unicode box-drawing characters, multi-line cells, column width constraints, and theme variants (plain ASCII, UTF-8 single/double border, LaTeX).

Limitation: static rendering only — not designed for live-updating display.

### 5c. Tabled (alternative to AsciiTable)
A lighter alternative with fewer dependencies. Maven coordinates: `com.github.freva:ascii-table:1.2.0`.

```java
String[] headers = {"Port", "State", "Service"};
String[][] data = {{"22","OPEN","SSH"}, {"80","OPEN","HTTP"}};
System.out.println(AsciiTable.getTable(headers, data));
```

### 5d. Colorize with Picocli's `@Option` `@Help.Ansi`
Picocli has a built-in `Help.Ansi` enum and `Ansi.AUTO` detection that respects `NO_COLOR`, `TERM=dumb`, and Windows. Used for coloring help output, but can also be applied to runtime output:
```java
String msg = Help.Ansi.AUTO.string("@|green OPEN|@ port @|bold 443|@");
System.out.println(msg);
```
This is zero-dependency since Picocli is already on the classpath.

---

## 6. Real-Time Scan Progress Display Patterns

### Key Metrics to Display
For a port scanner, the most useful live metrics are:
1. **Progress bar** — ports done / total ports (percentage + bar)
2. **Rate** — ports scanned per second (rolling average over last 1–2 seconds is smoother than total average)
3. **ETA** — `(totalPorts - scannedPorts) / rate` in seconds
4. **Open count** — running tally of OPEN ports found
5. **Current port** — the port being scanned right now (or the last N ports attempted)
6. **Animated spinner** — signals the scan is alive (important for slow filtered ports)

### Implementation Architecture
```java
// AtomicLong counters updated by scan workers
AtomicLong scanned = new AtomicLong(0);
AtomicLong opened  = new AtomicLong(0);
long startNanos    = System.nanoTime();

// Rolling rate: keep a deque of (timestamp, count) samples
Deque<long[]> rateSamples = new ArrayDeque<>();

// Scheduled progress renderer — runs every 100ms on a daemon thread
ScheduledExecutorService ticker = Executors.newSingleThreadScheduledExecutor(r -> {
    Thread t = new Thread(r, "progress-ticker");
    t.setDaemon(true);
    return t;
});
ticker.scheduleAtFixedRate(() -> {
    long done = scanned.get();
    long open = opened.get();
    long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000;
    double rate = computeRollingRate(rateSamples, done);
    long etaSec = rate > 0 ? (long)((totalPorts - done) / rate) : -1;
    renderProgress(done, totalPorts, open, rate, etaSec);
}, 0, 100, TimeUnit.MILLISECONDS);
```

### Rolling Rate Calculation
```java
double computeRollingRate(Deque<long[]> samples, long currentCount) {
    long now = System.currentTimeMillis();
    samples.addLast(new long[]{now, currentCount});
    // Drop samples older than 2 seconds
    while (!samples.isEmpty() && now - samples.peekFirst()[0] > 2000) {
        samples.pollFirst();
    }
    if (samples.size() < 2) return 0;
    long[] oldest = samples.peekFirst();
    long[] newest = samples.peekLast();
    double deltaTime = (newest[0] - oldest[0]) / 1000.0;
    return deltaTime > 0 ? (newest[1] - oldest[1]) / deltaTime : 0;
}
```

### Full Progress Line Example
```
[=============>          ] 342/1024 (33%) | 17 OPEN | 428 p/s | ETA: 1m 38s  /
```

### ETA Formatting
```java
String formatEta(long seconds) {
    if (seconds < 0)   return "?";
    if (seconds < 60)  return seconds + "s";
    if (seconds < 3600) return (seconds / 60) + "m " + (seconds % 60) + "s";
    return (seconds / 3600) + "h " + ((seconds % 3600) / 60) + "m";
}
```

### Stderr vs Stdout Separation
Write all progress/spinner output to `stderr`; write final results to `stdout`. This allows:
```bash
java -jar scanner.jar --host example.com --ports 1-1024 > results.txt
# Progress bar appears in terminal via stderr; results go to file via stdout
```
This is the POSIX-correct pattern and is explicitly supported by Picocli's `spec.commandLine().getErr()`.

---

## 7. Interactive Mode Ideas

### 7a. Pause / Resume Scan
Use a `volatile boolean paused` flag checked by scan worker threads. A background keyboard listener thread reads `System.in` for keypresses:
```java
// Keyboard listener (runs in daemon thread, reads raw stdin)
Thread keyListener = new Thread(() -> {
    try {
        while (true) {
            int ch = System.in.read();
            if (ch == 'p' || ch == 'P') paused = !paused;
            if (ch == 'q' || ch == 'Q') { cancel(); break; }
            if (ch == '+') increaseThreads();
        }
    } catch (IOException ignored) {}
}, "key-listener");
keyListener.setDaemon(true);
keyListener.start();
```
For proper raw-mode key reading (without requiring Enter), use JLine3's `Terminal.reader()` which puts the terminal in raw mode.

### 7b. Adding Ports Mid-Scan
Use a `BlockingQueue<Integer>` of pending ports rather than submitting all tasks upfront. A producer thread drains the queue; additional ports can be enqueued at runtime:
```java
BlockingQueue<Integer> portQueue = new LinkedBlockingQueue<>(portList);
// User types: "add 8080,8443"
portQueue.addAll(Arrays.asList(8080, 8443));
```

### 7c. Live Filtering Results (Picocli Shell)
With `picocli-shell-jline3`, implement a mini REPL alongside the scan:
```
[scan running] > filter open
[scan running] > filter service=HTTP
[scan running] > export json /tmp/partial-results.json
[scan running] > pause
[scan paused ] > resume
```
Each command is parsed by a sub-`CommandLine` instance while the main scan runs in a background thread. `LineReader.readLine()` handles line editing and history.

### 7d. Keybinding Summary (display in header)
```
[P]ause  [R]esume  [Q]uit  [+/-]Threads  [F]ilter  [E]xport
```

### 7e. Picocli Interactive Shell Integration
```xml
<dependency>
    <groupId>info.picocli</groupId>
    <artifactId>picocli-shell-jline3</artifactId>
    <version>4.7.6</version>
</dependency>
```
```java
// In the scan command, after starting scan background thread:
PicocliJLineCompleter completer = new PicocliJLineCompleter(subCmdSpec);
LineReader reader = LineReaderBuilder.builder()
    .terminal(terminal)
    .completer(completer)
    .build();
// Event loop processes shell commands while scan runs
while (scanRunning) {
    String line = reader.readLine("[scanning] > ");
    new CommandLine(new ShellCommands()).execute(line.split("\\s+"));
}
```

---

## 8. Web Dashboard — Embedded HTTP Server with Live Scan Results

### 8a. Javalin (Recommended)
**Javalin** (https://javalin.io) is a lightweight, Jetty-based Java web framework that embeds in a fat JAR with minimal setup. Ideal for a `--web` flag that starts a live dashboard.

```xml
<dependency>
    <groupId>io.javalin</groupId>
    <artifactId>javalin</artifactId>
    <version>6.3.0</version>
</dependency>
```

#### REST Endpoint for Live Results
```java
Javalin app = Javalin.create().start(7070);

// GET /results — returns current ScanReport as JSON
app.get("/results", ctx -> {
    ctx.json(currentReport);  // Jackson serialization (already on classpath)
});

// GET /progress — returns scan progress stats
app.get("/progress", ctx -> {
    ctx.json(Map.of(
        "scanned", scanned.get(),
        "total", totalPorts,
        "open", opened.get(),
        "rate", currentRate,
        "eta", currentEta
    ));
});
```

#### Server-Sent Events (SSE) for Real-Time Push
```java
// GET /stream — SSE endpoint; client receives new open ports as they are found
app.sse("/stream", client -> {
    openPortConsumer = port -> client.sendEvent("port", objectMapper.writeValueAsString(port));
    client.onClose(() -> openPortConsumer = null);
});
```
Then from scan workers: `if (result.isOpen()) openPortConsumer.accept(result);`

#### Simple HTML Dashboard
Serve a static `index.html` with a fetch/SSE client:
```html
<!-- Minimal dashboard: auto-refreshes open port list -->
<script>
  const es = new EventSource('/stream');
  es.addEventListener('port', e => {
    const p = JSON.parse(e.data);
    document.getElementById('results').insertAdjacentHTML('beforeend',
      `<tr><td>${p.port}</td><td>${p.serviceName}</td><td>${p.banner || ''}</td></tr>`);
  });
</script>
```

#### CLI Integration
```
java -jar scanner.jar --host 192.168.1.1 --ports 1-65535 --web 7070
# Opens http://localhost:7070 in browser (optional: Desktop.browse())
# Normal CLI progress bar continues in terminal
# Dashboard provides shareable real-time view
```

### 8b. Spark Java (Lighter Alternative)
**SparkJava** (https://sparkjava.com) is older but smaller. Less active maintenance as of 2024.
```xml
<dependency>
    <groupId>com.sparkjava</groupId>
    <artifactId>spark-core</artifactId>
    <version>2.9.4</version>
</dependency>
```
Not recommended for new code — Javalin is the better choice.

### 8c. Undertow (Embedded, No Servlet Container)
For minimal footprint with SSE, Undertow (used by WildFly) can be embedded:
```xml
<dependency>
    <groupId>io.undertow</groupId>
    <artifactId>undertow-core</artifactId>
    <version>2.3.13.Final</version>
</dependency>
```
More complex setup than Javalin but produces a smaller JAR (no Jetty dependency). Primarily relevant if JAR size is a concern.

### 8d. JAR Size Considerations
| Option | Added JAR Size (approx) |
|--------|------------------------|
| Javalin 6 + Jetty | ~8–10 MB |
| SparkJava + Jetty | ~5–7 MB |
| Undertow core | ~2–3 MB |
| Lanterna | ~400 KB |
| JLine3 (full) | ~1.5 MB |
| Jansi | ~150 KB |
| AsciiTable | ~200 KB |

Web dashboard options add the most weight due to the embedded HTTP server. Recommend making it an optional Maven profile or a separate `--web` module.

---

## 9. Recommended Implementation Roadmap

### Phase 1 — Minimal (No New Dependencies)
1. Add ANSI progress bar using `\r` carriage return writes to `stderr`.
2. Use `spec.commandLine().getErr()` for all progress output (Picocli already present).
3. Use `Help.Ansi.AUTO` for colored OPEN/CLOSED/FILTERED labels.
4. Format final results table using manual `String.format()` padding or Picocli's `TextTable`.
5. Add `ScheduledExecutorService` ticker at 100ms intervals.

**Effort:** ~4–6 hours. Zero new Maven dependencies.

### Phase 2 — Enhanced Terminal (JLine3 or Jansi)
1. Add **Jansi** for Windows ANSI compatibility.
2. Add **JLine3** (`jline-builtins`) for `Status` sticky line and terminal width detection.
3. Implement rolling-rate ETA display with smooth spinner.
4. Add keyboard listener for `P`ause / `Q`uit / `+/-` thread count.

**Effort:** ~1–2 days. ~2 MB JAR addition.

### Phase 3 — Full TUI (Lanterna)
1. Add `--tui` flag that activates Lanterna full-screen mode.
2. Show: host info panel, progress bar, live-updating results table (sorted by port), stats panel (rate, ETA, open count by service).
3. Fall back to Phase 1 output if `--tui` flag absent or terminal is dumb.

**Effort:** ~2–3 days. ~400 KB JAR addition.

### Phase 4 — Web Dashboard (Javalin)
1. Add `--web [PORT]` flag (default 7070).
2. Serve SSE stream of open port results.
3. Serve `GET /results` returning current `ScanReport` JSON.
4. Bundle minimal `index.html` in `src/main/resources/web/`.
5. Optionally open browser with `Desktop.getDesktop().browse(URI.create("http://localhost:7070"))`.

**Effort:** ~2–3 days. ~10 MB JAR addition (consider separate Maven profile).

---

## 10. Quick-Reference: Maven Dependencies Summary

```xml
<!-- Option A: Zero new deps — use Picocli's built-in Ansi + manual ANSI codes -->
<!-- No new dependencies needed -->

<!-- Option B: Windows ANSI + basic colors -->
<dependency>
    <groupId>org.fusesource.jansi</groupId>
    <artifactId>jansi</artifactId>
    <version>2.4.1</version>
</dependency>

<!-- Option C: Full terminal control + sticky status line + interactive input -->
<dependency>
    <groupId>org.jline</groupId>
    <artifactId>jline</artifactId>
    <version>3.26.3</version>
</dependency>

<!-- Option D: Full-screen TUI with widgets -->
<dependency>
    <groupId>com.googlecode.lanterna</groupId>
    <artifactId>lanterna</artifactId>
    <version>3.1.2</version>
</dependency>

<!-- Option E: Static ASCII table formatting for final report -->
<dependency>
    <groupId>de.vandermeer</groupId>
    <artifactId>asciitable</artifactId>
    <version>0.3.2</version>
</dependency>
<!-- OR lighter alternative: -->
<dependency>
    <groupId>com.github.freva</groupId>
    <artifactId>ascii-table</artifactId>
    <version>1.2.0</version>
</dependency>

<!-- Option F: Picocli interactive shell + JLine3 integration -->
<dependency>
    <groupId>info.picocli</groupId>
    <artifactId>picocli-shell-jline3</artifactId>
    <version>4.7.6</version>
</dependency>

<!-- Option G: Web dashboard -->
<dependency>
    <groupId>io.javalin</groupId>
    <artifactId>javalin</artifactId>
    <version>6.3.0</version>
</dependency>
```

---

## 11. Key Sources

- Lanterna GitHub: https://github.com/mabe02/lanterna
- JLine3 GitHub: https://github.com/jline/jline3
- JLine3 Wiki: https://github.com/jline/jline3/wiki
- Picocli official site: https://picocli.info/
- Picocli shell-jline3 module: https://github.com/remkop/picocli/tree/main/picocli-shell-jline3
- Jansi GitHub: https://github.com/fusesource/jansi
- AsciiTable (vdmeer): https://github.com/vdmeer/asciitable
- ASCII-table (freva): https://github.com/freva/ascii-table
- Javalin docs: https://javalin.io/documentation
- Javalin SSE guide: https://javalin.io/tutorials/sse-example-kotlin
- ANSI escape code reference: https://en.wikipedia.org/wiki/ANSI_escape_code
- Jansi Maven Central: https://search.maven.org/artifact/org.fusesource.jansi/jansi
- JLine3 Maven Central: https://search.maven.org/artifact/org.jline/jline
