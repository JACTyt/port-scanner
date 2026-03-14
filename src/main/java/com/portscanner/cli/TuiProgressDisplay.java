package com.portscanner.cli;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.gui2.table.Table;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;
import com.googlecode.lanterna.screen.Screen;
import com.googlecode.lanterna.terminal.DefaultTerminalFactory;

import java.nio.charset.Charset;
import com.portscanner.model.PortStatus;
import com.portscanner.model.ScanResult;
import com.portscanner.scanner.PortScanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Full-screen interactive TUI using Lanterna. Extends {@link ProgressReporter} so it can
 * be passed wherever a {@code ProgressReporter} is expected.
 *
 * <p>Threading model: the GUI loop thread owns all Lanterna components and calls
 * {@code gui.updateScreen()} directly — avoiding the GUI-thread enforcement of
 * {@code processEventsAndUpdate()}. The scan thread communicates via atomics and queues.
 *
 * <p>If the constructor throws {@link IOException} (no real terminal available),
 * the caller should fall back to a plain {@link ProgressReporter}.
 */
public class TuiProgressDisplay extends ProgressReporter {

    private static final Logger log = LoggerFactory.getLogger(TuiProgressDisplay.class);
    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");
    private static final int BAR_WIDTH = 24;

    private final int tuiTotalPorts;
    private final String scanHost;
    private final AtomicInteger tuiScanned   = new AtomicInteger(0);
    private final AtomicInteger tuiOpenCount = new AtomicInteger(0);
    private final AtomicLong    tuiStartMs   = new AtomicLong(0);
    private final AtomicBoolean guiRunning   = new AtomicBoolean(false);
    private volatile boolean    tuiPaused    = false;

    // Cross-thread state pushed by scan thread, consumed by GUI thread
    private final AtomicReference<String>   pendingProgress = new AtomicReference<>("");
    private final AtomicReference<String>   pendingStats    = new AtomicReference<>("");
    private final AtomicReference<String>   pendingControls = new AtomicReference<>("[P]ause [Q]uit [+/-]threads");
    private final ConcurrentLinkedQueue<String>      pendingLogs  = new ConcurrentLinkedQueue<>();
    private final AtomicReference<List<ScanResult>>  pendingPorts = new AtomicReference<>(null);

    private final Screen screen;
    private MultiWindowTextGUI  gui;
    private Label               progressLabel;
    private Label               statsLabel;
    private Label               controlsLabel;
    private Table<String>       portsTable;
    private TextBox             logBox;
    private Thread              guiLoopThread;
    private ScheduledExecutorService tuiScheduler;
    private ScheduledFuture<?>  tuiTickTask;
    private volatile PortScanner linkedScanner;

    /**
     * Creates a Lanterna TUI. Throws {@link IOException} if no real terminal is
     * available so the caller can fall back to a plain {@link ProgressReporter}.
     */
    public TuiProgressDisplay(int totalPorts, String host) throws IOException {
        super(totalPorts, false); // disable parent JLine3 — TUI handles all display
        this.tuiTotalPorts = totalPorts;
        this.scanHost = host;
        // Force headless + stream-based ANSI terminal so Lanterna never tries the
        // Windows native console API or Swing window (both fail under java.exe).
        // This works in Windows Terminal, CMD, and any ANSI-capable terminal.
        System.setProperty("java.awt.headless", "true");
        DefaultTerminalFactory factory = new DefaultTerminalFactory(System.out, System.in, Charset.defaultCharset());
        factory.setForceTextTerminal(true);
        factory.setAutoOpenTerminalEmulatorWindow(false);
        this.screen = factory.createScreen();
    }

    // ── ProgressReporter overrides ────────────────────────────────────────

    @Override
    public void portScanned(PortStatus status) {
        tuiScanned.incrementAndGet();
        if (status == PortStatus.OPEN) tuiOpenCount.incrementAndGet();
    }

    @Override
    public void setControlledScanner(PortScanner scanner) {
        this.linkedScanner = scanner;
    }

    @Override
    public void start() {
        tuiStartMs.set(System.currentTimeMillis());
        guiRunning.set(true);
        pendingLogs.add("Scan started — " + tuiTotalPorts + " ports queued");

        // GUI loop runs entirely on a single virtual thread that owns all Lanterna state
        guiLoopThread = Thread.ofVirtual().name("tui-gui-loop").unstarted(() -> {
            try {
                buildUI();
                screen.startScreen();

                while (guiRunning.get()) {
                    handleKeyInput();
                    applyPendingUpdates();
                    gui.updateScreen(); // draw components + screen.refresh()
                    Thread.sleep(50);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (IOException e) {
                log.debug("TUI loop error: {}", e.getMessage());
            } finally {
                try { screen.stopScreen(); } catch (IOException ignored) {}
            }
        });
        guiLoopThread.setDaemon(true);
        guiLoopThread.start();

        // Tick scheduler pushes updated stats to the atomics every 100ms
        tuiScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = Thread.ofVirtual().name("tui-tick").unstarted(r);
            t.setDaemon(true);
            return t;
        });
        tuiTickTask = tuiScheduler.scheduleAtFixedRate(this::pushTick, 0, 100, TimeUnit.MILLISECONDS);
    }

    @Override
    public void stop() {
        pendingLogs.add("Scan complete — " + tuiOpenCount.get() + " open port(s) found");
        if (tuiTickTask  != null) tuiTickTask.cancel(false);
        if (tuiScheduler != null) {
            tuiScheduler.shutdown();
            try { tuiScheduler.awaitTermination(300, TimeUnit.MILLISECONDS); } catch (InterruptedException ignored) {}
        }
        try { Thread.sleep(1200); } catch (InterruptedException ignored) {}

        guiRunning.set(false);
        if (guiLoopThread != null) guiLoopThread.interrupt();
        try { guiLoopThread.join(2000); } catch (InterruptedException ignored) {}
    }

    /** Call from ScanCommand after scan completes to show open ports in the table. */
    public void setOpenPorts(List<ScanResult> openPorts) {
        pendingPorts.set(openPorts);
    }

    // ── GUI thread internals ──────────────────────────────────────────────

    /** Builds the Lanterna window/component tree. Called on the GUI thread. */
    private void buildUI() {
        gui = new MultiWindowTextGUI(screen, new DefaultWindowManager(),
                new EmptySpace(TextColor.ANSI.BLACK));

        Panel mainPanel = new Panel(new LinearLayout(Direction.VERTICAL));
        mainPanel.addComponent(new Label(" PORT SCANNER TUI — scanning " + scanHost));
        mainPanel.addComponent(new Separator(Direction.HORIZONTAL));

        Panel middlePanel = new Panel(new LinearLayout(Direction.HORIZONTAL));

        // Left: progress panel
        Panel progressPanel = new Panel(new LinearLayout(Direction.VERTICAL));
        progressLabel = new Label("[" + " ".repeat(BAR_WIDTH) + "] 0%");
        statsLabel    = new Label("0/" + tuiTotalPorts + " | 0 OPEN | 0 p/s | ETA: --");
        controlsLabel = new Label("[P]ause [Q]uit [+/-]threads");
        progressPanel.addComponent(progressLabel);
        progressPanel.addComponent(statsLabel);
        progressPanel.addComponent(controlsLabel);
        middlePanel.addComponent(progressPanel.withBorder(Borders.singleLine("PROGRESS")));

        // Right: open ports table
        portsTable = new Table<>("PORT", "SERVICE", "RTT");
        portsTable.setVisibleRows(8);
        middlePanel.addComponent(portsTable.withBorder(Borders.singleLine("OPEN PORTS")));

        mainPanel.addComponent(middlePanel);
        mainPanel.addComponent(new Separator(Direction.HORIZONTAL));

        // Bottom: log
        logBox = new TextBox(new TerminalSize(78, 4), TextBox.Style.MULTI_LINE);
        logBox.setReadOnly(true);
        mainPanel.addComponent(logBox.withBorder(Borders.singleLine("LOG")));

        BasicWindow window = new BasicWindow(" Port Scanner");
        window.setHints(List.of(Window.Hint.FULL_SCREEN));
        window.setComponent(mainPanel);
        gui.addWindow(window);
    }

    /** Applies queued updates to Lanterna components. Called on the GUI thread. */
    private void applyPendingUpdates() {
        String p = pendingProgress.getAndSet(null);
        if (p != null && progressLabel != null) progressLabel.setText(p);

        String s = pendingStats.getAndSet(null);
        if (s != null && statsLabel != null) statsLabel.setText(s);

        String c = pendingControls.getAndSet(null);
        if (c != null && controlsLabel != null) controlsLabel.setText(c);

        // Drain log queue
        String logLine;
        while ((logLine = pendingLogs.poll()) != null && logBox != null) {
            String cur = logBox.getText();
            logBox.setText(cur.isEmpty() ? logLine : cur + "\n" + logLine);
        }

        // Apply port table if set
        List<ScanResult> ports = pendingPorts.getAndSet(null);
        if (ports != null && portsTable != null) {
            portsTable.getTableModel().clear();
            for (ScanResult r : ports) {
                portsTable.getTableModel().addRow(
                        String.valueOf(r.getPort()),
                        r.getServiceName() != null ? r.getServiceName() : "Unknown",
                        r.getResponseTimeMs() + "ms");
            }
        }
    }

    /** Handles keyboard input. Called on the GUI thread. */
    private void handleKeyInput() throws IOException {
        KeyStroke key = screen.pollInput();
        if (key == null || linkedScanner == null) return;
        if (key.getKeyType() == KeyType.Character && key.getCharacter() != null) {
            char c = Character.toLowerCase(key.getCharacter());
            switch (c) {
                case 'p' -> {
                    if (tuiPaused) { linkedScanner.resume(); tuiPaused = false; pendingLogs.add("Scan resumed"); }
                    else           { linkedScanner.pause();  tuiPaused = true;  pendingLogs.add("Scan paused"); }
                }
                case 'q' -> { linkedScanner.cancel(); pendingLogs.add("Scan cancelled by user"); }
                case '+' -> { linkedScanner.increaseThreads(10); pendingLogs.add("Thread count increased (+10)"); }
                case '-' -> { linkedScanner.decreaseThreads(10); pendingLogs.add("Thread count decreased (-10)"); }
            }
        } else if (key.getKeyType() == KeyType.Escape || key.getKeyType() == KeyType.EOF) {
            linkedScanner.cancel();
        }
    }

    /** Pushes updated progress values to atomics. Called on the tick scheduler thread. */
    private void pushTick() {
        int done     = tuiScanned.get();
        int open     = tuiOpenCount.get();
        long elapsed = System.currentTimeMillis() - tuiStartMs.get();
        double rate  = elapsed > 0 ? (done * 1000.0 / elapsed) : 0;
        int remaining = tuiTotalPorts - done;
        long etaSec   = rate > 0 ? (long)(remaining / rate) : 0;
        int pct       = tuiTotalPorts > 0 ? (done * 100 / tuiTotalPorts) : 0;

        pendingProgress.set("[" + buildBar(done, tuiTotalPorts) + "] " + pct + "%");
        pendingStats.set(String.format("%d/%d | %d OPEN | %d p/s | ETA: %ds",
                done, tuiTotalPorts, open, (int) rate, etaSec));
        pendingControls.set(tuiPaused
                ? "[PAUSED]  [P]resume [Q]uit [+/-]threads"
                : "[P]ause [Q]uit [+/-]threads");
    }

    private String buildBar(int done, int total) {
        if (total <= 0) return " ".repeat(BAR_WIDTH);
        int filled = Math.min((int)((double) done / total * BAR_WIDTH), BAR_WIDTH);
        StringBuilder sb = new StringBuilder(BAR_WIDTH);
        for (int i = 0; i < filled; i++) sb.append('=');
        if (filled < BAR_WIDTH) {
            sb.append('>');
            for (int i = filled + 1; i < BAR_WIDTH; i++) sb.append(' ');
        }
        return sb.toString();
    }
}
