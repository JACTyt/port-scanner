package com.portscanner.scanner;

import com.portscanner.model.OsGuess;
import com.portscanner.model.ScanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Guesses the target OS using TTL heuristics, banner analysis, and open port signals.
 * Enable with {@code --os}. Adds latency due to the ping subprocess.
 */
public class OsFingerprinter {

    private static final Logger log = LoggerFactory.getLogger(OsFingerprinter.class);
    private static final Pattern TTL_PATTERN = Pattern.compile("(?i)ttl[=<](\\d+)");

    /**
     * Perform OS fingerprinting and return the best guess, or {@code null} if nothing
     * could be determined.
     */
    public OsGuess fingerprint(InetAddress target, List<ScanResult> openPorts) {
        // 1. Banner / service signals (most specific — check first)
        OsGuess bannerGuess = bannerGuess(openPorts);
        if (bannerGuess != null && "high".equals(bannerGuess.getConfidence())) {
            return bannerGuess;
        }

        // 2. TTL heuristic via OS ping
        OsGuess ttlGuess = ttlGuess(target);

        // 3. If both found, prefer higher-confidence result; break ties with banner
        if (ttlGuess != null && bannerGuess != null) {
            int ttlScore = confidenceScore(ttlGuess.getConfidence());
            int bannerScore = confidenceScore(bannerGuess.getConfidence());
            return bannerScore >= ttlScore ? bannerGuess : ttlGuess;
        }

        if (ttlGuess != null) return ttlGuess;
        if (bannerGuess != null) return bannerGuess;
        return null;
    }

    // ── TTL probe ─────────────────────────────────────────────────────────────

    private OsGuess ttlGuess(InetAddress target) {
        try {
            boolean isWindows = System.getProperty("os.name", "").toLowerCase().contains("win");
            String[] cmd = isWindows
                    ? new String[]{"ping", "-n", "1", target.getHostAddress()}
                    : new String[]{"ping", "-c", "1", "-W", "2", target.getHostAddress()};

            Process proc = Runtime.getRuntime().exec(cmd);
            boolean exited = proc.waitFor(5, TimeUnit.SECONDS);
            if (!exited) {
                proc.destroyForcibly();
                return null;
            }
            String output = new String(proc.getInputStream().readAllBytes());
            Matcher m = TTL_PATTERN.matcher(output);
            if (m.find()) {
                int ttl = Integer.parseInt(m.group(1));
                return ttlToOs(ttl);
            }
        } catch (Exception e) {
            log.debug("TTL probe failed: {}", e.getMessage());
        }
        return null;
    }

    private static OsGuess ttlToOs(int ttl) {
        // Original TTL values are typically 64 (Linux/macOS), 128 (Windows), 255 (network gear).
        // Each router hop decrements TTL by 1, so we use generous thresholds.
        if (ttl > 200) {
            return OsGuess.builder()
                    .os("Network Device (Cisco / Juniper)")
                    .confidence("medium")
                    .method("TTL=" + ttl)
                    .build();
        } else if (ttl > 100) {
            return OsGuess.builder()
                    .os("Windows")
                    .confidence("medium")
                    .method("TTL=" + ttl)
                    .build();
        } else if (ttl > 32) {
            return OsGuess.builder()
                    .os("Linux / macOS")
                    .confidence("medium")
                    .method("TTL=" + ttl)
                    .build();
        } else {
            return OsGuess.builder()
                    .os("Unknown (low TTL — many hops or old OS)")
                    .confidence("low")
                    .method("TTL=" + ttl)
                    .build();
        }
    }

    // ── Banner / port signal analysis ─────────────────────────────────────────

    private static OsGuess bannerGuess(List<ScanResult> openPorts) {
        if (openPorts == null || openPorts.isEmpty()) return null;

        for (ScanResult r : openPorts) {
            String banner  = r.getBanner()      != null ? r.getBanner()      : "";
            String service = r.getServiceName() != null ? r.getServiceName().toLowerCase() : "";

            // ── SSH banner OS strings ────────────────────────────────────────
            if (containsAny(banner, "Ubuntu", "ubuntu")) {
                return OsGuess.builder().os("Linux (Ubuntu)").confidence("high").method("SSH banner").build();
            }
            if (containsAny(banner, "Debian", "debian")) {
                return OsGuess.builder().os("Linux (Debian)").confidence("high").method("SSH banner").build();
            }
            if (containsAny(banner, "CentOS", "centos", "Red Hat", "RHEL")) {
                return OsGuess.builder().os("Linux (RHEL/CentOS)").confidence("high").method("SSH banner").build();
            }
            if (containsAny(banner, "Alpine")) {
                return OsGuess.builder().os("Linux (Alpine)").confidence("high").method("SSH banner").build();
            }
            if (containsAny(banner, "FreeBSD")) {
                return OsGuess.builder().os("FreeBSD").confidence("high").method("SSH banner").build();
            }
            if (containsAny(banner, "OpenBSD")) {
                return OsGuess.builder().os("OpenBSD").confidence("high").method("SSH banner").build();
            }
            if (containsAny(banner, "Windows")) {
                return OsGuess.builder().os("Windows").confidence("high").method("SSH banner").build();
            }

            // ── HTTP Server header ───────────────────────────────────────────
            if (r.getHttpInfo() != null) {
                String server = r.getHttpInfo().getServerHeader();
                if (server != null) {
                    if (containsAny(server, "Microsoft-IIS", "IIS")) {
                        return OsGuess.builder().os("Windows (IIS)").confidence("high").method("HTTP Server header").build();
                    }
                    if (containsAny(server, "Ubuntu")) {
                        return OsGuess.builder().os("Linux (Ubuntu)").confidence("high").method("HTTP Server header").build();
                    }
                    if (containsAny(server, "Debian")) {
                        return OsGuess.builder().os("Linux (Debian)").confidence("high").method("HTTP Server header").build();
                    }
                    if (containsAny(server, "nginx", "Apache")) {
                        return OsGuess.builder().os("Linux (likely)").confidence("low").method("HTTP Server: " + server).build();
                    }
                }
            }

            // ── Open port signals ────────────────────────────────────────────
            int port = r.getPort();
            if (port == 3389) {
                return OsGuess.builder().os("Windows").confidence("medium").method("RDP port (3389) open").build();
            }
            if (port == 445 || port == 139) {
                return OsGuess.builder().os("Windows").confidence("medium").method("SMB port (" + port + ") open").build();
            }
            if (port == 5985 || port == 5986) {
                return OsGuess.builder().os("Windows").confidence("medium").method("WinRM port (" + port + ") open").build();
            }
        }
        return null;
    }

    private static boolean containsAny(String text, String... candidates) {
        for (String c : candidates) {
            if (text.contains(c)) return true;
        }
        return false;
    }

    private static int confidenceScore(String confidence) {
        return switch (confidence) {
            case "high"   -> 3;
            case "medium" -> 2;
            default       -> 1;
        };
    }
}
