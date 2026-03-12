package com.portscanner.scanner;

import com.portscanner.model.TracerouteHop;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Runs a system traceroute/tracert and parses the output into a list of TracerouteHop records.
 */
public class Traceroute {

    private static final Logger log = LoggerFactory.getLogger(Traceroute.class);

    // Windows: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
    // Also handles: "  1     1 ms     1 ms     1 ms  192.168.1.1"
    private static final Pattern WINDOWS_LINE = Pattern.compile(
            "^\\s*(\\d+)\\s+(?:(?:<?(\\d+)\\s+ms\\s+)){1,3}(\\S+)\\s*$"
    );

    // Windows line with angle brackets: match the actual IP/hostname at end plus all rtt tokens
    private static final Pattern WINDOWS_LINE_FULL = Pattern.compile(
            "^\\s*(\\d+)\\s+((?:(?:<?\\d+|\\*)\\s+ms\\s+){1,3})(\\S+)\\s*$"
    );

    // Windows timeout: "  3     *        *        *     Request timed out."
    private static final Pattern WINDOWS_TIMEOUT = Pattern.compile(
            "^\\s*(\\d+)\\s+\\*\\s+\\*\\s+\\*\\s+.*$"
    );

    // Linux: " 1  192.168.1.1 (192.168.1.1)  0.543 ms  0.412 ms  0.398 ms"
    private static final Pattern LINUX_LINE = Pattern.compile(
            "^\\s*(\\d+)\\s+(\\S+)\\s+\\((\\S+)\\)\\s+([\\d.]+)\\s+ms"
    );

    // Linux timeout: " 3  * * *"
    private static final Pattern LINUX_TIMEOUT = Pattern.compile(
            "^\\s*(\\d+)\\s+\\*\\s+\\*\\s+\\*\\s*$"
    );

    public List<TracerouteHop> run(String host, int maxHops) {
        List<TracerouteHop> hops = new ArrayList<>();
        boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");

        ProcessBuilder pb;
        if (isWindows) {
            pb = new ProcessBuilder("tracert", "-h", String.valueOf(maxHops), "-w", "1000", host);
        } else {
            pb = new ProcessBuilder("traceroute", "-m", String.valueOf(maxHops), "-w", "1", host);
        }
        pb.redirectErrorStream(true);

        try {
            Process process = pb.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    log.debug("traceroute line: {}", line);
                    Optional<TracerouteHop> hop = isWindows
                            ? parseWindowsLine(line)
                            : parseLinuxLine(line);
                    hop.ifPresent(hops::add);
                }
            }
            process.waitFor();
        } catch (Exception e) {
            log.error("Failed to run traceroute: {}", e.getMessage());
        }

        return hops;
    }

    /**
     * Parse a single Windows tracert output line.
     * Package-private for testing.
     */
    static Optional<TracerouteHop> parseWindowsLine(String line) {
        if (line == null) return Optional.empty();

        // Check for timeout line first
        Matcher timeoutMatcher = WINDOWS_TIMEOUT.matcher(line);
        if (timeoutMatcher.matches()) {
            int hopNum = Integer.parseInt(timeoutMatcher.group(1));
            return Optional.of(new TracerouteHop(hopNum, "*", "*", -1));
        }

        // Try to match a normal line with RTT values and IP/hostname at end
        Matcher fullMatcher = WINDOWS_LINE_FULL.matcher(line);
        if (fullMatcher.matches()) {
            int hopNum = Integer.parseInt(fullMatcher.group(1));
            String rttPart = fullMatcher.group(2).trim();
            String ipOrHost = fullMatcher.group(3);

            // Skip lines where the last token looks like a timeout label
            if (ipOrHost.equalsIgnoreCase("timed") || ipOrHost.equalsIgnoreCase("Request")) {
                return Optional.empty();
            }

            // Parse the first RTT token
            double rtt = parseWindowsRtt(rttPart);
            return Optional.of(new TracerouteHop(hopNum, ipOrHost, ipOrHost, rtt));
        }

        return Optional.empty();
    }

    /**
     * Parse RTT string from Windows tracert (e.g., "<1 ms  <1 ms  <1 ms  " or "10 ms  10 ms  10 ms  ").
     * Returns the first RTT value found.
     */
    private static double parseWindowsRtt(String rttBlock) {
        // Find the first "<N ms" or "N ms" token
        Pattern rttToken = Pattern.compile("<?(\\d+)\\s+ms");
        Matcher m = rttToken.matcher(rttBlock);
        if (m.find()) {
            String raw = m.group(0);
            if (raw.startsWith("<")) {
                // "<1 ms" => treat as 0.5
                int val = Integer.parseInt(m.group(1));
                return val <= 1 ? 0.5 : val - 0.5;
            } else {
                return Double.parseDouble(m.group(1));
            }
        }
        return -1;
    }

    /**
     * Parse a single Linux traceroute output line.
     * Package-private for testing.
     */
    static Optional<TracerouteHop> parseLinuxLine(String line) {
        if (line == null) return Optional.empty();

        // Check for timeout line
        Matcher timeoutMatcher = LINUX_TIMEOUT.matcher(line);
        if (timeoutMatcher.matches()) {
            int hopNum = Integer.parseInt(timeoutMatcher.group(1));
            return Optional.of(new TracerouteHop(hopNum, "*", "*", -1));
        }

        // Normal line
        Matcher m = LINUX_LINE.matcher(line);
        if (m.find()) {
            int hopNum = Integer.parseInt(m.group(1));
            String hostname = m.group(2);
            String ip = m.group(3);
            double rtt = Double.parseDouble(m.group(4));
            return Optional.of(new TracerouteHop(hopNum, ip, hostname, rtt));
        }

        return Optional.empty();
    }
}
