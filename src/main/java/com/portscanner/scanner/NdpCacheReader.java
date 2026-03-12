package com.portscanner.scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads the OS NDP (Neighbor Discovery Protocol) neighbor cache to find alive
 * IPv6 link-local hosts without requiring raw socket privileges.
 *
 * <ul>
 *   <li>Linux:   {@code ip -6 neigh show}</li>
 *   <li>macOS:   {@code ndp -a}</li>
 *   <li>Windows: {@code netsh interface ipv6 show neighbors}</li>
 * </ul>
 */
public class NdpCacheReader {

    private static final Logger log = LoggerFactory.getLogger(NdpCacheReader.class);

    // Linux: "fe80::1  dev eth0  lladdr aa:bb:cc:dd:ee:ff  REACHABLE"
    private static final Pattern LINUX_PATTERN =
            Pattern.compile("^([0-9a-fA-F:]+)\\s+dev\\s+\\S+\\s+lladdr\\s+([0-9a-fA-F:]+)\\s+(\\S+)");

    // macOS: "fe80::1%en0                 aa:bb:cc:dd:ee:ff  en0   R"
    private static final Pattern MACOS_PATTERN =
            Pattern.compile("^([0-9a-fA-F:%]+)\\s+([0-9a-fA-F:]+)\\s+\\S+\\s+(\\S+)");

    // Windows: " fe80::1                  aa-bb-cc-dd-ee-ff  Reachable"
    private static final Pattern WINDOWS_PATTERN =
            Pattern.compile("^\\s+([0-9a-fA-F:]+)\\s+([0-9a-fA-F-]+)\\s+(\\S+)");

    public record NeighborEntry(String ip, String mac, String state) {}

    /** Returns all entries from the system NDP cache, or empty list on any failure. */
    public List<NeighborEntry> readNeighbors() {
        String os = System.getProperty("os.name", "").toLowerCase();
        try {
            if (os.contains("win")) {
                return parseWindows(runCommand("netsh", "interface", "ipv6", "show", "neighbors"));
            } else if (os.contains("mac")) {
                return parseMac(runCommand("ndp", "-a"));
            } else {
                return parseLinux(runCommand("ip", "-6", "neigh", "show"));
            }
        } catch (Exception e) {
            log.debug("NDP cache read failed: {}", e.getMessage());
            return List.of();
        }
    }

    private List<String> runCommand(String... cmd) throws Exception {
        Process proc = new ProcessBuilder(cmd)
                .redirectErrorStream(true)
                .start();
        List<String> lines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) lines.add(line);
        }
        proc.waitFor();
        return lines;
    }

    private List<NeighborEntry> parseLinux(List<String> lines) {
        List<NeighborEntry> result = new ArrayList<>();
        for (String line : lines) {
            Matcher m = LINUX_PATTERN.matcher(line.trim());
            if (m.find()) result.add(new NeighborEntry(m.group(1), m.group(2), m.group(3)));
        }
        return result;
    }

    private List<NeighborEntry> parseMac(List<String> lines) {
        List<NeighborEntry> result = new ArrayList<>();
        for (String line : lines) {
            // Strip zone ID from address (e.g., fe80::1%en0 -> fe80::1)
            String stripped = line.replaceFirst("%\\S+\\s", " ");
            Matcher m = MACOS_PATTERN.matcher(stripped.trim());
            if (m.find()) result.add(new NeighborEntry(m.group(1), m.group(2), m.group(3)));
        }
        return result;
    }

    private List<NeighborEntry> parseWindows(List<String> lines) {
        List<NeighborEntry> result = new ArrayList<>();
        for (String line : lines) {
            Matcher m = WINDOWS_PATTERN.matcher(line);
            if (m.find()) {
                String mac = m.group(2).replace('-', ':');
                result.add(new NeighborEntry(m.group(1), mac, m.group(3)));
            }
        }
        return result;
    }
}
