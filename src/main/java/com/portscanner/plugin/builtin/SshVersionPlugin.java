package com.portscanner.plugin.builtin;

import com.portscanner.model.ScanResult;
import com.portscanner.plugin.PluginContext;
import com.portscanner.plugin.ScanPlugin;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * Plugin that extracts a clean SSH version string from the banner or by connecting to the port.
 * Converts raw banners like {@code SSH-2.0-OpenSSH_8.9} into {@code OpenSSH 8.9}.
 */
public class SshVersionPlugin implements ScanPlugin {

    @Override
    public String name() {
        return "ssh-version";
    }

    @Override
    public boolean appliesTo(ScanResult result) {
        if (result.getPort() == 22) {
            return true;
        }
        String service = result.getServiceName();
        return service != null && service.toLowerCase().contains("ssh");
    }

    @Override
    public void execute(ScanResult result, PluginContext ctx) {
        String banner = result.getBanner();

        if (banner != null && banner.contains("SSH-")) {
            // Parse existing banner
            String cleaned = parseSSHBanner(banner);
            if (cleaned != null) {
                result.setBanner(cleaned);
            }
            return;
        }

        // Banner absent — try reading from socket
        try {
            String host = ctx.getHost();
            int port = result.getPort();
            int timeout = ctx.getTimeoutMs();

            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), timeout);
                socket.setSoTimeout(timeout);
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(socket.getInputStream()));
                String line = reader.readLine();
                if (line != null && line.contains("SSH-")) {
                    String cleaned = parseSSHBanner(line);
                    result.setBanner(cleaned != null ? cleaned : line.trim());
                }
            }
        } catch (Exception e) {
            // Silently ignore — plugin failures must not disrupt the scan
        }
    }

    /**
     * Parses an SSH identification string such as {@code SSH-2.0-OpenSSH_8.9p1}
     * into a human-readable form like {@code OpenSSH 8.9p1}.
     *
     * @param raw the raw SSH banner string
     * @return cleaned version string, or null if parsing fails
     */
    private String parseSSHBanner(String raw) {
        try {
            // Format: SSH-<protocol>-<software>[_<version>][ <comments>]
            // Find the third '-' separated segment
            int firstDash = raw.indexOf('-');
            if (firstDash < 0) return null;
            int secondDash = raw.indexOf('-', firstDash + 1);
            if (secondDash < 0) return null;

            String softwarePart = raw.substring(secondDash + 1).trim();
            // Strip any trailing comments (after first space)
            int spaceIdx = softwarePart.indexOf(' ');
            if (spaceIdx > 0) {
                softwarePart = softwarePart.substring(0, spaceIdx);
            }

            // Replace underscore separator between name and version with a space
            // OpenSSH_8.9  →  OpenSSH 8.9
            int underscoreIdx = softwarePart.indexOf('_');
            if (underscoreIdx > 0) {
                softwarePart = softwarePart.substring(0, underscoreIdx)
                        + " " + softwarePart.substring(underscoreIdx + 1);
            }

            return softwarePart.isEmpty() ? null : softwarePart;
        } catch (Exception e) {
            return null;
        }
    }
}
