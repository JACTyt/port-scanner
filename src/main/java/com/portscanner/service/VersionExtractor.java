package com.portscanner.service;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts a clean version string from a service banner using per-service regex patterns.
 *
 * <p>Called after banner grabbing; result is stored in {@code ScanResult.version}.
 */
public class VersionExtractor {

    /**
     * Ordered map of service-name fragment → pattern.
     * The service name is upper-cased before matching so "SSH", "ssh", "OpenSSH" all hit "SSH".
     */
    private static final Map<String, Pattern> PATTERNS = new LinkedHashMap<>();

    static {
        // SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" → "OpenSSH_8.9p1"
        PATTERNS.put("SSH",        Pattern.compile("SSH-[\\d.]+-([\\w._-]+)"));
        // HTTP Server header: "Server: Apache/2.4.51 (Ubuntu)" → "Apache/2.4.51 (Ubuntu)"
        PATTERNS.put("HTTP",       Pattern.compile("(?i)Server:\\s*([^\\r\\n]+)"));
        // FTP: "220 Microsoft FTP Service 7.5.7600" or "220 vsftpd 3.0.5"
        PATTERNS.put("FTP",        Pattern.compile("220[- ][^\\r\\n]*?(\\w[\\w._-]+ [\\d][\\d._-]+)"));
        // SMTP: "220 mail.example.com ESMTP Postfix 3.7.0" → "Postfix 3.7.0"
        PATTERNS.put("SMTP",       Pattern.compile("220[- ][^\\r\\n]*?([A-Za-z][\\w._-]* [\\d][\\d._-]*)$"));
        // MySQL: probe response starts with version like "8.0.32-MySQL Community Server"
        PATTERNS.put("MYSQL",      Pattern.compile("([\\d]+\\.[\\d]+\\.[\\d]+[-\\w]*)"));
        // PostgreSQL probe response: "PostgreSQL 14.5 on ..."
        PATTERNS.put("POSTGRESQL", Pattern.compile("(?i)PostgreSQL\\s+([\\d.]+)"));
        // Redis INFO response: "redis_version:7.0.5"
        PATTERNS.put("REDIS",      Pattern.compile("redis_version:([\\d.]+)"));
        // Memcached: "VERSION 1.6.18"
        PATTERNS.put("MEMCACHED",  Pattern.compile("(?i)VERSION\\s+([\\d.]+)"));
        // IMAP: "* OK Dovecot ready"
        PATTERNS.put("IMAP",       Pattern.compile("(?i)Dovecot\\s+([\\d.]+)"));
        // Apache (also covered via HTTP Server header, but keep for direct banner match)
        PATTERNS.put("APACHE",     Pattern.compile("(?i)Apache/([\\d.]+(?:-[\\w]+)?)"));
        // nginx (same)
        PATTERNS.put("NGINX",      Pattern.compile("(?i)nginx/([\\d.]+)"));
        // Generic ISC BIND or other version strings with "version" keyword
        PATTERNS.put("DNS",        Pattern.compile("(?i)\\bversion[:\\s]+([\\d][\\d._-]+)"));
    }

    /**
     * Extracts a version string from {@code banner} using the pattern that matches
     * the provided service name. Returns {@code null} if no pattern matches.
     *
     * @param serviceName  the service name (e.g. "SSH", "HTTP", "MySQL")
     * @param banner       the raw first-line banner grabbed from the port
     * @return extracted version string or {@code null}
     */
    public static String extract(String serviceName, String banner) {
        if (serviceName == null || banner == null || banner.isBlank()) return null;
        String upper = serviceName.toUpperCase();
        for (Map.Entry<String, Pattern> entry : PATTERNS.entrySet()) {
            if (upper.contains(entry.getKey())) {
                Matcher m = entry.getValue().matcher(banner);
                if (m.find()) {
                    String result = m.groupCount() > 0 ? m.group(1) : m.group(0);
                    return result != null ? result.strip() : null;
                }
            }
        }
        return null;
    }
}
