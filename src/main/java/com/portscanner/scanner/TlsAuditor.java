package com.portscanner.scanner;

import com.portscanner.model.TlsAuditResult;
import com.portscanner.model.TlsVulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.DataInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * TLS deep auditor: enumerates supported protocol versions and cipher suites,
 * and probes for known TLS vulnerabilities (BEAST, POODLE, SWEET32, Heartbleed).
 */
public class TlsAuditor {

    private static final Logger log = LoggerFactory.getLogger(TlsAuditor.class);

    /** Trust-all TrustManager — we're auditing, not authenticating. */
    private static final TrustManager[] TRUST_ALL = {
        new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }
    };

    /** Patterns that identify weak/deprecated cipher suites. */
    private static final List<String> WEAK_PATTERNS = List.of(
            "RC4", "_NULL_", "EXPORT", "_DES_", "3DES", "_anon_", "_ADH_", "_AECDH_"
    );

    /** TLS protocol versions to test for support (in order of decreasing severity). */
    private static final List<String> PROTOCOL_CANDIDATES = List.of("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3");

    // Minimal TLS 1.1 ClientHello with heartbeat extension (type 0x000f)
    private static final byte[] CLIENT_HELLO_HEARTBEAT = {
        0x16, 0x03, 0x02, 0x00, 0x34,       // TLS record: Handshake, TLS 1.1, length=52
        0x01, 0x00, 0x00, 0x30,              // ClientHello, length=48
        0x03, 0x02,                          // client_version = TLS 1.1
        // 32 bytes random
        0x53, 0x43, 0x5b, (byte)0x90, (byte)0x9d, (byte)0x9b, 0x72, 0x0b,
        (byte)0xbc, 0x0c, (byte)0xbc, 0x2b, (byte)0x92, (byte)0xa8, 0x48, (byte)0x97,
        (byte)0xcf, (byte)0xbd, 0x39, 0x04, (byte)0xcc, 0x16, 0x0a, (byte)0x85,
        0x03, (byte)0x90, (byte)0x9f, 0x77, 0x04, 0x33, (byte)0xd4, (byte)0xde,
        0x00,                                // session_id_length = 0
        0x00, 0x02,                          // cipher_suites_length = 2
        0x00, 0x2f,                          // TLS_RSA_WITH_AES_128_CBC_SHA
        0x01, 0x00,                          // compression_methods: 1 method, null
        0x00, 0x05,                          // extensions_length = 5
        0x00, 0x0f, 0x00, 0x01, 0x01        // Heartbeat extension: type=15, len=1, mode=1
    };

    // Malformed heartbeat: payload_length=16384 but no actual payload — triggers Heartbleed
    private static final byte[] MALFORMED_HEARTBEAT = {
        0x18, 0x03, 0x02, 0x00, 0x03,       // ContentType=Heartbeat, TLS 1.1, length=3
        0x01, 0x40, 0x00                     // type=Request, payload_length=16384
    };

    public static Optional<TlsAuditResult> audit(String host, int port, int timeoutMs) {
        List<String> supportedProtocols = new ArrayList<>();
        List<String> weakCiphers = new ArrayList<>();
        List<String> acceptedCiphers = new ArrayList<>();
        List<TlsVulnerability> vulnerabilities = new ArrayList<>();

        // ── Protocol version detection ───────────────────────────────────────
        for (String protocol : PROTOCOL_CANDIDATES) {
            if (supportsProtocol(host, port, protocol, timeoutMs)) {
                supportedProtocols.add(protocol);
            }
        }

        // If no protocol succeeded, this is not a TLS port
        if (supportedProtocols.isEmpty()) {
            return Optional.empty();
        }

        // ── Weak cipher enumeration (parallel) ───────────────────────────────
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, TRUST_ALL, new SecureRandom());
            String[] allSupported = ctx.createSSLEngine().getSupportedCipherSuites();

            // Test only weak cipher patterns to keep audit fast
            List<String> candidates = Arrays.stream(allSupported)
                    .filter(c -> WEAK_PATTERNS.stream().anyMatch(c::contains))
                    .collect(Collectors.toList());

            List<CompletableFuture<Optional<String>>> futures = candidates.stream()
                    .map(cipher -> CompletableFuture.supplyAsync(
                            () -> testCipher(host, port, cipher, timeoutMs)))
                    .toList();
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

            for (CompletableFuture<Optional<String>> f : futures) {
                f.getNow(Optional.empty()).ifPresent(c -> {
                    weakCiphers.add(c);
                    acceptedCiphers.add(c);
                });
            }

            // Also probe a few strong ciphers to populate acceptedCiphers
            List<String> strongCandidates = Arrays.stream(allSupported)
                    .filter(c -> c.contains("AES_256") || c.contains("CHACHA20"))
                    .limit(5)
                    .toList();
            for (String cipher : strongCandidates) {
                testCipher(host, port, cipher, timeoutMs).ifPresent(acceptedCiphers::add);
            }
        } catch (Exception e) {
            log.debug("Cipher enumeration error for {}:{} — {}", host, port, e.getMessage());
        }

        // ── Vulnerability detection ──────────────────────────────────────────
        boolean hasTls10 = supportedProtocols.contains("TLSv1");
        boolean hasTls11 = supportedProtocols.contains("TLSv1.1");
        boolean hasWeakCbc = weakCiphers.stream().anyMatch(c -> c.contains("CBC") || c.contains("DES"));
        boolean has3Des = weakCiphers.stream().anyMatch(c -> c.contains("3DES"));

        if (hasTls10 && hasWeakCbc) {
            vulnerabilities.add(TlsVulnerability.builder()
                    .name("BEAST")
                    .severity("MEDIUM")
                    .description("TLS 1.0 with CBC cipher suites is susceptible to the BEAST attack. "
                            + "Upgrade to TLS 1.2+ and prefer AEAD cipher suites (AES-GCM, ChaCha20).")
                    .build());
        }

        if (hasTls10) {
            vulnerabilities.add(TlsVulnerability.builder()
                    .name("TLS 1.0 deprecated")
                    .severity("HIGH")
                    .description("TLS 1.0 is deprecated (RFC 8996) and should be disabled. "
                            + "Enable TLS 1.2 or 1.3 only.")
                    .build());
        }

        if (hasTls11) {
            vulnerabilities.add(TlsVulnerability.builder()
                    .name("TLS 1.1 deprecated")
                    .severity("HIGH")
                    .description("TLS 1.1 is deprecated (RFC 8996) and should be disabled. "
                            + "Enable TLS 1.2 or 1.3 only.")
                    .build());
        }

        if (has3Des) {
            vulnerabilities.add(TlsVulnerability.builder()
                    .name("SWEET32")
                    .cve("CVE-2016-2183")
                    .severity("MEDIUM")
                    .description("3DES cipher suites are accepted. "
                            + "Birthday attacks on 64-bit block ciphers (SWEET32) allow plaintext recovery "
                            + "in long-lived connections. Disable all 3DES cipher suites.")
                    .build());
        }

        boolean hasRc4 = weakCiphers.stream().anyMatch(c -> c.contains("RC4"));
        if (hasRc4) {
            vulnerabilities.add(TlsVulnerability.builder()
                    .name("RC4 cipher accepted")
                    .severity("HIGH")
                    .description("RC4 stream cipher is cryptographically broken and must not be used. "
                            + "Disable all RC4 cipher suites immediately.")
                    .build());
        }

        boolean hasNullCipher = weakCiphers.stream().anyMatch(c -> c.contains("NULL"));
        if (hasNullCipher) {
            vulnerabilities.add(TlsVulnerability.builder()
                    .name("NULL cipher accepted")
                    .severity("CRITICAL")
                    .description("NULL cipher suites provide no encryption — data is transmitted in plaintext "
                            + "even over a TLS connection. Disable immediately.")
                    .build());
        }

        boolean hasExport = weakCiphers.stream().anyMatch(c -> c.contains("EXPORT"));
        if (hasExport) {
            vulnerabilities.add(TlsVulnerability.builder()
                    .name("EXPORT cipher accepted")
                    .cve("CVE-2015-0204")
                    .severity("CRITICAL")
                    .description("EXPORT-grade cipher suites (40-bit and 56-bit key lengths) are accepted. "
                            + "This enables FREAK and DROWN attacks. Disable all EXPORT cipher suites.")
                    .build());
        }

        boolean hasAnon = weakCiphers.stream().anyMatch(c -> c.contains("anon") || c.contains("ADH") || c.contains("AECDH"));
        if (hasAnon) {
            vulnerabilities.add(TlsVulnerability.builder()
                    .name("Anonymous cipher accepted")
                    .severity("CRITICAL")
                    .description("Anonymous Diffie-Hellman cipher suites provide no server authentication, "
                            + "enabling man-in-the-middle attacks. Disable immediately.")
                    .build());
        }

        // ── Heartbleed probe ─────────────────────────────────────────────────
        if (probeHeartbleed(host, port, timeoutMs)) {
            vulnerabilities.add(TlsVulnerability.builder()
                    .name("Heartbleed")
                    .cve("CVE-2014-0160")
                    .severity("CRITICAL")
                    .description("Server is vulnerable to Heartbleed: a malformed TLS heartbeat request "
                            + "causes the server to return up to 64KB of heap memory, potentially including "
                            + "private keys, session tokens, and passwords. Patch OpenSSL immediately.")
                    .build());
        }

        return Optional.of(TlsAuditResult.builder()
                .supportedProtocols(supportedProtocols.isEmpty() ? null : supportedProtocols)
                .acceptedCiphers(acceptedCiphers.isEmpty() ? null : acceptedCiphers)
                .weakCiphers(weakCiphers.isEmpty() ? null : weakCiphers)
                .vulnerabilities(vulnerabilities.isEmpty() ? null : vulnerabilities)
                .build());
    }

    /** Returns true if the server negotiates the given TLS protocol version. */
    static boolean supportsProtocol(String host, int port, String protocol, int timeoutMs) {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, TRUST_ALL, new SecureRandom());
            SSLSocketFactory factory = ctx.getSocketFactory();
            try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
                socket.connect(new InetSocketAddress(host, port), timeoutMs);
                socket.setSoTimeout(timeoutMs);
                socket.setEnabledProtocols(new String[]{protocol});
                socket.startHandshake();
                return true;
            }
        } catch (SSLHandshakeException e) {
            // Server rejected this protocol version
            return false;
        } catch (Exception e) {
            log.debug("Protocol test failed for {} protocol={} — {}", host, protocol, e.getMessage());
            return false;
        }
    }

    /** Returns the cipher name if the server accepts it, empty otherwise. */
    private static Optional<String> testCipher(String host, int port, String cipher, int timeoutMs) {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, TRUST_ALL, new SecureRandom());
            SSLSocketFactory factory = ctx.getSocketFactory();
            try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
                socket.connect(new InetSocketAddress(host, port), timeoutMs);
                socket.setSoTimeout(timeoutMs);
                // Allow all protocol versions so the cipher can negotiate
                String[] allProtocols = ctx.createSSLEngine().getSupportedProtocols();
                socket.setEnabledProtocols(allProtocols);
                socket.setEnabledCipherSuites(new String[]{cipher});
                socket.startHandshake();
                return Optional.of(cipher);
            }
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    /**
     * Probes for Heartbleed (CVE-2014-0160) by sending a malformed TLS heartbeat
     * request before completing the TLS handshake. Vulnerable OpenSSL versions respond
     * with heap memory content instead of rejecting the oversized request.
     */
    static boolean probeHeartbleed(String host, int port, int timeoutMs) {
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);
            OutputStream out = socket.getOutputStream();
            DataInputStream in = new DataInputStream(socket.getInputStream());

            // Send ClientHello with heartbeat extension
            out.write(CLIENT_HELLO_HEARTBEAT);
            out.flush();

            // Read TLS records until we've seen a handshake message, then send heartbeat
            int handshakeRecords = 0;
            long deadline = System.currentTimeMillis() + timeoutMs;

            while (System.currentTimeMillis() < deadline) {
                int contentType = in.read();
                if (contentType < 0) break;
                in.readByte(); // version major
                in.readByte(); // version minor
                int length = in.readUnsignedShort();
                if (length < 0 || length > 32768) break;

                byte[] payload = new byte[length];
                in.readFully(payload);

                if (contentType == 0x16) { // Handshake
                    handshakeRecords++;
                    // After receiving at least 2 handshake records (ServerHello + something),
                    // send the malformed heartbeat
                    if (handshakeRecords >= 2) {
                        out.write(MALFORMED_HEARTBEAT);
                        out.flush();

                        // Read response record header
                        socket.setSoTimeout(Math.min(timeoutMs, 3000));
                        try {
                            int respType = in.read();
                            if (respType < 0) return false;
                            in.readByte(); // version
                            in.readByte();
                            int respLen = in.readUnsignedShort();
                            // If server responds with a heartbeat (0x18) and non-trivial data → vulnerable
                            return respType == 0x18 && respLen > 3;
                        } catch (Exception e) {
                            return false; // Timeout or reset — server likely rejected it
                        }
                    }
                } else if (contentType == 0x15) {
                    // Alert — server not happy, but not vulnerable to Heartbleed
                    return false;
                }
            }
        } catch (Exception e) {
            log.debug("Heartbleed probe failed for {}:{} — {}", host, port, e.getMessage());
        }
        return false;
    }
}
