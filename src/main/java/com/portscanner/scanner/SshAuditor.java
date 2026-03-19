package com.portscanner.scanner;

import com.portscanner.model.SshAuditResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * SSH algorithm auditor — parses the SSH Key Exchange Init (SSH_MSG_KEXINIT)
 * message per RFC 4253 §7.1 and flags weak or deprecated algorithms.
 * No authentication or key exchange is required; KEXINIT is sent in cleartext.
 */
public class SshAuditor {

    private static final Logger log = LoggerFactory.getLogger(SshAuditor.class);

    private static final String CLIENT_VERSION_BANNER = "SSH-2.0-PortScanner_2.0\r\n";
    private static final byte SSH_MSG_KEXINIT = 20;

    // Weak key exchange algorithms (Logjam, deprecated SHA-1)
    private static final Map<String, String> WEAK_KEX = Map.of(
            "diffie-hellman-group1-sha1",           "Logjam attack risk — 1024-bit MODP group (CVE-2015-4000)",
            "diffie-hellman-group-exchange-sha1",   "SHA-1 is cryptographically deprecated",
            "diffie-hellman-group14-sha1",          "SHA-1 is cryptographically deprecated",
            "gss-group1-sha1-toWIV3g8ImE=",        "1024-bit MODP group with SHA-1"
    );

    // Weak host key types
    private static final Set<String> WEAK_HOST_KEY = Set.of(
            "ssh-dss",    // DSA 1024-bit — NIST deprecated
            "ssh-rsa"     // RSA with SHA-1 — deprecated by OpenSSH 8.8+
    );

    // Weak / deprecated encryption algorithms
    private static final Set<String> WEAK_ENCRYPTION = Set.of(
            "arcfour", "arcfour128", "arcfour256",     // RC4 — broken
            "3des-cbc",                                 // SWEET32 / 64-bit block cipher
            "blowfish-cbc",                             // 64-bit block cipher
            "cast128-cbc",                              // 64-bit block cipher
            "aes128-cbc", "aes192-cbc", "aes256-cbc",  // CBC mode — BEAST-related
            "none"                                      // No encryption
    );

    // Weak MAC algorithms
    private static final Set<String> WEAK_MAC = Set.of(
            "hmac-md5",           "hmac-md5-96",
            "hmac-sha1",          "hmac-sha1-96",
            "umac-64@openssh.com", "umac-64",
            "none"
    );

    public static Optional<SshAuditResult> audit(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            // Read server version banner (ASCII line ending in \r\n or \n)
            String serverVersion = readVersionBanner(in);
            if (serverVersion == null || !serverVersion.startsWith("SSH-")) {
                return Optional.empty();
            }

            // Send our client version banner
            out.write(CLIENT_VERSION_BANNER.getBytes(StandardCharsets.UTF_8));
            out.flush();

            // Read the server's SSH_MSG_KEXINIT packet
            byte[] payload = readSshPacket(in);
            if (payload == null || payload.length == 0 || payload[0] != SSH_MSG_KEXINIT) {
                return Optional.empty();
            }

            // Parse KEXINIT: skip msg_type (1 byte) + cookie (16 bytes) = 17 bytes
            if (payload.length < 17) return Optional.empty();
            DataInputStream dis = new DataInputStream(
                    new ByteArrayInputStream(payload, 17, payload.length - 17));

            List<String> kexAlgorithms      = readNameList(dis);
            List<String> hostKeyAlgorithms   = readNameList(dis);
            List<String> encClientToServer   = readNameList(dis);
            List<String> encServerToClient   = readNameList(dis); // parallel list, we audit c2s only
            List<String> macClientToServer   = readNameList(dis);

            // ── Identify weak algorithms ────────────────────────────────────
            List<String> weakAlgorithms = new ArrayList<>();

            for (String kex : kexAlgorithms) {
                if (WEAK_KEX.containsKey(kex)) {
                    weakAlgorithms.add("KEX: " + kex + " — " + WEAK_KEX.get(kex));
                }
            }
            for (String hk : hostKeyAlgorithms) {
                if (WEAK_HOST_KEY.contains(hk)) {
                    String reason = hk.equals("ssh-dss")
                            ? "DSA 1024-bit is deprecated (NIST SP 800-131A)"
                            : "ssh-rsa uses SHA-1 which is deprecated (OpenSSH 8.8+ disables it)";
                    weakAlgorithms.add("HostKey: " + hk + " — " + reason);
                }
            }
            for (String enc : encClientToServer) {
                if (WEAK_ENCRYPTION.contains(enc)) {
                    weakAlgorithms.add("Cipher: " + enc + " — deprecated or weak");
                }
            }
            for (String mac : macClientToServer) {
                if (WEAK_MAC.contains(mac)) {
                    weakAlgorithms.add("MAC: " + mac + " — deprecated or weak");
                }
            }

            List<String> recommendations = buildRecommendations(
                    kexAlgorithms, hostKeyAlgorithms, encClientToServer, macClientToServer);

            return Optional.of(SshAuditResult.builder()
                    .serverVersion(serverVersion.trim())
                    .kexAlgorithms(kexAlgorithms.isEmpty() ? null : kexAlgorithms)
                    .hostKeyAlgorithms(hostKeyAlgorithms.isEmpty() ? null : hostKeyAlgorithms)
                    .encryptionAlgorithms(encClientToServer.isEmpty() ? null : encClientToServer)
                    .macAlgorithms(macClientToServer.isEmpty() ? null : macClientToServer)
                    .weakAlgorithms(weakAlgorithms.isEmpty() ? null : weakAlgorithms)
                    .recommendations(recommendations.isEmpty() ? null : recommendations)
                    .build());

        } catch (Exception e) {
            log.debug("SSH audit failed for {}:{} — {}", host, port, e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Reads the SSH version banner (first line). May skip comment lines starting with "SSH-".
     * Returns null if no valid version banner is found within the timeout.
     */
    static String readVersionBanner(InputStream in) {
        try {
            StringBuilder sb = new StringBuilder();
            int ch;
            while ((ch = in.read()) != -1) {
                if (ch == '\n') {
                    String line = sb.toString().replace("\r", "");
                    if (line.startsWith("SSH-")) return line;
                    sb.setLength(0); // skip comment line
                } else {
                    sb.append((char) ch);
                    if (sb.length() > 255) break; // Sanity: banner can't be longer than 255 chars (RFC 4253)
                }
            }
        } catch (Exception e) {
            log.debug("Error reading SSH version banner: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Reads one SSH binary packet per RFC 4253 §6 and returns the payload bytes.
     * (No MAC is present at this stage since key exchange hasn't completed.)
     */
    static byte[] readSshPacket(InputStream in) {
        try {
            DataInputStream din = new DataInputStream(in);
            int packetLen = din.readInt();
            if (packetLen < 2 || packetLen > 65536) return null;
            int paddingLen = din.readUnsignedByte();
            int payloadLen = packetLen - paddingLen - 1;
            if (payloadLen < 1 || payloadLen > packetLen) return null;
            byte[] payload = new byte[payloadLen];
            din.readFully(payload);
            if (paddingLen > 0) din.skipNBytes(paddingLen);
            return payload;
        } catch (Exception e) {
            log.debug("Error reading SSH packet: {}", e.getMessage());
            return null;
        }
    }

    /** Parses a SSH name-list (uint32 length + UTF-8 comma-separated names). */
    static List<String> readNameList(DataInputStream dis) {
        try {
            int len = dis.readInt();
            if (len < 0 || len > 65535) return List.of();
            if (len == 0) return List.of();
            byte[] bytes = new byte[len];
            dis.readFully(bytes);
            return Arrays.asList(new String(bytes, StandardCharsets.UTF_8).split(","));
        } catch (Exception e) {
            return List.of();
        }
    }

    private static List<String> buildRecommendations(
            List<String> kex, List<String> hostKey, List<String> enc, List<String> mac) {
        List<String> recs = new ArrayList<>();
        boolean hasWeakKex = kex.stream().anyMatch(WEAK_KEX::containsKey);
        boolean hasWeakHostKey = hostKey.stream().anyMatch(WEAK_HOST_KEY::contains);
        boolean hasWeakEnc = enc.stream().anyMatch(WEAK_ENCRYPTION::contains);
        boolean hasWeakMac = mac.stream().anyMatch(WEAK_MAC::contains);

        if (hasWeakKex) {
            recs.add("Replace weak kex algorithms with curve25519-sha256 or ecdh-sha2-nistp256");
        }
        if (hasWeakHostKey) {
            recs.add("Add ssh-ed25519 and rsa-sha2-256/rsa-sha2-512 host key types");
        }
        if (hasWeakEnc) {
            recs.add("Disable CBC and RC4 ciphers; prefer chacha20-poly1305@openssh.com and aes256-gcm@openssh.com");
        }
        if (hasWeakMac) {
            recs.add("Disable MD5 and SHA-1 MACs; prefer hmac-sha2-256-etm@openssh.com and umac-128-etm@openssh.com");
        }
        if (!recs.isEmpty()) {
            recs.add("Reference: https://ssh-audit.com for a full configuration guide");
        }
        return recs;
    }
}
