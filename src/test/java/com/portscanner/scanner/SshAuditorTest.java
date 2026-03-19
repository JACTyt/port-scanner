package com.portscanner.scanner;

import com.portscanner.model.SshAuditResult;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SshAuditorTest {

    // ── Model construction ────────────────────────────────────────────────

    @Test
    void ssh_audit_result_builder_all_fields() {
        SshAuditResult r = SshAuditResult.builder()
                .serverVersion("SSH-2.0-OpenSSH_8.9")
                .kexAlgorithms(List.of("curve25519-sha256", "diffie-hellman-group1-sha1"))
                .hostKeyAlgorithms(List.of("ssh-ed25519", "ssh-rsa"))
                .encryptionAlgorithms(List.of("chacha20-poly1305@openssh.com", "aes128-cbc"))
                .macAlgorithms(List.of("umac-128-etm@openssh.com", "hmac-md5"))
                .weakAlgorithms(List.of("KEX: diffie-hellman-group1-sha1 — Logjam"))
                .recommendations(List.of("Replace weak kex algorithms"))
                .build();

        assertEquals("SSH-2.0-OpenSSH_8.9", r.getServerVersion());
        assertEquals(2, r.getKexAlgorithms().size());
        assertEquals(1, r.getWeakAlgorithms().size());
        assertEquals(1, r.getRecommendations().size());
    }

    @Test
    void ssh_audit_result_no_args_constructor() {
        SshAuditResult r = new SshAuditResult();
        assertNull(r.getServerVersion());
        assertNull(r.getWeakAlgorithms());
    }

    // ── Version banner parsing ─────────────────────────────────────────────

    @Test
    void reads_version_banner_simple() throws Exception {
        String banner = "SSH-2.0-OpenSSH_9.0\r\n";
        InputStream in = new ByteArrayInputStream(banner.getBytes(StandardCharsets.UTF_8));
        String result = SshAuditor.readVersionBanner(in);
        assertEquals("SSH-2.0-OpenSSH_9.0", result);
    }

    @Test
    void reads_version_banner_skips_comment_lines() throws Exception {
        String banner = "This is a comment\r\nSSH-2.0-OpenSSH_8.0\r\n";
        InputStream in = new ByteArrayInputStream(banner.getBytes(StandardCharsets.UTF_8));
        String result = SshAuditor.readVersionBanner(in);
        assertEquals("SSH-2.0-OpenSSH_8.0", result);
    }

    @Test
    void reads_version_banner_returns_null_for_empty() throws Exception {
        InputStream in = new ByteArrayInputStream(new byte[0]);
        String result = SshAuditor.readVersionBanner(in);
        assertNull(result);
    }

    // ── SSH packet parsing ─────────────────────────────────────────────────

    @Test
    void reads_ssh_packet_correctly() throws Exception {
        // Build a minimal SSH packet: packet_len=9, padding_len=4, payload="hello"
        byte[] payload = "hello".getBytes(StandardCharsets.UTF_8);
        int paddingLen = 4;
        int packetLen = 1 + payload.length + paddingLen; // padding_len byte + payload + padding
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(packetLen);
        dos.writeByte(paddingLen);
        dos.write(payload);
        dos.write(new byte[paddingLen]); // padding
        dos.flush();

        InputStream in = new ByteArrayInputStream(baos.toByteArray());
        byte[] result = SshAuditor.readSshPacket(in);
        assertNotNull(result);
        assertArrayEquals(payload, result);
    }

    @Test
    void reads_ssh_packet_returns_null_for_invalid_length() throws Exception {
        // packet_len = 0 is invalid (< 2)
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(0); // Invalid
        dos.flush();

        InputStream in = new ByteArrayInputStream(baos.toByteArray());
        byte[] result = SshAuditor.readSshPacket(in);
        assertNull(result);
    }

    // ── Name-list parsing ─────────────────────────────────────────────────

    @Test
    void reads_name_list_correctly() throws Exception {
        String names = "curve25519-sha256,diffie-hellman-group14-sha256";
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(names.length());
        dos.write(names.getBytes(StandardCharsets.UTF_8));
        dos.flush();

        java.io.DataInputStream dis = new java.io.DataInputStream(
                new ByteArrayInputStream(baos.toByteArray()));
        List<String> result = SshAuditor.readNameList(dis);

        assertEquals(2, result.size());
        assertEquals("curve25519-sha256", result.get(0));
        assertEquals("diffie-hellman-group14-sha256", result.get(1));
    }

    @Test
    void reads_empty_name_list() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(0);
        dos.flush();

        java.io.DataInputStream dis = new java.io.DataInputStream(
                new ByteArrayInputStream(baos.toByteArray()));
        List<String> result = SshAuditor.readNameList(dis);
        assertTrue(result.isEmpty());
    }

    // ── Full audit with unreachable host ──────────────────────────────────

    @Test
    void audit_returns_empty_for_non_ssh_port() {
        Optional<SshAuditResult> result = SshAuditor.audit("localhost", 1, 200);
        assertTrue(result.isEmpty());
    }

    @Test
    void audit_returns_empty_for_unreachable_host() {
        Optional<SshAuditResult> result = SshAuditor.audit("192.0.2.1", 22, 100);
        assertTrue(result.isEmpty());
    }

    // ── KEXINIT construction and parsing roundtrip ─────────────────────────

    @Test
    void full_kexinit_roundtrip_detects_weak_algorithms() throws Exception {
        // Build a synthetic KEXINIT payload with a weak kex algorithm
        ByteArrayOutputStream payloadBaos = new ByteArrayOutputStream();
        DataOutputStream payloadDos = new DataOutputStream(payloadBaos);

        payloadDos.writeByte(20); // SSH_MSG_KEXINIT
        payloadDos.write(new byte[16]); // cookie
        writeNameList(payloadDos, "diffie-hellman-group1-sha1,curve25519-sha256"); // kex (has weak one)
        writeNameList(payloadDos, "ssh-ed25519");     // host key
        writeNameList(payloadDos, "aes256-gcm@openssh.com,aes128-cbc"); // enc c2s (has weak one)
        writeNameList(payloadDos, "aes256-gcm@openssh.com"); // enc s2c
        writeNameList(payloadDos, "hmac-sha2-256,hmac-md5");  // mac c2s (has weak one)
        payloadDos.flush();
        byte[] kexinitPayload = payloadBaos.toByteArray();

        // Wrap in SSH packet
        int paddingLen = 8;
        int packetLen = 1 + kexinitPayload.length + paddingLen;
        ByteArrayOutputStream packetBaos = new ByteArrayOutputStream();
        DataOutputStream packetDos = new DataOutputStream(packetBaos);
        packetDos.writeInt(packetLen);
        packetDos.writeByte(paddingLen);
        packetDos.write(kexinitPayload);
        packetDos.write(new byte[paddingLen]);
        packetDos.flush();

        byte[] packet = SshAuditor.readSshPacket(new ByteArrayInputStream(packetBaos.toByteArray()));
        assertNotNull(packet);
        assertEquals(20, packet[0]); // SSH_MSG_KEXINIT

        // Now simulate what audit() does to parse this
        java.io.DataInputStream dis = new java.io.DataInputStream(
                new ByteArrayInputStream(packet, 17, packet.length - 17));
        List<String> kex = SshAuditor.readNameList(dis);
        List<String> hostKey = SshAuditor.readNameList(dis);
        List<String> encC2S = SshAuditor.readNameList(dis);
        List<String> encS2C = SshAuditor.readNameList(dis);
        List<String> macC2S = SshAuditor.readNameList(dis);

        assertTrue(kex.contains("diffie-hellman-group1-sha1"), "Should contain weak kex");
        assertTrue(kex.contains("curve25519-sha256"), "Should contain strong kex");
        assertTrue(encC2S.contains("aes128-cbc"), "Should contain CBC cipher");
        assertTrue(macC2S.contains("hmac-md5"), "Should contain weak MAC");
    }

    private static void writeNameList(DataOutputStream dos, String names) throws Exception {
        byte[] bytes = names.getBytes(StandardCharsets.UTF_8);
        dos.writeInt(bytes.length);
        dos.write(bytes);
    }
}
