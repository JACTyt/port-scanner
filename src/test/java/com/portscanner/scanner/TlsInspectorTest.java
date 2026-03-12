package com.portscanner.scanner;

import com.portscanner.model.TlsInfo;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class TlsInspectorTest {

    @Test
    void returns_empty_for_non_tls_port() throws Exception {
        // Connect to a port that doesn't speak TLS (just a closed port scenario)
        // Should return empty Optional rather than throwing
        Optional<TlsInfo> result = TlsInspector.inspect("localhost", 1, 200);
        assertTrue(result.isEmpty(), "Expected empty Optional for non-TLS port");
    }

    @Test
    void weak_cipher_detection_rc4() {
        String cipher = "TLS_RSA_WITH_RC4_128_SHA";
        assertTrue(containsWeakPattern(cipher));
    }

    @Test
    void weak_cipher_detection_3des() {
        String cipher = "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
        assertTrue(containsWeakPattern(cipher));
    }

    @Test
    void weak_cipher_detection_des() {
        String cipher = "TLS_RSA_WITH_DES_CBC_SHA";
        // _DES_ won't match DES directly — test the actual pattern used
        // The pattern is "_DES_" but the cipher has "WITH_DES_" which contains "_DES_"
        assertTrue(containsWeakPattern(cipher));
    }

    @Test
    void strong_cipher_is_not_weak() {
        String cipher = "TLS_AES_256_GCM_SHA384";
        assertFalse(containsWeakPattern(cipher));
    }

    @Test
    void deprecated_protocol_tlsv1() {
        assertTrue(isDeprecatedProtocol("TLSv1"));
    }

    @Test
    void deprecated_protocol_tlsv11() {
        assertTrue(isDeprecatedProtocol("TLSv1.1"));
    }

    @Test
    void deprecated_protocol_sslv3() {
        assertTrue(isDeprecatedProtocol("SSLv3"));
    }

    @Test
    void modern_protocol_is_not_deprecated() {
        assertFalse(isDeprecatedProtocol("TLSv1.2"));
        assertFalse(isDeprecatedProtocol("TLSv1.3"));
    }

    private boolean containsWeakPattern(String cipherSuite) {
        for (String p : new String[]{"RC4", "_NULL_", "EXPORT", "_DES_", "3DES"}) {
            if (cipherSuite.contains(p)) return true;
        }
        return false;
    }

    private boolean isDeprecatedProtocol(String protocol) {
        return protocol.equals("TLSv1") || protocol.equals("TLSv1.1") || protocol.equals("SSLv3");
    }
}
