package com.portscanner.scanner;

import com.portscanner.model.TlsInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;

public class TlsInspector {

    private static final Logger log = LoggerFactory.getLogger(TlsInspector.class);

    private static final List<String> WEAK_CIPHER_PATTERNS = List.of("RC4", "_NULL_", "EXPORT", "_DES_", "3DES");
    private static final List<String> DEPRECATED_PROTOCOLS = List.of("TLSv1", "TLSv1.1", "SSLv3");

    public static Optional<TlsInfo> inspect(String host, int port, int timeoutMs) {
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            try (SSLSocket sslSocket = (SSLSocket) factory.createSocket()) {
                sslSocket.connect(new InetSocketAddress(host, port), timeoutMs);
                sslSocket.setSoTimeout(timeoutMs);
                sslSocket.startHandshake();

                SSLSession session = sslSocket.getSession();
                String protocol = session.getProtocol();
                String cipherSuite = session.getCipherSuite();

                java.security.cert.Certificate[] certs = session.getPeerCertificates();
                if (certs == null || certs.length == 0 || !(certs[0] instanceof X509Certificate)) {
                    return Optional.empty();
                }

                X509Certificate cert = (X509Certificate) certs[0];
                String subject = cert.getSubjectX500Principal().getName();
                String issuer = cert.getIssuerX500Principal().getName();
                Date notAfter = cert.getNotAfter();
                LocalDate expiry = notAfter.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
                LocalDate now = LocalDate.now();

                boolean isExpired = expiry.isBefore(now);
                boolean expiresSoon = !isExpired && expiry.isBefore(now.plusDays(30));
                boolean isSelfSigned = subject.equals(issuer);

                boolean hasWeakCipher = WEAK_CIPHER_PATTERNS.stream()
                        .anyMatch(p -> cipherSuite.contains(p));
                boolean hasDeprecatedProtocol = DEPRECATED_PROTOCOLS.contains(protocol);

                // Extract SANs
                List<String> sans = new ArrayList<>();
                try {
                    Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
                    if (altNames != null) {
                        for (List<?> altName : altNames) {
                            if (altName.size() >= 2) {
                                Integer type = (Integer) altName.get(0);
                                // type 2 = DNS, type 7 = IP
                                if (type == 2 || type == 7) {
                                    sans.add(String.valueOf(altName.get(1)));
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    log.debug("Could not extract SANs: {}", e.getMessage());
                }

                return Optional.of(TlsInfo.builder()
                        .protocol(protocol)
                        .cipherSuite(cipherSuite)
                        .certSubject(subject)
                        .certIssuer(issuer)
                        .certExpiry(expiry)
                        .subjectAltNames(sans.isEmpty() ? null : sans)
                        .expired(isExpired)
                        .expiresSoon(expiresSoon)
                        .selfSigned(isSelfSigned)
                        .weakCipher(hasWeakCipher)
                        .deprecatedProtocol(hasDeprecatedProtocol)
                        .build());
            }
        } catch (Exception e) {
            log.debug("TLS inspection failed for {}:{} — {}", host, port, e.getMessage());
            return Optional.empty();
        }
    }
}
