package com.portscanner.plugin.builtin;

import com.portscanner.model.ScanResult;
import com.portscanner.plugin.PluginContext;
import com.portscanner.plugin.ScanPlugin;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Set;

/**
 * Plugin that retrieves SSL/TLS certificate information and summarises it in the banner.
 * Skips the port if TLS info is already populated by the main TLS inspector.
 */
public class SslCertPlugin implements ScanPlugin {

    private static final Set<Integer> SSL_PORTS = Set.of(443, 8443);

    @Override
    public String name() {
        return "ssl-cert";
    }

    @Override
    public boolean appliesTo(ScanResult result) {
        if (SSL_PORTS.contains(result.getPort())) {
            return true;
        }
        String service = result.getServiceName();
        return service != null && service.toLowerCase().contains("https");
    }

    @Override
    public void execute(ScanResult result, PluginContext ctx) {
        // Skip if TLS info already populated by the main TLS inspector
        if (result.getTlsInfo() != null) {
            return;
        }

        try {
            String host = ctx.getHost();
            int port = result.getPort();
            int timeout = ctx.getTimeoutMs();

            SSLSocket sslSocket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            sslSocket.connect(new java.net.InetSocketAddress(host, port), timeout);
            sslSocket.setSoTimeout(timeout);

            try (sslSocket) {
                sslSocket.startHandshake();
                Certificate[] certs = sslSocket.getSession().getPeerCertificates();
                if (certs.length > 0 && certs[0] instanceof X509Certificate x509) {
                    String subject = x509.getSubjectX500Principal().getName();
                    String cn = extractCn(subject);
                    LocalDate expiry = x509.getNotAfter()
                            .toInstant()
                            .atZone(ZoneId.systemDefault())
                            .toLocalDate();
                    result.setBanner("SSL: CN=" + cn + " expires " + expiry);
                }
            }
        } catch (Exception e) {
            // Silently ignore — plugin failures must not disrupt the scan
        }
    }

    private String extractCn(String dn) {
        if (dn == null) return "unknown";
        for (String part : dn.split(",")) {
            String trimmed = part.trim();
            if (trimmed.startsWith("CN=")) {
                return trimmed.substring(3);
            }
        }
        return dn;
    }
}
