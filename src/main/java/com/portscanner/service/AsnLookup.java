package com.portscanner.service;

import com.portscanner.model.AsnInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;
import java.util.Optional;

public class AsnLookup {

    private static final Logger log = LoggerFactory.getLogger(AsnLookup.class);

    public static Optional<AsnInfo> lookup(String ip) {
        try {
            String reversed = reverseIp(ip);
            String queryHost = reversed + ".origin.asn.cymru.com";

            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            env.put("com.sun.jndi.dns.timeout.initial", "3000");
            env.put("com.sun.jndi.dns.timeout.retries", "1");
            DirContext ctx = new InitialDirContext(env);

            Attributes attrs = ctx.getAttributes(queryHost, new String[]{"TXT"});
            javax.naming.NamingEnumeration<?> txtEnum = attrs.get("TXT").getAll();
            if (!txtEnum.hasMore()) return Optional.empty();

            String txt = stripQuotes(String.valueOf(txtEnum.next()));
            // Format: "15169 | 8.8.8.0/24 | US | arin | 2000-03-30"
            String[] parts = txt.split("\\|");
            if (parts.length < 4) return Optional.empty();

            String asn = parts[0].trim();
            String prefix = parts[1].trim();
            String country = parts[2].trim();
            String registry = parts[3].trim();

            // Second query for org name
            String orgName = lookupOrgName(asn, ctx);

            return Optional.of(AsnInfo.builder()
                    .asn("AS" + asn)
                    .prefix(prefix)
                    .country(country)
                    .registry(registry)
                    .name(orgName)
                    .build());
        } catch (Exception e) {
            log.debug("ASN lookup failed for {}: {}", ip, e.getMessage());
            return Optional.empty();
        }
    }

    private static String lookupOrgName(String asn, DirContext ctx) {
        try {
            String asnQuery = "AS" + asn + ".asn.cymru.com";
            Attributes attrs = ctx.getAttributes(asnQuery, new String[]{"TXT"});
            javax.naming.NamingEnumeration<?> txtEnum = attrs.get("TXT").getAll();
            if (!txtEnum.hasMore()) return null;

            String txt = stripQuotes(String.valueOf(txtEnum.next()));
            // Format: "15169 | ARIN | 2000-03-30 | US | Google LLC"
            String[] parts = txt.split("\\|");
            if (parts.length >= 5) {
                return parts[4].trim();
            } else if (parts.length >= 2) {
                return parts[1].trim();
            }
            return null;
        } catch (Exception e) {
            log.debug("ASN org lookup failed for AS{}: {}", asn, e.getMessage());
            return null;
        }
    }

    static String reverseIp(String ip) {
        String[] octets = ip.split("\\.");
        if (octets.length != 4) return ip;
        return octets[3] + "." + octets[2] + "." + octets[1] + "." + octets[0];
    }

    static Optional<AsnInfo> parseTxtRecord(String txt) {
        String clean = stripQuotes(txt);
        String[] parts = clean.split("\\|");
        if (parts.length < 4) return Optional.empty();
        return Optional.of(AsnInfo.builder()
                .asn("AS" + parts[0].trim())
                .prefix(parts[1].trim())
                .country(parts[2].trim())
                .registry(parts[3].trim())
                .build());
    }

    private static String stripQuotes(String s) {
        if (s == null) return "";
        s = s.trim();
        if (s.startsWith("\"") && s.endsWith("\"")) {
            s = s.substring(1, s.length() - 1);
        }
        return s;
    }
}
