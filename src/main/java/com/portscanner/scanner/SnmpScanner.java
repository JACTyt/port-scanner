package com.portscanner.scanner;

import com.portscanner.model.SnmpInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Performs SNMP GET queries against UDP port 161 using SNMPv2c.
 *
 * <p>Retrieves the standard MIB-II system group OIDs:
 * sysDescr, sysName, sysLocation, sysContact, and ifNumber.
 * Tries each community string in turn and returns on the first success.
 */
public class SnmpScanner {

    private static final Logger log = LoggerFactory.getLogger(SnmpScanner.class);

    // Standard MIB-II system OIDs
    private static final OID OID_SYS_DESCR    = new OID("1.3.6.1.2.1.1.1.0");
    private static final OID OID_SYS_NAME      = new OID("1.3.6.1.2.1.1.5.0");
    private static final OID OID_SYS_LOCATION  = new OID("1.3.6.1.2.1.1.6.0");
    private static final OID OID_SYS_CONTACT   = new OID("1.3.6.1.2.1.1.4.0");
    private static final OID OID_IF_NUMBER     = new OID("1.3.6.1.2.1.2.1.0");

    private static final int SNMP_PORT    = 161;
    private static final int SNMP_RETRIES = 1;

    private final int timeoutMs;
    private final List<String> communities;

    /**
     * @param timeoutMs   per-community probe timeout in milliseconds
     * @param communities community strings to try (in order)
     */
    public SnmpScanner(int timeoutMs, List<String> communities) {
        this.timeoutMs   = timeoutMs;
        this.communities = communities.isEmpty() ? List.of("public", "private") : communities;
    }

    /**
     * Probe a host and return an {@link SnmpInfo} if an SNMP agent responds,
     * or {@link Optional#empty()} if the host does not respond to any community.
     */
    public Optional<SnmpInfo> probe(InetAddress target) {
        for (String community : communities) {
            Optional<SnmpInfo> result = tryGet(target, community);
            if (result.isPresent()) return result;
        }
        return Optional.empty();
    }

    private Optional<SnmpInfo> tryGet(InetAddress target, String community) {
        try (Snmp snmp = new Snmp(new DefaultUdpTransportMapping())) {
            snmp.listen();

            CommunityTarget<UdpAddress> ct = new CommunityTarget<>();
            ct.setCommunity(new OctetString(community));
            ct.setAddress(new UdpAddress(target, SNMP_PORT));
            ct.setVersion(SnmpConstants.version2c);
            ct.setTimeout(timeoutMs);
            ct.setRetries(SNMP_RETRIES);

            PDU pdu = new PDU();
            pdu.setType(PDU.GET);
            pdu.add(new VariableBinding(OID_SYS_DESCR));
            pdu.add(new VariableBinding(OID_SYS_NAME));
            pdu.add(new VariableBinding(OID_SYS_LOCATION));
            pdu.add(new VariableBinding(OID_SYS_CONTACT));
            pdu.add(new VariableBinding(OID_IF_NUMBER));
            pdu.setRequestID(new Integer32(1));

            ResponseEvent<?> event = snmp.get(pdu, ct);
            if (event == null || event.getResponse() == null) return Optional.empty();

            PDU response = event.getResponse();
            if (response.getErrorStatus() != PDU.noError) {
                log.debug("SNMP error from {}: {}", target.getHostAddress(), response.getErrorStatusText());
            }

            SnmpInfo.SnmpInfoBuilder info = SnmpInfo.builder().community(community);
            for (VariableBinding vb : response.getVariableBindings()) {
                String val = vb.getVariable().toString();
                OID oid = vb.getOid();
                if (OID_SYS_DESCR.equals(oid))   info.sysDescr(val);
                else if (OID_SYS_NAME.equals(oid))     info.sysName(val);
                else if (OID_SYS_LOCATION.equals(oid)) info.sysLocation(val);
                else if (OID_SYS_CONTACT.equals(oid))  info.sysContact(val);
                else if (OID_IF_NUMBER.equals(oid)) {
                    try { info.interfaceCount(Integer.parseInt(val)); } catch (NumberFormatException ignored) {}
                }
            }
            return Optional.of(info.build());

        } catch (IOException e) {
            log.debug("SNMP probe to {} with community '{}' failed: {}", target.getHostAddress(), community, e.getMessage());
            return Optional.empty();
        }
    }

    // ── Convenience factory ───────────────────────────────────────────────────

    /** Parse comma-separated community strings from a CLI value. */
    public static List<String> parseCommunities(String raw) {
        if (raw == null || raw.isBlank()) return List.of("public", "private");
        List<String> result = new ArrayList<>();
        for (String c : raw.split(",")) {
            String trimmed = c.trim();
            if (!trimmed.isEmpty()) result.add(trimmed);
        }
        return result.isEmpty() ? List.of("public", "private") : result;
    }
}
