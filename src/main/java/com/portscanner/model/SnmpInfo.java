package com.portscanner.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * SNMP system information retrieved via SNMPv2c GET/WALK.
 * Populated by {@code SnmpScanner} when {@code --protocol snmp} is used.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SnmpInfo {
    /** OID 1.3.6.1.2.1.1.1.0 — full system description string. */
    private String sysDescr;
    /** OID 1.3.6.1.2.1.1.5.0 — configured system name. */
    private String sysName;
    /** OID 1.3.6.1.2.1.1.6.0 — physical location. */
    private String sysLocation;
    /** OID 1.3.6.1.2.1.1.4.0 — administrative contact. */
    private String sysContact;
    /** OID 1.3.6.1.2.1.2.1.0 — number of network interfaces. */
    private Integer interfaceCount;
    /** Community string that produced a successful response. */
    private String community;
}
