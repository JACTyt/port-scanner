package com.portscanner.scanner;

import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddress;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Enumerates host addresses from an IPv6 CIDR block using the ipaddress library.
 * Enforces a maximum of 65536 addresses to prevent memory exhaustion on large subnets.
 */
public class IPv6CidrEnumerator {

    public static final int MAX_HOSTS = 65536;

    /** Returns true if the given CIDR string contains a colon — indicating IPv6. */
    public static boolean isIPv6Cidr(String cidr) {
        return cidr != null && cidr.contains(":");
    }

    /**
     * Enumerates addresses from an IPv6 CIDR (e.g., "2001:db8::/120").
     * Returns at most {@link #MAX_HOSTS} addresses.
     *
     * @throws IllegalArgumentException if the CIDR is not a valid IPv6 block
     */
    public static List<String> enumerate(String cidr) {
        IPAddressString addrStr = new IPAddressString(cidr);
        if (!addrStr.isValid()) {
            throw new IllegalArgumentException("Invalid IPv6 CIDR: " + cidr);
        }
        IPAddress address = addrStr.getAddress();
        if (address == null || !address.isIPv6()) {
            throw new IllegalArgumentException("Not an IPv6 address: " + cidr);
        }

        IPAddress network = address.toPrefixBlock();
        List<String> hosts = new ArrayList<>();
        Iterator<? extends IPAddress> it = network.iterator();
        int count = 0;
        while (it.hasNext() && count < MAX_HOSTS) {
            hosts.add(it.next().withoutPrefixLength().toCompressedString());
            count++;
        }
        if (it.hasNext()) {
            System.out.printf("[IPv6] Subnet %s is larger than %d hosts — enumeration capped.%n", cidr, MAX_HOSTS);
        }
        return hosts;
    }
}
