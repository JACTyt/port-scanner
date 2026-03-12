package com.portscanner.scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

/**
 * Discovers local network subnets by inspecting all non-loopback, active network interfaces.
 */
public class NetworkInterfaceScanner {

    private static final Logger log = LoggerFactory.getLogger(NetworkInterfaceScanner.class);

    /**
     * Returns a list of CIDR subnets (e.g. "192.168.1.0/24") for each IPv4 address
     * found on all non-loopback, up network interfaces.
     */
    public List<String> discoverLocalSubnets() {
        List<String> subnets = new ArrayList<>();
        Enumeration<NetworkInterface> interfaces;
        try {
            interfaces = NetworkInterface.getNetworkInterfaces();
        } catch (SocketException e) {
            log.warn("Could not enumerate network interfaces: {}", e.getMessage());
            return subnets;
        }
        if (interfaces == null) return subnets;

        for (NetworkInterface iface : Collections.list(interfaces)) {
            try {
                if (iface.isLoopback() || !iface.isUp()) continue;
            } catch (SocketException e) {
                log.debug("Skipping interface {}: {}", iface.getName(), e.getMessage());
                continue;
            }
            for (InterfaceAddress addr : iface.getInterfaceAddresses()) {
                if (addr.getAddress() instanceof Inet4Address) {
                    int prefix = addr.getNetworkPrefixLength();
                    String networkAddr = computeNetworkAddress(addr.getAddress(), prefix);
                    subnets.add(networkAddr + "/" + prefix);
                    log.debug("Discovered subnet {} on interface {}", networkAddr + "/" + prefix, iface.getName());
                }
            }
        }
        return subnets;
    }

    /**
     * Computes the network address for a given IPv4 address and prefix length.
     * Package-private for testing.
     */
    String computeNetworkAddress(InetAddress addr, int prefixLength) {
        byte[] bytes = addr.getAddress();
        int mask = prefixLength == 0 ? 0 : (0xFFFFFFFF << (32 - prefixLength));
        int ip = ((bytes[0] & 0xFF) << 24) | ((bytes[1] & 0xFF) << 16)
               | ((bytes[2] & 0xFF) << 8)  |  (bytes[3] & 0xFF);
        int network = ip & mask;
        return ((network >> 24) & 0xFF) + "." + ((network >> 16) & 0xFF) + "."
             + ((network >> 8) & 0xFF) + "." + (network & 0xFF);
    }
}
