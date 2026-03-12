package com.portscanner.scanner.probe;

import java.util.HashMap;
import java.util.Map;

public class ProbeRegistry {

    private static final Map<Integer, Probe> PORT_PROBES = new HashMap<>();

    static {
        PORT_PROBES.put(80, new HttpProbe());
        PORT_PROBES.put(8080, new HttpProbe());
        PORT_PROBES.put(8443, new HttpProbe());
        PORT_PROBES.put(8000, new HttpProbe());
        PORT_PROBES.put(8888, new HttpProbe());
        PORT_PROBES.put(25, new SmtpProbe());
        PORT_PROBES.put(465, new SmtpProbe());
        PORT_PROBES.put(587, new SmtpProbe());
        PORT_PROBES.put(21, new FtpProbe());
        PORT_PROBES.put(20, new FtpProbe());
        PORT_PROBES.put(22, new SshProbe());
        PORT_PROBES.put(6379, new RedisProbe());
        PORT_PROBES.put(11211, new MemcachedProbe());
        PORT_PROBES.put(3306, new MysqlProbe());
        PORT_PROBES.put(5432, new PostgresProbe());
    }

    public static Probe getProbe(int port) {
        return PORT_PROBES.getOrDefault(port, new GenericProbe());
    }
}
