package com.portscanner.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class ServiceMapper {

    private final Map<Integer, String> portMap;

    public ServiceMapper() {
        Map<Integer, String> map = new HashMap<>();
        try (InputStream is = ServiceMapper.class.getResourceAsStream("/services.json")) {
            if (is != null) {
                ObjectMapper objectMapper = new ObjectMapper();
                Map<String, String> raw = objectMapper.readValue(is, new TypeReference<>() {});
                for (Map.Entry<String, String> entry : raw.entrySet()) {
                    map.put(Integer.parseInt(entry.getKey()), entry.getValue());
                }
            } else {
                System.err.println("Warning: services.json not found on classpath");
            }
        } catch (Exception e) {
            System.err.println("Warning: failed to load services.json — " + e.getMessage());
        }
        this.portMap = Collections.unmodifiableMap(map);
    }

    public String getService(int port) {
        return portMap.getOrDefault(port, "Unknown");
    }

    public boolean isKnown(int port) {
        return portMap.containsKey(port);
    }
}
