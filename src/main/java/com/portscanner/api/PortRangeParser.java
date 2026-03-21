package com.portscanner.api;

import java.util.ArrayList;
import java.util.List;

/**
 * Shared port-range parser with 1–65535 bounds validation.
 * Parses "80,443,8080" (list), "1-1024" (range), or "443" (single port).
 */
public final class PortRangeParser {

    private PortRangeParser() {}

    public static int[] parse(String spec) {
        if (spec == null || spec.isBlank()) throw new IllegalArgumentException("Port spec must not be blank");

        if (spec.contains("-") && !spec.contains(",")) {
            String[] parts = spec.split("-", 2);
            int from = parseInt(parts[0].trim());
            int to   = parseInt(parts[1].trim());
            if (from > to) throw new IllegalArgumentException("Range start must be <= end: " + spec);
            int[] arr = new int[to - from + 1];
            for (int i = 0; i < arr.length; i++) arr[i] = from + i;
            return arr;
        }

        String[] parts = spec.split(",");
        List<Integer> list = new ArrayList<>(parts.length);
        for (String p : parts) list.add(parseInt(p.trim()));
        return list.stream().mapToInt(Integer::intValue).toArray();
    }

    private static int parseInt(String s) {
        int v = Integer.parseInt(s);
        if (v < 1 || v > 65535) throw new IllegalArgumentException("Port out of range (1-65535): " + v);
        return v;
    }
}
