package com.portscanner.api;

import com.portscanner.api.dto.ScanRequest;
import com.portscanner.api.dto.ScanResponse;
import com.portscanner.model.ScanReport;
import com.portscanner.scanner.PortScanner;
import com.portscanner.service.ServiceMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.Proxy;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.UnaryOperator;

public class ScanJobManager {

    private static final Logger log = LoggerFactory.getLogger(ScanJobManager.class);
    private static final int MAX_HISTORY = 50;

    private final Map<String, ScanResponse> jobs = new ConcurrentHashMap<>();
    private final List<String> jobOrder = new CopyOnWriteArrayList<>();
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    private final ServiceMapper serviceMapper = new ServiceMapper();

    public ScanResponse submit(ScanRequest req) {
        String id = UUID.randomUUID().toString().substring(0, 8);
        ScanResponse response = ScanResponse.builder()
                .id(id)
                .host(req.getHost())
                .status("PENDING")
                .submittedAt(now())
                .build();
        jobs.put(id, response);
        jobOrder.add(0, id);
        if (jobOrder.size() > MAX_HISTORY) {
            String oldId = jobOrder.remove(jobOrder.size() - 1);
            jobs.remove(oldId);
        }
        executor.submit(() -> runScan(id, req));
        return response;
    }

    private void runScan(String id, ScanRequest req) {
        update(id, b -> b.status("RUNNING"));
        try {
            InetAddress addr = InetAddress.getByName(req.getHost());
            int[] ports = parsePorts(req.getPorts() != null ? req.getPorts() : "1-1024");
            int timeout = req.getTimeout() > 0 ? req.getTimeout() : 200;
            int threads = Math.min(req.getThreads() > 0 ? req.getThreads() : 100, 1000);
            PortScanner scanner = new PortScanner(threads, timeout, req.isBanner(),
                    serviceMapper, false, 0, Proxy.NO_PROXY);
            ScanReport report = scanner.scan(req.getHost(), addr, ports);
            update(id, b -> b.status("DONE").result(report).completedAt(now()));
        } catch (Exception e) {
            log.error("Scan {} failed: {}", id, e.getMessage());
            update(id, b -> b.status("FAILED").error(e.getMessage()).completedAt(now()));
        }
    }

    public ScanResponse get(String id) {
        return jobs.get(id);
    }

    public List<ScanResponse> listRecent() {
        List<ScanResponse> result = new ArrayList<>();
        for (String id : jobOrder) {
            ScanResponse r = jobs.get(id);
            if (r != null) result.add(r);
        }
        return result;
    }

    public boolean cancel(String id) {
        ScanResponse r = jobs.get(id);
        if (r == null) return false;
        if ("RUNNING".equals(r.getStatus()) || "PENDING".equals(r.getStatus())) {
            update(id, b -> b.status("CANCELLED").completedAt(now()));
            return true;
        }
        return false;
    }

    public void shutdown() {
        executor.shutdownNow();
    }

    private void update(String id, UnaryOperator<ScanResponse.ScanResponseBuilder> fn) {
        ScanResponse current = jobs.get(id);
        if (current == null) return;
        jobs.put(id, fn.apply(current.toBuilder()).build());
    }

    private static String now() {
        return LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
    }

    private static int[] parsePorts(String portRange) {
        if (!portRange.contains(",") && portRange.contains("-")) {
            String[] p = portRange.split("-", 2);
            int start = Integer.parseInt(p[0].trim());
            int end   = Integer.parseInt(p[1].trim());
            int[] arr = new int[end - start + 1];
            for (int i = 0; i < arr.length; i++) arr[i] = start + i;
            return arr;
        } else if (portRange.contains(",")) {
            String[] parts = portRange.split(",");
            List<Integer> list = new ArrayList<>();
            for (String p : parts) list.add(Integer.parseInt(p.trim()));
            return list.stream().mapToInt(Integer::intValue).toArray();
        } else {
            return new int[]{Integer.parseInt(portRange.trim())};
        }
    }
}
