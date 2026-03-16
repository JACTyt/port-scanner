package com.portscanner.cli;

import com.portscanner.db.ScanHistoryDao;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import com.portscanner.report.DiffReport;
import com.portscanner.report.ReportDiffer;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

/**
 * {@code portscanner history} — show scan history for a given host.
 *
 * <p>Example usage:
 * <pre>
 *   portscanner history --host 192.168.1.1
 *   portscanner history --host 192.168.1.1 --last 5 --diff
 * </pre>
 */
@Command(
        name = "history",
        mixinStandardHelpOptions = true,
        description = "Show scan history for a host stored in ~/.portscanner/history.db"
)
public class HistoryCommand implements Callable<Integer> {

    @Option(names = {"--host", "-h"}, required = true,
            description = "Host to retrieve history for")
    private String host;

    @Option(names = {"--last"}, defaultValue = "10",
            description = "Number of most recent scans to show. Default: 10")
    private int last;

    @Option(names = {"--diff"},
            description = "Show port changes between consecutive scans in the history")
    private boolean diff;

    @Override
    public Integer call() {
        ScanHistoryDao dao = new ScanHistoryDao();
        List<ScanReport> history = dao.getHistory(host, last);

        if (history.isEmpty()) {
            System.out.println("No scan history found for: " + host);
            System.out.println("Run a scan with --save-history to record results.");
            return 0;
        }

        System.out.printf("Scan history for %s (%d scan(s)):%n%n", host, history.size());
        System.out.printf("%-4s %-20s %-10s %-6s %s%n", "#", "DATE", "DURATION", "OPEN", "OPEN PORTS");
        System.out.println("-".repeat(70));

        for (int i = 0; i < history.size(); i++) {
            ScanReport r = history.get(i);
            String date = r.getScannedAt() != null
                    ? r.getScannedAt().toString().replace('T', ' ').substring(0, 16)
                    : "unknown";
            String portList = r.getOpenPorts() != null && !r.getOpenPorts().isEmpty()
                    ? r.getOpenPorts().stream()
                            .map(sr -> String.valueOf(sr.getPort()))
                            .collect(Collectors.joining(","))
                    : "(none)";
            System.out.printf("%-4d %-20s %-10s %-6d %s%n",
                    i + 1, date, r.getDurationMs() + "ms", r.getOpenCount(), portList);
        }

        if (diff && history.size() >= 2) {
            System.out.println();
            System.out.println("Port changes between consecutive scans:");
            System.out.println("-".repeat(70));
            ReportDiffer differ = new ReportDiffer();

            for (int i = 0; i < history.size() - 1; i++) {
                ScanReport newer = history.get(i);       // newer is index i (sorted desc)
                ScanReport older = history.get(i + 1);   // older is index i+1

                DiffReport d = differ.diff(older, newer,
                        "scan #" + (i + 2), "scan #" + (i + 1));

                String newerDate = newer.getScannedAt() != null
                        ? newer.getScannedAt().toString().replace('T', ' ').substring(0, 16)
                        : "scan #" + (i + 1);

                System.out.println("  Scan #" + (i + 1) + " vs #" + (i + 2) + " (" + newerDate + "):");

                if (!d.getNewOpenPorts().isEmpty()) {
                    System.out.println("    NEW: " + formatPorts(d.getNewOpenPorts()));
                }
                if (!d.getClosedPorts().isEmpty()) {
                    System.out.println("    CLOSED: " + formatPorts(d.getClosedPorts()));
                }
                if (d.getNewOpenPorts().isEmpty() && d.getClosedPorts().isEmpty()) {
                    System.out.println("    No changes.");
                }
            }
        }

        return 0;
    }

    private String formatPorts(List<ScanResult> ports) {
        return ports.stream()
                .map(r -> r.getPort() + "/" + nvl(r.getServiceName()))
                .collect(Collectors.joining(", "));
    }

    private String nvl(String s) {
        return s != null ? s : "?";
    }
}
