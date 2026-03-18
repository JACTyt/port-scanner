package com.portscanner.report;

import com.portscanner.model.MultiHostReport;
import com.portscanner.model.OsGuess;
import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;
import com.portscanner.model.SubnetReport;
import com.portscanner.model.TracerouteHop;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Generates network topology diagrams from scan results.
 *
 * <p>Two output formats are supported, selected by file extension:
 * <ul>
 *   <li>{@code .dot} — Graphviz DOT; render with {@code dot -Tpng topology.dot -o topology.png}</li>
 *   <li>{@code .mmd} — Mermaid; paste into GitHub, GitLab, Obsidian, etc.</li>
 * </ul>
 *
 * <p>Works with a single {@link ScanReport}, a {@link SubnetReport}, or a
 * {@link MultiHostReport}. The file extension of {@code outputPath} selects
 * the format; defaults to Graphviz DOT for unknown extensions.
 */
public class TopologyExporter {

    public void export(ScanReport report, Path outputPath) throws IOException {
        String content = isMermaid(outputPath)
                ? mermaidSingle(report)
                : dotSingle(report);
        Files.writeString(outputPath, content, StandardCharsets.UTF_8);
    }

    public void export(SubnetReport report, Path outputPath) throws IOException {
        String content = isMermaid(outputPath)
                ? mermaidSubnet(report)
                : dotSubnet(report);
        Files.writeString(outputPath, content, StandardCharsets.UTF_8);
    }

    public void export(MultiHostReport report, Path outputPath) throws IOException {
        String content = isMermaid(outputPath)
                ? mermaidMultiHost(report)
                : dotMultiHost(report);
        Files.writeString(outputPath, content, StandardCharsets.UTF_8);
    }

    // ── Graphviz DOT ──────────────────────────────────────────────────────────

    private static String dotSingle(ScanReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("digraph topology {\n");
        sb.append("  graph [rankdir=LR fontname=Helvetica];\n");
        sb.append("  node  [fontname=Helvetica fontsize=11];\n\n");
        sb.append("  scanner [label=\"scanner\" shape=diamond style=filled fillcolor=\"#cce5ff\"];\n");

        String hostId = dotId(report.getHost());
        sb.append("  ").append(hostId).append(" [")
          .append(dotHostAttrs(report)).append("];\n");
        sb.append("  scanner -> ").append(hostId)
          .append(" [label=\"").append(report.getOpenCount()).append(" open\"];\n\n");

        appendDotPorts(sb, hostId, report.getOpenPorts());
        appendDotTraceroute(sb, report);

        sb.append("}\n");
        return sb.toString();
    }

    private static String dotSubnet(SubnetReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("digraph topology {\n");
        sb.append("  graph [rankdir=LR fontname=Helvetica label=\"Subnet: ")
          .append(report.getSubnet()).append("\"];\n");
        sb.append("  node  [fontname=Helvetica fontsize=11];\n\n");
        sb.append("  scanner [label=\"scanner\" shape=diamond style=filled fillcolor=\"#cce5ff\"];\n\n");

        if (report.getHostReports() != null) {
            for (ScanReport hr : report.getHostReports()) {
                if (hr.getOpenCount() == 0) continue;
                String hid = dotId(hr.getHost());
                sb.append("  ").append(hid).append(" [").append(dotHostAttrs(hr)).append("];\n");
                sb.append("  scanner -> ").append(hid)
                  .append(" [label=\"").append(hr.getOpenCount()).append("\"];\n");
                appendDotPorts(sb, hid, hr.getOpenPorts());
            }
        }
        sb.append("}\n");
        return sb.toString();
    }

    private static String dotMultiHost(MultiHostReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("digraph topology {\n");
        sb.append("  graph [rankdir=LR fontname=Helvetica];\n");
        sb.append("  node  [fontname=Helvetica fontsize=11];\n\n");
        sb.append("  scanner [label=\"scanner\" shape=diamond style=filled fillcolor=\"#cce5ff\"];\n\n");

        if (report.getResults() != null) {
            for (ScanReport hr : report.getResults()) {
                if (hr.getOpenCount() == 0) continue;
                String hid = dotId(hr.getHost());
                sb.append("  ").append(hid).append(" [").append(dotHostAttrs(hr)).append("];\n");
                sb.append("  scanner -> ").append(hid)
                  .append(" [label=\"").append(hr.getOpenCount()).append("\"];\n");
                appendDotPorts(sb, hid, hr.getOpenPorts());
            }
        }
        sb.append("}\n");
        return sb.toString();
    }

    private static String dotHostAttrs(ScanReport report) {
        String color = osColor(report.getOsGuess());
        String label = report.getHost()
                + (report.getResolvedIp() != null ? "\\n" + report.getResolvedIp() : "")
                + "\\n" + report.getOpenCount() + " open";
        return String.format("label=\"%s\" shape=box style=filled fillcolor=\"%s\"", label, color);
    }

    private static void appendDotPorts(StringBuilder sb, String hostId, List<ScanResult> ports) {
        if (ports == null) return;
        for (ScanResult r : ports) {
            String portId = hostId + "_" + r.getPort();
            String svc = r.getServiceName() != null ? r.getServiceName() : "?";
            sb.append("  ").append(portId)
              .append(" [label=\"").append(r.getPort()).append("/").append(svc)
              .append("\" shape=ellipse style=filled fillcolor=\"#d4edda\" fontsize=9];\n");
            sb.append("  ").append(hostId).append(" -> ").append(portId).append(";\n");
        }
    }

    private static void appendDotTraceroute(StringBuilder sb, ScanReport report) {
        if (report.getTracerouteHops() == null || report.getTracerouteHops().isEmpty()) return;
        sb.append("\n  // Traceroute hops\n");
        String prev = "scanner";
        for (TracerouteHop hop : report.getTracerouteHops()) {
            if ("*".equals(hop.ip())) continue;
            String hopId = "hop_" + hop.hopNumber();
            String rtt = hop.rttMs() < 0 ? "*" : String.format("%.1fms", hop.rttMs());
            sb.append("  ").append(hopId)
              .append(" [label=\"").append(hop.ip()).append("\\n").append(rtt)
              .append("\" shape=plaintext fontsize=9 fontcolor=gray];\n");
            sb.append("  ").append(prev).append(" -> ").append(hopId)
              .append(" [style=dashed color=gray];\n");
            prev = hopId;
        }
    }

    // ── Mermaid ───────────────────────────────────────────────────────────────

    private static String mermaidSingle(ScanReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("graph LR\n");
        sb.append("  scanner[\"🖥 scanner\"]\n");

        String hid = mId(report.getHost());
        sb.append("  ").append(hid).append("[\"").append(report.getHost());
        if (report.getResolvedIp() != null) sb.append("<br/>").append(report.getResolvedIp());
        sb.append("<br/>").append(report.getOpenCount()).append(" open\"]").append("\n");
        sb.append("  scanner -->|\"").append(report.getOpenCount()).append(" open\"| ").append(hid).append("\n");

        appendMermaidPorts(sb, hid, report.getOpenPorts());
        appendMermaidStyle(sb, hid, report.getOsGuess());
        return sb.toString();
    }

    private static String mermaidSubnet(SubnetReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("graph LR\n");
        sb.append("  scanner[\"🖥 scanner\"]\n");
        if (report.getHostReports() != null) {
            for (ScanReport hr : report.getHostReports()) {
                if (hr.getOpenCount() == 0) continue;
                String hid = mId(hr.getHost());
                sb.append("  ").append(hid).append("[\"").append(hr.getHost())
                  .append("<br/>").append(hr.getOpenCount()).append(" open\"]\n");
                sb.append("  scanner -->|\"").append(hr.getOpenCount()).append("\"| ").append(hid).append("\n");
                appendMermaidPorts(sb, hid, hr.getOpenPorts());
                appendMermaidStyle(sb, hid, hr.getOsGuess());
            }
        }
        return sb.toString();
    }

    private static String mermaidMultiHost(MultiHostReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("graph LR\n");
        sb.append("  scanner[\"🖥 scanner\"]\n");
        if (report.getResults() != null) {
            for (ScanReport hr : report.getResults()) {
                if (hr.getOpenCount() == 0) continue;
                String hid = mId(hr.getHost());
                sb.append("  ").append(hid).append("[\"").append(hr.getHost())
                  .append("<br/>").append(hr.getOpenCount()).append(" open\"]\n");
                sb.append("  scanner -->|\"").append(hr.getOpenCount()).append("\"| ").append(hid).append("\n");
                appendMermaidPorts(sb, hid, hr.getOpenPorts());
                appendMermaidStyle(sb, hid, hr.getOsGuess());
            }
        }
        return sb.toString();
    }

    private static void appendMermaidPorts(StringBuilder sb, String hostId, List<ScanResult> ports) {
        if (ports == null) return;
        for (ScanResult r : ports) {
            String pid = hostId + "_p" + r.getPort();
            String svc = r.getServiceName() != null ? r.getServiceName() : "?";
            sb.append("  ").append(pid).append("((\"").append(r.getPort()).append("/").append(svc).append("\"))\n");
            sb.append("  ").append(hostId).append(" --- ").append(pid).append("\n");
            sb.append("  style ").append(pid).append(" fill:#d4edda,stroke:#28a745\n");
        }
    }

    private static void appendMermaidStyle(StringBuilder sb, String id, OsGuess os) {
        String fill = mermaidOsColor(os);
        sb.append("  style ").append(id).append(" fill:").append(fill).append(",stroke:#333\n");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String dotId(String host) {
        return "h_" + host.replaceAll("[^a-zA-Z0-9]", "_");
    }

    private static String mId(String host) {
        return "h_" + host.replaceAll("[^a-zA-Z0-9]", "_");
    }

    private static String osColor(OsGuess os) {
        if (os == null) return "#f0f0f0";
        String name = os.getOs().toLowerCase();
        if (name.contains("windows"))             return "#ffcccc"; // red-ish
        if (name.contains("linux") || name.contains("ubuntu") || name.contains("debian")
                || name.contains("centos") || name.contains("freebsd"))
            return "#ccffcc"; // green-ish
        if (name.contains("network") || name.contains("cisco")) return "#ffe0b2"; // orange
        return "#f0f0f0"; // grey = unknown
    }

    private static String mermaidOsColor(OsGuess os) {
        if (os == null) return "#f0f0f0";
        String name = os.getOs().toLowerCase();
        if (name.contains("windows"))  return "#ffcccc";
        if (name.contains("linux") || name.contains("ubuntu") || name.contains("debian")
                || name.contains("centos") || name.contains("freebsd")) return "#ccffcc";
        if (name.contains("network") || name.contains("cisco")) return "#ffe0b2";
        return "#f0f0f0";
    }

    private static boolean isMermaid(Path path) {
        String name = path.getFileName().toString().toLowerCase();
        return name.endsWith(".mmd") || name.endsWith(".mermaid");
    }
}
