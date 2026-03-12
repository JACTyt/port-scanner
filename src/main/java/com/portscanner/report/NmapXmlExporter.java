package com.portscanner.report;

import com.portscanner.model.ScanReport;
import com.portscanner.model.ScanResult;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class NmapXmlExporter implements ReportExporter {

    private static final DateTimeFormatter HUMAN_FMT =
            DateTimeFormatter.ofPattern("EEE MMM dd HH:mm:ss yyyy").withZone(ZoneOffset.UTC);

    @Override
    public void export(ScanReport report, Path outputPath) throws IOException {
        try (OutputStreamWriter writer = new OutputStreamWriter(
                new FileOutputStream(outputPath.toFile()), StandardCharsets.UTF_8)) {

            XMLOutputFactory factory = XMLOutputFactory.newInstance();
            XMLStreamWriter xml;
            try {
                xml = factory.createXMLStreamWriter(writer);
            } catch (Exception e) {
                throw new IOException("Failed to create XMLStreamWriter", e);
            }

            try {
                xml.writeStartDocument("UTF-8", "1.0");
                xml.writeCharacters("\n");

                long startEpoch = report.getScannedAt() != null
                        ? report.getScannedAt().toEpochSecond(ZoneOffset.UTC)
                        : System.currentTimeMillis() / 1000;
                long endEpoch = startEpoch + (report.getDurationMs() / 1000);
                String startStr = report.getScannedAt() != null
                        ? HUMAN_FMT.format(report.getScannedAt().toInstant(ZoneOffset.UTC))
                        : "";

                xml.writeStartElement("nmaprun");
                xml.writeAttribute("scanner", "portscanner");
                xml.writeAttribute("version", "2.0");
                xml.writeAttribute("xmloutputversion", "1.05");
                xml.writeAttribute("start", String.valueOf(startEpoch));
                xml.writeAttribute("startstr", startStr);
                xml.writeCharacters("\n  ");

                xml.writeStartElement("host");
                xml.writeAttribute("starttime", String.valueOf(startEpoch));
                xml.writeAttribute("endtime", String.valueOf(endEpoch));
                xml.writeCharacters("\n    ");

                xml.writeEmptyElement("status");
                xml.writeAttribute("state", "up");
                xml.writeAttribute("reason", "conn-refused");
                xml.writeCharacters("\n    ");

                xml.writeEmptyElement("address");
                xml.writeAttribute("addr", nvl(report.getResolvedIp()));
                xml.writeAttribute("addrtype", "ipv4");
                xml.writeCharacters("\n    ");

                xml.writeStartElement("hostnames");
                if (report.getHost() != null) {
                    xml.writeCharacters("\n      ");
                    xml.writeEmptyElement("hostname");
                    xml.writeAttribute("name", report.getHost());
                    xml.writeAttribute("type", "PTR");
                    xml.writeCharacters("\n    ");
                }
                xml.writeEndElement(); // hostnames
                xml.writeCharacters("\n    ");

                xml.writeStartElement("ports");
                List<ScanResult> openPorts = report.getOpenPorts();
                if (openPorts != null) {
                    for (ScanResult r : openPorts) {
                        xml.writeCharacters("\n      ");
                        xml.writeStartElement("port");
                        xml.writeAttribute("protocol", "tcp");
                        xml.writeAttribute("portid", String.valueOf(r.getPort()));
                        xml.writeCharacters("\n        ");

                        xml.writeEmptyElement("state");
                        xml.writeAttribute("state", "open");
                        xml.writeAttribute("reason", "syn-ack");
                        xml.writeCharacters("\n        ");

                        xml.writeEmptyElement("service");
                        xml.writeAttribute("name", nvl(r.getServiceName()));
                        if (r.getBanner() != null) {
                            xml.writeAttribute("product", r.getBanner());
                        }
                        xml.writeCharacters("\n      ");

                        xml.writeEndElement(); // port
                    }
                }
                xml.writeCharacters("\n    ");
                xml.writeEndElement(); // ports
                xml.writeCharacters("\n  ");

                xml.writeEndElement(); // host
                xml.writeCharacters("\n  ");

                xml.writeStartElement("runstats");
                xml.writeCharacters("\n    ");
                xml.writeEmptyElement("finished");
                xml.writeAttribute("time", String.valueOf(endEpoch));
                xml.writeAttribute("elapsed", String.format("%.2f", report.getDurationMs() / 1000.0));
                xml.writeCharacters("\n    ");
                xml.writeEmptyElement("hosts");
                xml.writeAttribute("up", "1");
                xml.writeAttribute("down", "0");
                xml.writeAttribute("total", "1");
                xml.writeCharacters("\n  ");
                xml.writeEndElement(); // runstats
                xml.writeCharacters("\n");

                xml.writeEndElement(); // nmaprun
                xml.writeEndDocument();
                xml.flush();
            } catch (Exception e) {
                throw new IOException("Error writing nmap XML", e);
            }
        }
    }

    private String nvl(String s) {
        return s != null ? s : "";
    }
}
