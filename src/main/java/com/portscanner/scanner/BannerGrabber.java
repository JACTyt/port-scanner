package com.portscanner.scanner;

import com.portscanner.scanner.probe.Probe;
import com.portscanner.scanner.probe.ProbeRegistry;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;

public class BannerGrabber {

    private final boolean useProbes;

    public BannerGrabber() {
        this.useProbes = false;
    }

    public BannerGrabber(boolean useProbes) {
        this.useProbes = useProbes;
    }

    public String grabBanner(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(1500);

            if (useProbes) {
                Probe probe = ProbeRegistry.getProbe(port);
                byte[] payload = probe.getPayload();
                if (payload != null) {
                    socket.getOutputStream().write(payload);
                    socket.getOutputStream().flush();
                }
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            return reader.readLine();
        } catch (Exception e) {
            return null;
        }
    }
}
