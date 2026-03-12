package com.portscanner.scanner;

import com.portscanner.scanner.probe.Probe;
import com.portscanner.scanner.probe.ProbeRegistry;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;

public class BannerGrabber {

    private final boolean useProbes;
    private final Proxy proxy;

    public BannerGrabber() {
        this.useProbes = false;
        this.proxy = Proxy.NO_PROXY;
    }

    public BannerGrabber(boolean useProbes) {
        this.useProbes = useProbes;
        this.proxy = Proxy.NO_PROXY;
    }

    public BannerGrabber(boolean useProbes, Proxy proxy) {
        this.useProbes = useProbes;
        this.proxy = proxy != null ? proxy : Proxy.NO_PROXY;
    }

    public String grabBanner(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket(proxy)) {
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

    /**
     * Read up to maxBytes raw bytes from an InputStream within timeoutMs.
     * Returns whatever bytes were available before timeout or EOF.
     */
    public static byte[] readRawBytes(InputStream in, int maxBytes, int timeoutMs) throws IOException {
        byte[] buf = new byte[maxBytes];
        long deadline = System.currentTimeMillis() + timeoutMs;
        int total = 0;
        while (total < maxBytes) {
            int remaining = (int) (deadline - System.currentTimeMillis());
            if (remaining <= 0) break;
            int avail = in.available();
            if (avail <= 0) {
                // Short sleep to avoid busy-wait
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                remaining = (int) (deadline - System.currentTimeMillis());
                if (remaining <= 0) break;
                avail = in.available();
                if (avail <= 0) break;
            }
            int toRead = Math.min(avail, maxBytes - total);
            int read = in.read(buf, total, toRead);
            if (read < 0) break;
            total += read;
        }
        if (total == 0) return new byte[0];
        byte[] result = new byte[total];
        System.arraycopy(buf, 0, result, 0, total);
        return result;
    }
}
