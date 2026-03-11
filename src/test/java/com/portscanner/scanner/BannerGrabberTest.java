package com.portscanner.scanner;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

import static org.junit.jupiter.api.Assertions.*;

class BannerGrabberTest {

    private ServerSocket serverSocket;
    private int port;
    private Thread acceptThread;

    @BeforeEach
    void setUp() throws IOException {
        serverSocket = new ServerSocket(0);
        port = serverSocket.getLocalPort();
    }

    @AfterEach
    void tearDown() throws IOException {
        if (acceptThread != null) acceptThread.interrupt();
        if (serverSocket != null && !serverSocket.isClosed()) serverSocket.close();
    }

    private void serveBanner(String banner) {
        acceptThread = new Thread(() -> {
            try {
                Socket client = serverSocket.accept();
                PrintWriter pw = new PrintWriter(client.getOutputStream(), true);
                pw.println(banner);
                Thread.sleep(200); // hold open so reader can finish
                client.close();
            } catch (Exception ignored) {}
        });
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    @Test
    void grabs_banner_from_server() throws Exception {
        serveBanner("SSH-2.0-OpenSSH_8.9");
        BannerGrabber grabber = new BannerGrabber(false);
        String result = grabber.grabBanner("localhost", port, 1000);
        assertEquals("SSH-2.0-OpenSSH_8.9", result);
    }

    @Test
    void returns_null_when_no_server_is_running() throws IOException {
        int closedPort = serverSocket.getLocalPort();
        serverSocket.close();
        BannerGrabber grabber = new BannerGrabber(false);
        String result = grabber.grabBanner("localhost", closedPort, 200);
        assertNull(result);
    }

    @Test
    void returns_null_on_read_timeout() {
        // Server accepts but never sends data
        acceptThread = new Thread(() -> {
            try {
                Socket client = serverSocket.accept();
                Thread.sleep(5000); // hold open with no data
                client.close();
            } catch (Exception ignored) {}
        });
        acceptThread.setDaemon(true);
        acceptThread.start();

        BannerGrabber grabber = new BannerGrabber(false);
        String result = grabber.grabBanner("localhost", port, 200);
        assertNull(result);
    }

    @Test
    void grabs_banner_with_special_characters() throws Exception {
        serveBanner("220 mail.example.com ESMTP Postfix (Ubuntu)");
        BannerGrabber grabber = new BannerGrabber(false);
        String result = grabber.grabBanner("localhost", port, 1000);
        assertEquals("220 mail.example.com ESMTP Postfix (Ubuntu)", result);
    }
}
