package com.portscanner;

import com.portscanner.cli.ScanCommand;
import picocli.CommandLine;

public class Main {

    public static void main(String[] args) {
        int exitCode = new CommandLine(new ScanCommand()).execute(args);
        System.exit(exitCode);
    }
}
