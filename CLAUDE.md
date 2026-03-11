# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A multithreaded Java CLI tool for TCP port scanning with service detection, banner grabbing, and multi-format report export. **No source code has been written yet** — `Project implementation plan.md` contains the full design specification.

## Tech Stack

- **Java 17+**, **Maven 3.9+**
- **Picocli 4.7.6** — CLI argument parsing with auto-generated `--help`
- **Lombok 1.18.x** — `@Data`, `@Builder` on model classes
- **Jackson Databind 2.17+** — JSON serialization
- **JUnit 5 5.10+** / **Mockito 5.x** — testing

## Build Commands

```bash
mvn clean compile          # Compile
mvn package                # Build fat JAR (maven-shade-plugin)
mvn test                   # Run all tests
mvn test -Dtest=ClassName  # Run a single test class
```

**Run the scanner:**
```bash
java -jar target/port-scanner-1.0-jar-with-dependencies.jar --host <host> --ports 1-1024
java -jar target/port-scanner-1.0-jar-with-dependencies.jar --help
```

## Architecture

```
com.portscanner/
├── Main.java                  — Calls CommandLine(new ScanCommand()).execute(args)
├── cli/ScanCommand.java       — Picocli @Command, implements Callable<Integer>
├── scanner/
│   ├── PortScanner.java       — Core TCP connect scan; submits Callable<ScanResult> to ExecutorService
│   └── BannerGrabber.java     — Reads first line from open socket InputStream (optional, --banner flag)
├── model/
│   ├── ScanResult.java        — Lombok @Data @Builder: port, PortStatus, serviceName, banner, responseTimeMs
│   └── ScanReport.java        — Aggregated report: host, resolvedIp, scannedAt, durationMs, openPorts, filteredPorts
├── service/ServiceMapper.java — HashMap<Integer,String> loaded from services.json (~60 well-known ports)
└── report/
    ├── ReportExporter.java    — Interface: export(ScanReport, Path)
    ├── JsonExporter.java      — Jackson implementation
    ├── CsvExporter.java       — Plain CSV
    └── TextExporter.java      — Human-readable table
```

**`src/main/resources/services.json`** — extensible port-to-service map.

## Key Design Decisions

- **Port states:** `OPEN` (no exception), `CLOSED` (`ConnectException`), `FILTERED` (`SocketTimeoutException`), `ERROR` (other `IOException`)
- **Thread pool:** `Executors.newFixedThreadPool(threads)`, capped at 200 (OS file descriptor limit safety margin). Formula: `min(portCount, 200)`
- **Each port scan is a `Callable<ScanResult>`** submitted upfront; results collected via `Future.get(timeout + 500, MILLISECONDS)` to preserve port order
- **Output format selected by file extension:** `.json` → `JsonExporter`, `.csv` → `CsvExporter`, default → `TextExporter`
- **TCP connect scan only** (not SYN) — no raw socket / root privileges required
- **`try-with-resources` on every `Socket`** — prevents file descriptor leaks

## CLI Options

| Option | Default | Notes |
|--------|---------|-------|
| `--host` / `-h` | required | Resolved via `InetAddress.getByName()` |
| `--ports` / `-p` | `1-1024` | Supports `1-1024` range or `80,443,8080` list |
| `--timeout` / `-t` | `200` | 50–5000ms |
| `--threads` | `100` | Max 200 |
| `--banner` | false | Grabs first line from open port's InputStream |
| `--output` / `-o` | stdout | File extension determines format |

## Testing Approach

- `PortScannerTest` — spin up a `ServerSocket` on a test port to assert `OPEN`; scan a port with no listener to assert `CLOSED`
- `ServiceMapperTest` — assert `mapper.getService(22).equals("SSH")`, port 9999 maps to `"Unknown"`
- `ReportExporterTest` — parse JSON output with Jackson, assert expected fields

## Ethical Constraint

The tool must include a **mandatory confirmation prompt** before scanning any non-localhost host. Port scanning without authorization may violate computer misuse laws. Only scan systems you own or have explicit written permission to scan.
