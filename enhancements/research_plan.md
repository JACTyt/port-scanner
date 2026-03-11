# Port Scanner Enhancement Research Plan

## Main Question
What are the best directions to enhance a Java multithreaded TCP/UDP port scanner CLI tool?

## Current Feature Set
- TCP/UDP scanning, banner grabbing, service detection (220+ ports)
- CIDR subnet scanning, NIO non-blocking scanner, rate limiting
- CVE lookup via NVD API, multiple export formats (JSON, CSV, TXT, HTML, XML)
- Report diffing, YAML config, Picocli CLI, SLF4J logging

## Subtopics

### 1. Advanced Scanning Techniques
- OS fingerprinting, version detection, SYN scan alternatives
- Protocol-specific probes, SSL/TLS inspection

### 2. Modern Java Performance
- Project Loom virtual threads, structured concurrency (Java 21+)
- Async I/O improvements, smarter thread pool strategies

### 3. Threat Intelligence & Security Integrations
- APIs beyond NVD: Shodan, VirusTotal, Censys, Exploit-DB, GreyNoise
- Local vulnerability databases, offline CVE support

### 4. Output & Reporting Enhancements
- Interactive TUI (Lanterna, Picocli), real-time progress bars
- Dashboard/web UI, live scan updates, better terminal output

### 5. Features from nmap / masscan / rustscan
- Ideas that translate well to pure-Java implementation
- Script engine concepts, timing profiles, output formats

### 6. Network Topology & Discovery
- Traceroute, improved ping sweep, ARP scanning concepts
- AS/BGP lookups, geolocation enrichment

## Synthesis Plan
Each subtopic saved to its own .md file, then a final summary.md consolidating all findings.
