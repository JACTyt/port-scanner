# Known Issues & Non-Working Features

## 1. TUI Mode (`--tui`) — BROKEN on Windows

**Status:** Falls back to plain text output with warning:
> `TUI unavailable (To start java on Windows, use javaw! ...)`

**Root cause:** Lanterna's terminal backend fails to initialize in Windows CMD / PowerShell / Windows Terminal when launched via `java.exe`. It requires either:
- `javaw.exe` — which detaches from the console entirely (no stdout), or
- A compatible text-mode terminal backend (JNA-based `WindowsTerminal`) that fails in shaded JARs

**Workaround:** The plain text output works correctly. You still get full scan results — just no full-screen UI.

**Fix in progress:** `TuiProgressDisplay.java` has been updated to force headless mode + stream-based ANSI terminal. Needs a successful build + verification.

---

## 2. Traceroute (`--traceroute`) — MAY REQUIRE ELEVATION on Windows

**Status:** Calls `tracert.exe` via `ProcessBuilder`. Works if `tracert` is available on PATH (it is by default), but results may be empty or partial if Windows Firewall blocks ICMP.

**Workaround:**
- Run as Administrator if you get no hops
- Check Windows Firewall is not blocking ICMP outbound

---

## 3. UDP Scanning (`--protocol udp` or `--protocol both`) — UNRELIABLE on Windows

**Status:** UDP scanning relies on ICMP "port unreachable" responses to detect closed ports. Windows may require elevated privileges to receive raw ICMP responses, and results are often inaccurate without them.

**Workaround:**
- Run as Administrator for more accurate UDP results
- UDP scanning is inherently less reliable than TCP regardless of OS

**Note:** `--proxy` is silently ignored when UDP scanning (by design).

---

## 4. CVE Lookup (`--cve`) — REQUIRES INTERNET + NVD API KEY

**Status:** Makes live HTTP requests to the NVD (National Vulnerability Database) API. Without an API key, requests are heavily rate-limited (may time out or return no results).

**Workaround:**
- Set `NVD_API_KEY` environment variable, or add it to the config file
- Use `--cve` only on a small port range to avoid hitting rate limits

---

## 5. AbuseIPDB Check (`--abuse-check`) — REQUIRES API KEY

**Status:** Will silently skip enrichment if `ABUSEIPDB_KEY` is not set.

**Workaround:** Set the `ABUSEIPDB_KEY` environment variable:
```powershell
$env:ABUSEIPDB_KEY = "your_key_here"
```

---

## 6. GreyNoise Check (`--greynoise`) — REQUIRES API KEY

**Status:** Will silently skip enrichment if `GREYNOISE_KEY` is not set.

**Workaround:** Set the `GREYNOISE_KEY` environment variable:
```powershell
$env:GREYNOISE_KEY = "your_key_here"
```

---

## 7. Geolocate (`--geolocate`) — WORKS but rate-limited without token

**Status:** Uses IPinfo.io free tier. Works without a token but limited to 50,000 requests/month.

**Workaround:** Set `IPINFO_TOKEN` environment variable for higher limits.

---

## 8. `run.bat` Build Behavior

**Status:** `run.bat` always rebuilds the project before running. This takes ~5–10 seconds on every launch.

**Workaround:** Run the JAR directly to skip the build step:
```powershell
"C:\Users\legion\.jdks\temurin-21.0.9\bin\java" -jar "D:\Repos\Github\port-scanner\target\port-scanner-1.0-shaded.jar" --host localhost --ports 1-1024
```
