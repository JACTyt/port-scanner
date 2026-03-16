# GraalVM Native Image — Port Scanner

A GraalVM native binary starts in ~5ms (vs ~300ms JVM), uses ~15MB RSS (vs ~80MB), and requires
no Java installation. It is a single self-contained executable.

---

## Prerequisites

### Option A — GraalVM CE (recommended, free)

Download from [github.com/graalvm/graalvm-ce-builds/releases](https://github.com/graalvm/graalvm-ce-builds/releases)
or install via SDKMAN / Homebrew:

```bash
# SDKMAN (Linux/Mac)
sdk install java 21.0.3-graalce
sdk use java 21.0.3-graalce

# Homebrew (Mac)
brew install --cask graalvm/tap/graalvm-community-java21

# Windows — download the zip, extract, set JAVA_HOME
```

`native-image` is bundled with GraalVM CE 21+ — no separate `gu install` step needed.

### Option B — GitHub Actions (CI)

The release pipeline uses `graalvm/setup-graalvm@v1` which installs GraalVM CE automatically.
See `.github/workflows/release.yml`.

---

## System dependencies

| Platform | Required packages |
|----------|------------------|
| Linux (Ubuntu/Debian) | `sudo apt-get install zlib1g-dev` |
| Linux (RHEL/Fedora) | `sudo dnf install zlib-devel` |
| macOS | Xcode Command Line Tools (`xcode-select --install`) |
| Windows | Visual Studio 2019+ with "Desktop development with C++" workload |

On Windows, run the build inside a **Visual Studio Developer Command Prompt** or use
the GitHub Actions workflow which sets up the build environment automatically.

---

## Build

```bash
# Compile and package native binary
mvn -Pnative package -DskipTests

# Output: target/port-scanner  (Linux/Mac)
#         target\port-scanner.exe  (Windows)
```

Expect the build to take 2–5 minutes. The `native-maven-plugin 0.10.x` (already in `pom.xml`)
drives the build. All reflection/resource config is read automatically from
`src/main/resources/META-INF/native-image/com.portscanner/port-scanner/`.

---

## Run

```bash
# Linux / macOS
./target/port-scanner --host localhost --ports 1-1024

# Windows
target\port-scanner.exe --host localhost --ports 1-1024
```

All CLI flags work identically to the JVM JAR. Startup is typically under 10ms.

---

## Performance comparison

| Metric | JVM JAR | Native binary |
|--------|---------|---------------|
| Startup time | ~300ms | ~5–10ms |
| Heap (idle) | ~80 MB | ~15 MB |
| Peak heap (large scan) | ~200–400 MB | ~50–120 MB |
| Distribution | Requires Java 21+ | Self-contained |
| Binary size | ~15 MB JAR | ~60–80 MB binary |

---

## How the reflection configuration works

GraalVM's static analysis cannot see classes loaded dynamically at runtime (Jackson serialization,
Logback appenders, Picocli command classes, ServiceLoader plugins). The config files in
`src/main/resources/META-INF/native-image/com.portscanner/port-scanner/` register these:

| File | Purpose |
|------|---------|
| `reflect-config.json` | All model/config/CLI/report/plugin classes + Jackson JSR-310 + Logback pattern converters + dnsjava record types |
| `resource-config.json` | `services.json`, `logback.xml`, `top-1000-subdomains.txt`, all `META-INF/services/` files |
| `native-image.properties` | Build flags: `--no-fallback`, HTTPS protocol, run-time init for Lanterna/JNA/SQLite/Logback |
| `proxy-config.json` | Dynamic proxy interfaces (currently empty — none used) |
| `jni-config.json` | JNA dispatch classes for Lanterna Windows TUI support |

Additionally, `picocli-codegen` (an annotation processor configured in `pom.xml`) auto-generates
GraalVM config for all `@Command`/`@Option`/`@Parameters` fields during `mvn compile`. Output:
`target/generated-sources/annotations/META-INF/native-image/picocli-generated/`. These are merged
with the hand-written configs at build time via the shade plugin's `ServicesResourceTransformer`.

---

## Tracing agent (regenerating config after code changes)

If you add new classes that are loaded reflectively, re-run the tracing agent to regenerate configs:

```bash
# 1. Build the fat JAR first
mvn package -DskipTests

# 2. Run with the agent against a representative workload
java -agentlib:native-image-agent=config-merge-dir=src/main/resources/META-INF/native-image/com.portscanner/port-scanner \
  -jar target/port-scanner-1.0-shaded.jar --host localhost --ports 80,443,22

# 3. Run again with different flags to capture more code paths
java -agentlib:native-image-agent=config-merge-dir=src/main/resources/META-INF/native-image/com.portscanner/port-scanner \
  -jar target/port-scanner-1.0-shaded.jar --host localhost --ports 1-1024 --banner --tls

# 4. Rebuild native image
mvn -Pnative package -DskipTests
```

Use `config-merge-dir` (not `config-output-dir`) after the first run to accumulate entries without
overwriting what was already there.

---

## Known limitations in native mode

| Feature | Status | Notes |
|---------|--------|-------|
| TCP scanning | ✅ Full support | |
| UDP scanning | ✅ Full support | May require elevated privileges |
| Banner grabbing | ✅ Full support | |
| TLS inspection | ✅ Full support | |
| JSON/CSV/HTML/XML output | ✅ Full support | |
| CVE lookup (NVD API) | ✅ Full support | |
| Geolocation / AbuseIPDB / GreyNoise | ✅ Full support | |
| DNS subdomain brute-force | ✅ Full support | |
| `--tui` (Lanterna) | ⚠️ Best-effort | JNA native lib extraction at runtime; may fail without a real TTY. Use without `--tui` for scripts. |
| Local CVE SQLite cache | ⚠️ Best-effort | SQLite-JDBC extracts a native lib at runtime — needs a writable temp directory. |
| Plugin loading | ✅ Full support | Built-in plugins included; external JAR loading requires GraalVM agent pass. |

---

## Troubleshooting

### `Missing class exception` at runtime

Add the missing class to `reflect-config.json` and rebuild.

### `ClassNotFoundException` for a Logback class

Logback loads appender/encoder/filter classes by name from `logback.xml`. Ensure every class name
referenced in `logback.xml` appears in `reflect-config.json`.

### `UnsatisfiedLinkError` from JNA / SQLite

These libraries extract native binaries to a temp directory. Ensure the process has write access
to `java.io.tmpdir`. The `--initialize-at-run-time` flags in `native-image.properties` defer their
loading to runtime which is required.

### Build fails with `--no-fallback`

Remove `--no-fallback` temporarily to get a fallback binary that runs on the JVM. Inspect the
build log for classes that need to be added to the reflection config. Re-add `--no-fallback` once
resolved.

### Windows: `LINK : fatal error`

Open a **Visual Studio Developer Command Prompt** and run `mvn -Pnative package` from there.
Alternatively, the GitHub Actions release workflow handles this automatically.
