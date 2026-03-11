# Building a Native Binary with GraalVM

## Prerequisites
- GraalVM JDK 17+ installed and set as `JAVA_HOME`
- `native-image` tool installed: `gu install native-image`

## Build

```bash
mvn -Pnative package
```

This produces a self-contained `port-scanner` binary in `target/`.

## Run

```bash
# Linux / macOS
./target/port-scanner --host localhost --ports 1-1024

# Windows
target\port-scanner.exe --host localhost --ports 1-1024
```

## Benefits

| | JVM JAR | Native binary |
|---|---|---|
| Startup time | ~300ms | ~5ms |
| Memory (RSS) | ~80MB | ~15MB |
| Distribution | Requires JRE | Self-contained |

## Notes
- Banner grabbing works normally in native mode.
- The `--use-nio` flag and all other options are fully supported.
- If you encounter reflection errors, add entries to `reflect-config.json`.
