@echo off
:: ─────────────────────────────────────────────────────────────────────────────
:: jpackage-win.bat — Build a Windows .msi installer for port-scanner
::
:: Prerequisites:
::   - JDK 21+ on PATH  (must include jpackage and jlink)
::   - WiX Toolset 3.x  (required by jpackage for .msi output)
::     Install from: https://wixtoolset.org/releases/
::   - Run: mvn package -DskipTests  before this script
::
:: Output: target\Port-Scanner-1.0.msi
:: ─────────────────────────────────────────────────────────────────────────────

setlocal

set JAVA_HOME_LOCAL=%JAVA_HOME%
if "%JAVA_HOME_LOCAL%"=="" (
    echo ERROR: JAVA_HOME is not set. Point it to a JDK 21+ installation.
    exit /b 1
)

set JAR=target\port-scanner-1.0-shaded.jar
if not exist "%JAR%" (
    echo ERROR: %JAR% not found. Run: mvn package -DskipTests
    exit /b 1
)

echo Building Windows installer...

"%JAVA_HOME_LOCAL%\bin\jpackage" ^
    --type msi ^
    --name "Port-Scanner" ^
    --app-version 1.0 ^
    --description "Multithreaded TCP/UDP port scanner with service detection" ^
    --vendor "port-scanner" ^
    --input target ^
    --main-jar port-scanner-1.0-shaded.jar ^
    --main-class com.portscanner.Main ^
    --dest target ^
    --win-console ^
    --win-shortcut ^
    --win-dir-chooser ^
    --win-menu ^
    --win-menu-group "Port Scanner" ^
    --java-options "-Xmx512m"

if %ERRORLEVEL% neq 0 (
    echo ERROR: jpackage failed. Ensure WiX Toolset 3.x is installed and on PATH.
    exit /b %ERRORLEVEL%
)

echo.
echo Installer built: target\Port-Scanner-1.0.msi
echo Install with:    msiexec /i target\Port-Scanner-1.0.msi
endlocal
