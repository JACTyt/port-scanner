@echo off
setlocal

set JAVA="C:\Users\legion\.jdks\temurin-21.0.9\bin\java"
set MVN="D:\DevTools\IntelliJ IDEA 2025.3.1\plugins\maven\lib\maven3\bin\mvn.cmd"
set JAR="D:\Repos\Github\port-scanner\target\port-scanner-1.0-shaded.jar"
set POM="D:\Repos\Github\port-scanner\pom.xml"

:: Always rebuild to pick up source changes
echo [*] Building...
set JAVA_HOME=C:\Users\legion\.jdks\temurin-21.0.9
call %MVN% -f %POM% package -DskipTests -q
if errorlevel 1 (
    echo [!] Build failed. Fix errors above and try again.
    exit /b 1
)
echo [*] Build complete.

:: Default scan if no arguments given
if "%~1"=="" (
    %JAVA% -jar %JAR% --host localhost --ports 1-1024 --tui
) else (
    %JAVA% -jar %JAR% %* --tui
)
