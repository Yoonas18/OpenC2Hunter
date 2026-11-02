@echo off
:: OpenC2Hunter - Auto-elevating Firewall Blocker Script
setlocal EnableDelayedExpansion

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [i] Requesting Administrator privileges for Windows Firewall...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

echo ======================================================================
echo   OpenC2Hunter - Blocking Malicious Command ^& Control (C2) IPs
echo ======================================================================
echo.

echo [+] Adding Firewall Outbound Block for 185.220.101.45 (Sliver C2)...
netsh advfirewall firewall add rule name="OpenC2Block_185.220.101.45" dir=out action=block remoteip=185.220.101.45

echo.
echo [+] Adding Firewall Outbound Block for 149.154.167.220 (C2 / Malicious Host)...
netsh advfirewall firewall add rule name="OpenC2Block_149.154.167.220" dir=out action=block remoteip=149.154.167.220

echo.
echo ======================================================================
echo   Verifying Firewall Rules:
echo ======================================================================
netsh advfirewall firewall show rule name="OpenC2Block_185.220.101.45"
echo.
netsh advfirewall firewall show rule name="OpenC2Block_149.154.167.220"

echo.
echo [SUCCESS] Both C2 IPs have been permanently blocked in Windows Firewall!
echo.
pause
