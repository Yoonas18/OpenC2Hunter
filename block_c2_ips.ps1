# OpenC2Hunter — C2 IP Blocker
# Run this as Administrator

Write-Host "=== OpenC2Hunter: Blocking known C2 IPs ===" -ForegroundColor Cyan

netsh advfirewall firewall add rule name="OpenC2Block_185.220.101.45" dir=out action=block remoteip=185.220.101.45
Write-Host "[+] Blocked Sliver C2: 185.220.101.45" -ForegroundColor Green

netsh advfirewall firewall add rule name="OpenC2Block_149.154.167.220" dir=out action=block remoteip=149.154.167.220
Write-Host "[+] Blocked svchost_sync C2: 149.154.167.220" -ForegroundColor Green

Write-Host "`n=== Verifying rules ===" -ForegroundColor Cyan
netsh advfirewall firewall show rule name="OpenC2Block_185.220.101.45" | Select-String "Rule Name|Enabled|Action|RemoteIP"
netsh advfirewall firewall show rule name="OpenC2Block_149.154.167.220" | Select-String "Rule Name|Enabled|Action|RemoteIP"

Write-Host "`n[DONE] Both C2 IPs are now blocked at the Windows Firewall level." -ForegroundColor Green
Read-Host "Press Enter to exit"

