while ($true) {
    Get-ChildItem C:\Users -Recurse -ErrorAction SilentlyContinue | Select-Object -First 20
    Get-ChildItem "C:\Program Files" -ErrorAction SilentlyContinue
    whoami | Out-Null
    net user | Out-Null
    ipconfig /all | Out-Null
    Start-Process notepad.exe
    Start-Sleep -Seconds 5
    Stop-Process -Name notepad -ErrorAction SilentlyContinue
    Start-Process calc.exe
    Start-Sleep -Seconds 5
    Stop-Process -Name CalculatorApp -ErrorAction SilentlyContinue
    Write-Host "Baseline cycle complete - $(Get-Date)"
    Start-Sleep -Seconds (Get-Random -Minimum 1200 -Maximum 1800)  # 20-30 minutes randomly
}