# Restart Tailscale service to fix connectivity
Write-Host "Restarting Tailscale service..." -ForegroundColor Yellow
try {
    Stop-Service -Name "Tailscale" -Force -ErrorAction Stop
    Write-Host "Tailscale service stopped" -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    Start-Service -Name "Tailscale" -ErrorAction Stop
    Write-Host "Tailscale service started successfully!" -ForegroundColor Green
    
    Start-Sleep -Seconds 3
    Write-Host "`nChecking Tailscale status..." -ForegroundColor Yellow
    & tailscale status
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host "Make sure you're running this script as Administrator." -ForegroundColor Yellow
}

Write-Host "`nPress any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")