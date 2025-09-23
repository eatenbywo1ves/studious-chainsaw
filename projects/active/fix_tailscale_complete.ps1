# Complete Tailscale fix after Npcap conflict
Write-Host "=== Tailscale Complete Fix Script ===" -ForegroundColor Cyan
Write-Host "This will reset Tailscale to fix connectivity issues" -ForegroundColor Yellow
Write-Host ""

# Step 1: Kill all Tailscale processes
Write-Host "[1/5] Stopping all Tailscale processes..." -ForegroundColor Yellow
Get-Process | Where-Object {$_.ProcessName -like "*tailscale*"} | Stop-Process -Force -ErrorAction SilentlyContinue

# Step 2: Stop the service
Write-Host "[2/5] Stopping Tailscale service..." -ForegroundColor Yellow
Stop-Service -Name "Tailscale" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Step 3: Clear any stuck state
Write-Host "[3/5] Clearing network state..." -ForegroundColor Yellow
netsh int ip reset
netsh winsock reset

# Step 4: Restart the service
Write-Host "[4/5] Starting Tailscale service..." -ForegroundColor Yellow
Start-Service -Name "Tailscale" -ErrorAction Stop
Start-Sleep -Seconds 3

# Step 5: Start Tailscale GUI
Write-Host "[5/5] Starting Tailscale GUI..." -ForegroundColor Yellow
$tailscalePath = "C:\Program Files\Tailscale\tailscale-ipn.exe"
if (Test-Path $tailscalePath) {
    Start-Process $tailscalePath
    Write-Host "Tailscale GUI started!" -ForegroundColor Green
} else {
    Write-Host "Tailscale GUI not found at expected location" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Fix Complete ===" -ForegroundColor Green
Write-Host "Please wait a moment for Tailscale to reconnect." -ForegroundColor Yellow
Write-Host "You may need to click on the Tailscale icon in the system tray and log in again." -ForegroundColor Yellow
Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")