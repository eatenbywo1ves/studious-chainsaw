# Script to disable Npcap on Tailscale adapter
# This resolves conflicts between Tailscale VPN and Wireshark's packet capture

Write-Host "Disabling Npcap binding on Tailscale adapter..." -ForegroundColor Yellow
try {
    Disable-NetAdapterBinding -Name 'Tailscale' -ComponentID 'INSECURE_NPCAP' -ErrorAction Stop
    Write-Host "Successfully disabled Npcap on Tailscale adapter!" -ForegroundColor Green
    Write-Host "Tailscale should now work properly." -ForegroundColor Green
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host "Make sure you're running this script as Administrator." -ForegroundColor Yellow
}

Write-Host "`nPress any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")