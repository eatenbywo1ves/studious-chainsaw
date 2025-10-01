# PowerShell script to merge MCP configuration into Claude Code config

$claudeConfigPath = "$env:USERPROFILE\.claude\config.json"
$mcpConfigPath = "$PSScriptRoot\claude-code-config.json"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Merging MCP Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Read the MCP configuration
$mcpConfig = Get-Content $mcpConfigPath -Raw | ConvertFrom-Json

# Check if Claude config exists
if (Test-Path $claudeConfigPath) {
    Write-Host "Found existing Claude Code configuration" -ForegroundColor Green
    $claudeConfig = Get-Content $claudeConfigPath -Raw | ConvertFrom-Json
} else {
    Write-Host "Creating new Claude Code configuration" -ForegroundColor Yellow
    $claudeConfig = @{}
}

# Ensure mcpServers object exists
if (-not $claudeConfig.mcpServers) {
    $claudeConfig | Add-Member -NotePropertyName "mcpServers" -NotePropertyValue @{} -Force
}

# Add or update the webhook-audio-tracker server
$claudeConfig.mcpServers | Add-Member -NotePropertyName "webhook-audio-tracker" -NotePropertyValue $mcpConfig.mcpServers.'webhook-audio-tracker' -Force

# Save the updated configuration
$claudeConfig | ConvertTo-Json -Depth 10 | Set-Content $claudeConfigPath

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Configuration Merged Successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Configuration saved to: $claudeConfigPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Start the webhook server: start.bat" -ForegroundColor White
Write-Host "2. Restart Claude Code" -ForegroundColor White
Write-Host "3. Test with: 'Play a test audio cue'" -ForegroundColor White
Write-Host ""

pause
