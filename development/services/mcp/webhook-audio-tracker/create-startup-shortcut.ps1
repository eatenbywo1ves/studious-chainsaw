$WshShell = New-Object -comObject WScript.Shell
$StartupPath = [Environment]::GetFolderPath('Startup')
$Shortcut = $WshShell.CreateShortcut("$StartupPath\WebhookAudioTracker.lnk")
$Shortcut.TargetPath = "wscript.exe"
$Shortcut.Arguments = "`"C:\Users\Corbin\development\services\mcp\webhook-audio-tracker\start-background.vbs`""
$Shortcut.WorkingDirectory = "C:\Users\Corbin\development\services\mcp\webhook-audio-tracker"
$Shortcut.Description = "Webhook Audio Tracker for Claude Code"
$Shortcut.Save()
Write-Host "Startup shortcut created at: $StartupPath\WebhookAudioTracker.lnk"
