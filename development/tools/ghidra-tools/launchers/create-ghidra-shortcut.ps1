# Create Desktop Shortcut for Ghidra
$GhidraPath = "C:\Users\Corbin\development\ghidra_11.4.2_PUBLIC"
$GhidraRun = Join-Path $GhidraPath "ghidraRun.bat"
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $DesktopPath "Ghidra.lnk"

if (Test-Path $GhidraRun) {
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = $GhidraRun
    $Shortcut.WorkingDirectory = $GhidraPath
    $Shortcut.Description = "Ghidra Reverse Engineering Platform"

    # Try to set icon
    $IconPath = Join-Path $GhidraPath "support\ghidra.ico"
    if (Test-Path $IconPath) {
        $Shortcut.IconLocation = $IconPath
    }

    $Shortcut.Save()

    Write-Host "Desktop shortcut created: $ShortcutPath" -ForegroundColor Green
    Write-Host "You can now double-click the Ghidra shortcut on your desktop!" -ForegroundColor Yellow
} else {
    Write-Host "ERROR: Ghidra not found at $GhidraRun" -ForegroundColor Red
}