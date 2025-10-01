Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "C:\Users\Corbin\development\services\mcp\webhook-audio-tracker"
WshShell.Run "cmd /c start.bat", 0, False
Set WshShell = Nothing
