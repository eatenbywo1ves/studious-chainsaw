' Ghidra VBScript Launcher - Bypasses all console redirection issues
' This script launches Ghidra without any console interaction

Dim fso, shell, ghidraDir, ghidraRun

Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

' Set Ghidra directory
ghidraDir = "C:\Users\Corbin\development\ghidra_11.4.2_PUBLIC"
ghidraRun = ghidraDir & "\ghidraRun.bat"

' Check if Ghidra exists
If Not fso.FolderExists(ghidraDir) Then
    MsgBox "Ghidra not found at: " & ghidraDir, vbCritical, "Ghidra Launcher Error"
    WScript.Quit 1
End If

If Not fso.FileExists(ghidraRun) Then
    MsgBox "ghidraRun.bat not found at: " & ghidraRun, vbCritical, "Ghidra Launcher Error"
    WScript.Quit 1
End If

' Change working directory and launch Ghidra
shell.CurrentDirectory = ghidraDir

' Launch with no console window (WindowStyle = 0)
' This completely bypasses input redirection issues
On Error Resume Next
shell.Run """" & ghidraRun & """", 0, False

If Err.Number <> 0 Then
    ' If batch file fails, try direct Java launch
    Dim javaCmd
    javaCmd = "java -cp """ & ghidraDir & "\support\LaunchSupport.jar"" " & _
              "-Dghidra.install.dir=""" & ghidraDir & """ " & _
              "-Xmx4G " & _
              "LaunchSupport """ & ghidraDir & """ ghidra.GhidraRun"

    shell.Run javaCmd, 0, False
End If

On Error Goto 0

' Script completes immediately, Ghidra runs independently
WScript.Quit 0