$WshShell = New-Object -ComObject WScript.Shell
$DesktopPath = [Environment]::GetFolderPath('Desktop')
$Shortcut = $WshShell.CreateShortcut("$DesktopPath\Vantor Chat.lnk")
$Shortcut.TargetPath = "D:\DFIR Coding AI\apps\dfir-coding-ai-desktop\src-tauri\target\release\dfir-coding-ai-desktop.exe"
$Shortcut.WorkingDirectory = "D:\DFIR Coding AI\apps\dfir-coding-ai-desktop\src-tauri\target\release"
$Shortcut.Description = "Vantor Chat - DFIR Coding AI"
$Shortcut.Save()
Write-Host "Desktop shortcut created at: $DesktopPath"
