# install_autostart.ps1 - run once. Makes LiteAudit start automatically when you sign in to Windows.
# Right-click this file > "Run with PowerShell", or run:  powershell -ExecutionPolicy Bypass -File .\install_autostart.ps1

$project = Split-Path -Parent $MyInvocation.MyCommand.Path
$launcher = Join-Path $project "start_liteaudit.vbs"

if (-not (Test-Path $launcher)) {
    Write-Host "Could not find start_liteaudit.vbs next to this script." -ForegroundColor Red
    exit 1
}

$startup = [Environment]::GetFolderPath("Startup")
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut((Join-Path $startup "LiteAudit.lnk"))
$shortcut.TargetPath = "wscript.exe"
$shortcut.Arguments = "`"$launcher`""
$shortcut.WorkingDirectory = $project
$shortcut.Save()

Write-Host "Done. LiteAudit will now start automatically at sign-in." -ForegroundColor Green
Write-Host "Starting it now..."
Start-Process wscript.exe -ArgumentList "`"$launcher`"" -WorkingDirectory $project
