# install_autostart.ps1 - run once. Makes LiteAudit start automatically when you sign in to Windows.
# Run it from the LiteAudit project folder:
#   powershell -ExecutionPolicy Bypass -File .\install_autostart.ps1

$project = Split-Path -Parent $MyInvocation.MyCommand.Path

foreach ($required in @("quarantine_watcher.py", "liteaudit_app.py", "scanner.py")) {
    if (-not (Test-Path (Join-Path $project $required))) {
        Write-Host "Missing $required in $project" -ForegroundColor Red
        exit 1
    }
}

# Find Python and make sure it really runs (not just the Microsoft Store shortcut).
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "Python was not found. Install Python from python.org and tick 'Add Python to PATH'." -ForegroundColor Red
    exit 1
}
$python = $pythonCmd.Source
$versionText = & $python --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Python at $python did not run correctly: $versionText" -ForegroundColor Red
    exit 1
}
& $python -c "import streamlit, pandas, altair" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Streamlit, pandas or altair is missing for this Python. Run:  `"$python`" -m pip install streamlit pandas altair" -ForegroundColor Red
    exit 1
}
Write-Host "Using $python ($versionText)"

# Write the hidden launcher with the full Python path, and log all output to launcher.log.
$launcher = Join-Path $project "start_liteaudit.vbs"
$vbs = @"
Set shell = CreateObject("WScript.Shell")
shell.CurrentDirectory = "$project"
shell.Run "cmd /c """"$python"" quarantine_watcher.py >> launcher.log 2>&1""", 0, False
shell.Run "cmd /c """"$python"" -m streamlit run liteaudit_app.py --server.headless true --server.address 127.0.0.1 --server.port 8501 >> launcher.log 2>&1""", 0, False
"@
Set-Content -Path $launcher -Value $vbs -Encoding ASCII

# Add a shortcut to the Startup folder so it runs at every sign-in.
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
Start-Sleep -Seconds 4
$running = Get-CimInstance Win32_Process -Filter "name like 'python%'" | Where-Object { $_.CommandLine -like "*quarantine_watcher*" }
if ($running) { Write-Host "Watcher is running." -ForegroundColor Green }
else { Write-Host "Watcher did not start. Open launcher.log in $project to see why." -ForegroundColor Yellow }
