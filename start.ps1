# ===================================================
#  SystemSniffer - Unified Launcher
#  Starts both Flask backend (port 5000) and Vite frontend (port 3000)
# ===================================================

Write-Host ""
Write-Host "  SystemSniffer - Network Monitor & IDS" -ForegroundColor Cyan
Write-Host ""

$projectDir = $PSScriptRoot

# -- Start Flask Backend --
Write-Host "[1/2] Starting Flask backend on port 5000..." -ForegroundColor Yellow
$backendJob = Start-Process -FilePath "python" `
    -ArgumentList "$projectDir\app.py" `
    -WorkingDirectory $projectDir `
    -PassThru `
    -WindowStyle Normal

Start-Sleep -Seconds 2

# -- Start Vite Frontend --
Write-Host "[2/2] Starting Vite frontend on port 3000..." -ForegroundColor Yellow
$frontendJob = Start-Process -FilePath "npm" `
    -ArgumentList "run dev" `
    -WorkingDirectory "$projectDir\frontend" `
    -PassThru `
    -WindowStyle Normal

Start-Sleep -Seconds 3

Write-Host ""
Write-Host "  Both servers are running!" -ForegroundColor Green
Write-Host ""
Write-Host "  Frontend  -> http://localhost:3000" -ForegroundColor Cyan
Write-Host "  Backend   -> http://localhost:5000" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Press Ctrl+C in each terminal window to stop." -ForegroundColor DarkGray
Write-Host ""

# Open browser
Start-Process "http://localhost:3000"

# Wait for user input before exiting
Write-Host "Press Enter to stop both servers..." -ForegroundColor Yellow
Read-Host

# Cleanup
if ($backendJob -and !$backendJob.HasExited) { Stop-Process -Id $backendJob.Id -Force -ErrorAction SilentlyContinue }
if ($frontendJob -and !$frontendJob.HasExited) { Stop-Process -Id $frontendJob.Id -Force -ErrorAction SilentlyContinue }

Write-Host "Servers stopped." -ForegroundColor Red
