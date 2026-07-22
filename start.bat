@echo off
setlocal
cd /d "%~dp0"

set "COMFYUI_CLEANER_PORT=8765"
set "COMFYUI_CLEANER_URL=http://127.0.0.1:%COMFYUI_CLEANER_PORT%/"
set "COMFYUI_CLEANER_DIR=%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$port=%COMFYUI_CLEANER_PORT%; $url='%COMFYUI_CLEANER_URL%'; $healthUrl=$url + 'api/health'; $healthy=$false; " ^
  "$existing=Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1; " ^
  "if ($existing) { try { $health=Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2; $healthy=($health.ok -and $health.app -eq 'comfyui-cleaner') } catch {} } " ^
  "else { Start-Process -FilePath 'powershell' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-Command','cd ''%COMFYUI_CLEANER_DIR%''; Write-Host ''ComfyUI Cleaner server is running. Close this window or press Ctrl+C to stop it.''; python -B app.py') -WorkingDirectory '%COMFYUI_CLEANER_DIR%'; for ($i=0; $i -lt 20 -and -not $healthy; $i++) { Start-Sleep -Milliseconds 250; try { $health=Invoke-RestMethod -Uri $healthUrl -TimeoutSec 1; $healthy=($health.ok -and $health.app -eq 'comfyui-cleaner') } catch {} } }; " ^
  "if (-not $healthy) { Write-Host 'ComfyUI Cleaner could not start. Port 8765 may be in use by another application.' -ForegroundColor Red; Read-Host 'Press Enter to close'; exit 1 }; " ^
  "Start-Process $url"

endlocal
