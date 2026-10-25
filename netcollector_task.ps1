# v2.2.1 — Accion de la tarea programada AI-NETWATCH-NetBytes.
#
# Se ejecuta ELEVADA (RunLevel Highest) por el task engine cuando el
# servidor hace `schtasks /run /TN AI-NETWATCH-NetBytes`. Lee los
# parametros que el servidor escribio en data\netcollector_cmd.json y
# lanza el colector. Sin red, sin interaccion: solo corre y escribe el
# JSONL; el servidor (no elevado) lo lee despues.
#
# v2.6(6): este wrapper ya no hace el trabajo. Task Scheduler, con
# LogonType Interactive, crea una consola para powershell.exe: cada ciclo
# (10 min) aparecia una ventana de PowerShell que robaba el foco. El
# wrapper ahora SOLO arranca el colector en pythonw.exe (sin consola) y
# sale: la ventana vive ~50 ms en lugar de los 30 s de la traza.
#
# Para eliminar la ventana por completo hay que re-registrar la tarea con
# pythonw.exe como ejecutable (setup_netbytes_task.ps1, ya actualizado).
# Eso requiere una consola elevada una vez:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\setup_netbytes_task.ps1

$ErrorActionPreference = "Stop"
try {
    $repo = $PSScriptRoot
    $cmdPath = Join-Path $repo "data\netcollector_cmd.json"
    $c = Get-Content -LiteralPath $cmdPath -Raw | ConvertFrom-Json

    $pythonw = Join-Path $repo ".venv\Scripts\pythonw.exe"
    if (-not (Test-Path -LiteralPath $pythonw)) {
        $pythonw = 'C:\Users\Sammi\AppData\Local\Programs\Python\Python312\pythonw.exe'
    }

    if (Test-Path -LiteralPath $pythonw) {
        Start-Process -FilePath $pythonw `
            -ArgumentList "`"$repo\netcollector_task.py`" `
            -WindowStyle Hidden
        exit 0
    }

    # Fallback: el interprete sin consola no esta disponible (venv roto).
    & $c.python $c.script ([int]$c.duration_s) $c.out_path
    exit $LASTEXITCODE
} catch {
    try {
        $diag = Join-Path $PSScriptRoot "data\netcollector_task_error.txt"
        Set-Content -LiteralPath $diag -Value $_.Exception.Message
    } catch {}
    exit 1
}
