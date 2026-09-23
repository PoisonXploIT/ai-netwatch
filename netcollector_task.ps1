# v2.2.1 — Accion de la tarea programada AI-NETWATCH-NetBytes.
#
# Se ejecuta ELEVADA (RunLevel Highest) por el task engine cuando el
# servidor hace `schtasks /run /TN AI-NETWATCH-NetBytes`. Lee los
# parametros que el servidor escribio en data\netcollector_cmd.json y
# lanza el colector. Sin red, sin interaccion: solo corre y escribe el
# JSONL; el servidor (no elevado) lo lee despues.

$ErrorActionPreference = "Stop"
try {
    $cmdPath = Join-Path $PSScriptRoot "data\netcollector_cmd.json"
    $c = Get-Content -LiteralPath $cmdPath -Raw | ConvertFrom-Json
    # netcollector.py <duracion_s> <ruta_jsonl_salida>
    & $c.python $c.script ([int]$c.duration_s) $c.out_path
    exit $LASTEXITCODE
} catch {
    # Diagnostico minimo junto al cmd (el servidor, no elevado, no puede
    # ver la consola de la tarea).
    try {
        $diag = Join-Path $PSScriptRoot "data\netcollector_task_error.txt"
        Set-Content -LiteralPath $diag -Value $_.Exception.Message
    } catch {}
    exit 1
}
