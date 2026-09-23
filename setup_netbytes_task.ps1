# v2.2.1 — Setup UNICO (una vez, ELEVADO) de la tarea programada que
# dispara el colector de bytes remotos sin prompt UAC por ciclo.
#
# COMO USARLO: desde una consola PowerShell ELEVADA (como administrador):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\setup_netbytes_task.ps1
#
# Crea/actualiza la tarea AI-NETWATCH-NetBytes con "Run with highest
# privileges" y logon interactivo. Despues, el servidor (no elevado) la
# dispara con `schtasks /run` en cada ciclo: sin prompt, y funciona
# aunque el servidor corra desde un proceso de fondo oculto.

$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot
$wrapper = Join-Path $repo "netcollector_task.ps1"
$taskName = "AI-NETWATCH-NetBytes"

if (-not (Test-Path -LiteralPath $wrapper)) {
    throw "No encuentro el wrapper: $wrapper"
}

# Verifico que soy admin; si no, fallo claro (no creo tarea a medias).
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "Este script necesita una consola ELEVADA (como administrador)."
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$wrapper`""

# On-demand start ya es el default (el inverso seria -DisallowDemandStart);
# -StartWhenAvailable es un switch y su default (no iniciar) es lo que
# queremos, asi que se omite.
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
    -MultipleInstances IgnoreNew

# LogonType Interactive + RunLevel Highest = "Run with highest
# privileges" con solo logon interactivo: el task engine eleva sin prompt.
$principal = New-ScheduledTaskPrincipal `
    -UserId $env:USERNAME `
    -LogonType Interactive `
    -RunLevel Highest

Register-ScheduledTask -TaskName $taskName `
    -Action $action -Settings $settings -Principal $principal -Force | Out-Null

Write-Host "Tarea '$taskName' creada/actualizada (highest privileges, interactivo)."
Write-Host "Prueba manual:  schtasks /run /TN $taskName"
Write-Host "El servidor la disparara solo si net_bytes_enabled=true."
