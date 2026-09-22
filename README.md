# AI NetWatch

Monitor local de **salidas de red hacia proveedores cloud IA** (OpenAI/Azure, Anthropic, Google, TypeSafe/Jev, Groq, OpenRouter, Mistral, Cohere, Hugging Face, DeepSeek, xAI, Together, Replicate...). Lo que ve: **proceso + destino IP/puerto + periodicidad** de cada conexion establecida a un destino IA.

- Solo loopback (`127.0.0.1`), puerto 8790.
- **Jev (TypeSafe)** como juez de criticidad, a demanda (boton *Triar eventos con Jev*): clasificacion `expected_ai_use / background_exfil_suspect / telemetry_noise / unrelated`, criticidad 0-3, accion inmediata y **probabilidad de falso positivo** derivada.
- **LLM local** (OpenAI-compatible, SOLO loopback, sin key): explicaciones tecnicas en espanol de los eventos marcados.
- Fail-safe: sin IA configurada la vista clasica funciona igual; ningun error de IA rompe el monitor.
- Sin dependencias nuevas: FastAPI + stdlib (el monitor usa `Get-NetTCPConnection` via PowerShell).

## Limitaciones honestas

- No ve **bytes** ni **payload**: solo que un proceso abrio/mantiene conexion a un destino IA, con cuantas veces se repite. Bytes/payload requieren ETW/WFP o MITM (fuera de scope).
- Dominio mostrado es best-effort (caché DNS del sistema + resolucion activa del catalogo cada 5 min, inmune a CNAME/CDN); el match va por IP contra dominios conocidos, o por hosts extra que anadas tu.
- Sin Sysmon, el polling (5 s) puede perder conexiones muy breves. Con Sysmon activo (recomendado), cada conexion es un evento: nada se pierde.

## Sysmon (fuente v2, opcional pero recomendada)

Con Sysmon instalado, AI NetWatch usa **EventID 3** como fuente adicional al polling:

- **Conexiones breves**: es evento, no foto -> una conexion de 0.4 s queda registrada.
- **Ruta completa del proceso** (`image`): detecta masquerading (ej. `svchost.exe` fuera de System32) y desambigua PIDs.
- Watermark: al arrancar fija el ultimo `RecordId` visto **sin backfill** (no inunda con historico); a partir de ahi, cada evento nuevo pasa por el mismo pipeline (match catalogo + store).
- Toggle en vivo en la UI (checkbox *Sysmon*); sin reiniciar.

Instalacion (una vez, requiere admin):

```powershell
# Descarga oficial (v15+): https://live.sysinternals.com/Sysmon.exe
Sysmon64.exe -accepteula -i
```

Notas v15: servicio `Sysmon64`, canal de eventos `Microsoft-Windows-Sysmon/Operational` (en v14 era `...-Operational`), campos `DestinationIp`/`DestinationHostname` (antes `DestinationAddress`). Sin config XML: Sysmon loguea todo y AI NetWatch filtra por catalogo.

## Arranque

```powershell
cd C:\Users\Sammi\ai-netwatch
python -m venv .venv
.\.venv\Scripts\pip install fastapi uvicorn
.\.venv\Scripts\python -m uvicorn server:app --host 127.0.0.1 --port 8790
```

Abrir `http://127.0.0.1:8790`. Config (solo memoria, se pierde al reiniciar): key Jev, LLM local (URL loopback + modelo), hosts extra (IP o dominio propios que quieras vigilar).

## Endpoints

- `GET /api/events?limit=&process=&dest=`
- `POST /api/triage` (`{"event_ids": [...]}` opcional; sin ids = todos)
- `GET /api/triages/latest`
- `GET/POST /api/config` (key Jev maskeda en lecturas)
- `POST /api/test` (`{"target": "jev"|"llm"}`)
- `GET /api/export/json`, `GET /api/export/csv`

## Contrato Jev (exacto)

Modelo pin `jev-1.13.0`, una llamada batch por triaje (cap 50 eventos). State por evento: `process, dest_ip, dest_port, dest_host, catalog_domain, seen_count, first_seen, last_seen, user_active="unknown"`. Preguntas con criteria contrastivas:

1. **Choice** — `expected_ai_use` / `background_exfil_suspect` / `telemetry_noise` / `unrelated`
2. **Score 0-3** — criticidad de exfiltracion (0 esperado/sin datos; 1 telemetry baja sensibilidad; 2 background a destino ambiguo; 3 probable exfiltracion activa)
3. **Noul** — requiere accion inmediata ahora?

Derivado: `prob_false_positive` = 1−confianza si `expected_ai_use`, confianza en el resto. Coste por triaje ~$0.001-0.002.

## Tests

```powershell
.\.venv\Scripts\python -m unittest discover tests -v
```

(sin red; HTTP mockeado)
