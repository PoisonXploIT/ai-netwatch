# AI NetWatch

Monitor local de **salidas de red hacia proveedores cloud IA** (OpenAI/Azure, Anthropic, Google, TypeSafe/Jev, Groq, OpenRouter, Mistral, Cohere, Hugging Face, DeepSeek, xAI, Together, Replicate...). Lo que ve: **proceso + destino IP/puerto + periodicidad** de cada conexion establecida a un destino IA.

- Solo loopback (`127.0.0.1`), puerto 8790.
- **Jev (TypeSafe)** como juez de criticidad, a demanda (boton *Triar eventos con Jev*): clasificacion `expected_ai_use / background_exfil_suspect / telemetry_noise / unrelated`, criticidad 0-3, accion inmediata y **probabilidad de falso positivo** derivada.
- **LLM local** (OpenAI-compatible, SOLO loopback, sin key): explicaciones tecnicas en espanol de los eventos marcados.
- Fail-safe: sin IA configurada la vista clasica funciona igual; ningun error de IA rompe el monitor.
- Sin dependencias nuevas: FastAPI + stdlib (el monitor usa `Get-NetTCPConnection` via PowerShell).

## Limitaciones honestas (v1)

- No ve **bytes** ni **payload**: solo que un proceso abrio/mantiene conexion a un destino IA, con cuantas veces se repite. Para bytes y dominio real: v2 con Sysmon EventID 3.
- Dominio mostrado es best-effort (caché DNS del sistema); el match de catalogo va por IP contra dominios conocidos cuando el DNS lo resuelve, o por hosts extra que anadas tu.
- El polling (5 s) puede perder conexiones muy breves; las periodicidades cortas (<5 s) se subestiman.

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
