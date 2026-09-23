# CHANGELOG

Resumido; lo detallado esta en el historial de git y en las notas del vault.

## Sesiones y beaconing (F1/D3, v2.1) — episodios de conexion, no polls

### Anadido
- **F1 sesiones**: sesion = transicion ausente->presente por clave
  (proceso, IP, puerto). Un keep-alive largo que sigue presente en cada
  poll NO suma (sigue siendo 1); un reconnect si. Sysmon EID 3 y polling
  alimentan el mismo set de presencia: sin doble conteo. Persistido:
  `events.sessions` (acumulado) + tabla `sessions_log` (timestamps por
  sesion; techo 50 por clave, prune con la retencion).
- **D3 beaconing**: CV (coef. de variacion) de los inter-arrival sobre la
  ventana de los ultimos 20 timestamps; beaconing si N>=5 y CV<=0.3
  (periodicidad regular: beacon, no keep-alive). Persistido `iat_cv` +
  `beacon_score`; `new_beaconing` solo en la transicion.
- **Jev**: `sessions`, `iat_cv`, `beaconing` en el payload.
- **Alerta `beaconing_ai_call`**: una por clave IA que transita a
  beaconing; el reset limpia el dedup y re-alerta. No-IA no alerta.
- **UI**: columna *Sesiones* (badge `beacon`) y *Polls* (antes *Veces*):
  la diferencia entre muestras y episodios es visible.
- Tests: aceptacion (sintetica cada 60 s -> CV~0 -> beaconing; keep-alive
  -> sessions=1 sin beacon), transiciones ausente->presente, techo de
  ventana, callback una sola vez, dedup de alerta / no-IA, payload Jev
  (`tests/test_f1_d3.py`).

## Autonomía (R2, v2.1) — quién hace la salida a IA

### Añadido
- **`autonomy.py`**: señales locales (ctypes/stdlib, fail-safe): idle global
  (`GetLastInputInfo`) con dos guardas de honestidad: idle > uptime →
  `None` de inmediato (valor imposible — p. ej. sesión sin entrada
  reportando un contador viejo), y auto-diagnóstico de vida (contador que
  no avanza → `None`). Nunca inventa autonomía: `idle=None ⇒ unknown`,
  nunca autonomous. Sesión bloqueada/pantalla apagada (presencia de
  `LogonUI.exe`), foreground PID (`GetForegroundWindow`).
- **Linaje de autonomía** vía Sysmon EID 1 (`poll_sysmon_process_creation`):
  padre servicio (`svchost`) o tarea programada (`schtasks`/Task Scheduler)
  → flags `service_parent` / `scheduled_task`.
- **Derivado por evento, persistido**: `autonomy_score` 0–100 +
  `autonomy_flags` + veredicto `user_driven | autonomous | scheduled |
  unknown`. Reglas: bloqueo o idle ≥5 min → autónomo; linaje schtasks →
  programado; usuario activo (<60 s) → user_driven; resto, unknown.
- **Jev**: `user_active` ya no es siempre "unknown": lleva el veredicto
  persistido del evento.
- **Veredictos y vida de la conexion**: el veredicto se recalcula en cada
  observacion (se sobreescribe). Una conexion desaparecida conserva su
  ultimo veredicto hasta que la conexion vuelva a ser observada; el reset
  limpia todo. Sin re-evaluacion al arrancar: las senales del arranque
  tienen la misma ventana de basura que cualquier otro momento.
- **Alerta `autonomous_ai_call`**: una por (proceso, proveedor); el reset
  limpia el dedup y re-alerta.
- **`GET /api/autonomy`**: señales globales del momento + eventos con
  veredicto autónomo/programado. UI: tarjeta *Autonomía* + columna de
  veredicto en la tabla de eventos.
- Tests: evaluate (reglas y caps), señales smoke, persistencia/overwrite,
  filtro `autonomy_events`, payload Jev, dedup de alertas, linaje EID 1
  (`tests/test_autonomy.py`).

## Panel / dashboard (v2.0) — actividad agregada, sin F1

### Añadido
- **`GET /api/dashboard?days=7`** (clamp 1..365): agrega lo que ya existe.
  Actividad diaria (eventos/triajes), top proveedores y procesos por
  presencia (`seen_count`, polls — no sesiones; F1 pendiente para v2.1),
  reparto por capa (catalog/llm/heuristic = cobertura real), nº de
  shadow AI, y LLM Inspector local (llamadas/tokens/bytes).
- **Bytes cloud**: `cloud_bytes.available=false` con motivo — no disponible
  para TLS remoto (ETW/logman, v2.1). Honestidad: un "no disponible",
  no un cero que engane.
- **UI**: tarjeta *Panel* arriba de todo, refresh 60 s; enlace a la tarjeta
  Shadow AI.
- `Store.events_since(days)`, `LlmCallStore.summary(days)` (agregados SQL).
- Tests: tops ordenados, capas, shadow count, resumen LLM, corte por días,
  clamp de days (`tests/test_dashboard.py`).

## Shadow AI (v2.0) — detectar vs aprobar

### Añadido
- **Shadow AI**: IA detectada que no esta aprobada. Proveedor de un evento =
  `sni_domain > catalog_domain > dest_host > dest_ip` (mismo orden que las
  alertas). Aprobado = catalogo (si `catalog_approved`, por defecto True) union
  `approved_providers` (match por sufijo de dominio; IPs, exacto).
- **`GET /api/shadow`**: agrupado por proveedor — procesos, capas,
  first/last seen, seen_count, event_ids. Solo lo no aprobado.
- **UI**: tarjeta *Shadow AI* con lista y boton *Aprobar proveedor* por item
  (desaparece al aprobar; se guarda en `approved_providers`).
- **Alerta `shadow_ai`**: una por proveedor no aprobado, distinta de
  `new_ai_destination` (que sigue siendo "destino IA nuevo", aprobado o no).
  Se reevalua al cambiar `catalog_approved`/`approved_providers`.
- Config: `catalog_approved: bool = True`, `approved_providers: list[str] = []`.
- Tests: proveedor, sufijo/IP exacto, agrupacion, config persistente, dedup de
  alerta (`tests/test_shadow.py`).

## Puerta de publicacion v2.0 (2026-09-23) — DPAPI, CI, LICENSE, SECURITY, mypy

### Seguridad
- **Key Jev cifrada en reposo con DPAPI** (`secret_store.py`, ctypes stdlib):
  `data/config.json` ya no guarda la key en claro; un config antiguo en claro se
  migra solo al arrancar. Fail-safe: si DPAPI no esta o el blob no descifra
  (otra cuenta/maquina), se trata como "sin key" sin romper el arranque. `data/`
  esta en `.gitignore` (nada sensible sale al push).

### Calidad / producto
- **CI** (`.github/workflows/ci.yml`, Windows): `ruff` + `mypy` + `unittest`.
- **mypy en verde** (22 archivos); config en `mypy.ini`. Correcciones de tipos en
  `store.py`, `jev_triage.py` y `server.py` (helper `_req_store`, guardas de
  `None`, tipado de `result`); sin cambios de comportamiento.
- **LICENSE** (MIT) y **SECURITY.md** (modelo de seguridad y como reportar).

## v2.0-alpha (2026-09-23) — R1 cobertura universal + egress en bytes

### Añadido
- **Cobertura universal (R1)**: Sysmon EventID 22 (DnsQuery) como fuente; join
  proceso -> dominio -> IP real (`QueryResults`), no heuristico. Un proveedor/SDK
  no listado se ve si resolvio DNS.
- **Clasificador en 3 capas** (`ai_classifier.py`): catalogo (evidencia) ->
  heuristica (senal `.ai`/token IA, a revisar) -> LLM local (bajo demanda, cache
  por dominio, fail-safe). Cada evento lleva `ai_layer`, visible en la UI
  (columna *IA (capa)*). Dominio sin clasificar = visible, nunca oculto.
- **Egress medido en bytes** (LLM Inspector): `request_bytes` / `response_bytes`
  por llamada (medida real del wire) + total en la tarjeta.
- **Retencion (F7)**: config `retention_days` (default 90, rango 1–3650,
  persistida). Prune de eventos/triajes/llm_calls mas antiguos que N dias +
  `VACUUM`; corre en el arranque y cada 24 h desde el monitor. El historico
  diario (`daily_stats`) se conserva. Input visible en Ajustes.
- **Alertas (O3)**: `alerts.py` — cola en memoria acotada + log JSONL
  (`data/alerts.log`) + webhook opcional (solo loopback, SSRF-check). Primer
  trigger: `new_ai_destination` (pareja proceso->destino IA no vista antes).
  Toast en la UI (poll `/api/alerts`). Toggle y webhook en Ajustes. El motor de
  reglas por umbral llega en v2.1.
- **Clasificador automatico** (`auto_classify.py`): job periodico del server
  (hilo daemon, 60 s; fuera del monitor) que resuelve los dominios en capa 0.5
  con el LLM local. Prompt JSON estricto `{is_ai, provider, category,
  confidence}` con criterios contrastivos y ejemplos; contexto = dominio +
  proceso. Cache persistente `domain_classifications` (TTL 30 d), rate-limit
  10 s entre dominios, backoff si el LLM cae. Resultado: eventos pasan de
  `heuristic` a `llm`; el catalogo nunca se pisa; sin LLM = no-op.
- **Retencion separada para llm_calls** (`retention_days_llm`, default 30 d;
  eventos siguen a 90 d): el contenido en claro lleva vida mas corta. Opcion
  `llm_store_content`: apagado, solo se persisten metadatos y bytes.
- **Rotacion de `alerts.log`** por tamano (1 MiB, una generacion `.1`).

### Cambiado
- Eventos: nueva columna `ai_layer`. LLM calls: nuevas columnas
  `request_bytes`/`response_bytes` (migracion automatica para bases antiguas).
- Monitor: nuevo ciclo EID 22; un dominio aprendido solo por EID 22 se registra
  solo si el clasificador lo marca IA (no inundar con trafico no-IA).

### Corregido
- Arranque roto por `@app.on_event("startup")` sobre `_on_new_ai_event`
  (FastAPI lo invocaba sin args -> TypeError en el startup; la suite no lo
  cubria porque no ejecuta el lifespan). Test de regresion sobre los
  handlers de arranque.
- `response_bytes`: ahora es un contador total (`total += len(chunk)`) en el
  bucle de recv, independiente del buffer de parseo limitado a `MAX_PARSE_BUF`
  (2 MB). Antes subcontaba respuestas >2 MB (generaciones largas, audio).
  `request_bytes` ya era correcto.

### Limitaciones honestas
- Bytes/payload del trafico TLS **remoto** siguen sin verse (requiere ETW
  `Kernel-Network` [pywin32/nativo, rompe "solo stdlib"], Npcap loopback
  [ausente] o MITM). El egress en bytes es solo para el LLM local.
- La capa LLM del clasificador es bajo demanda, no en vivo; la heuristica es
  senal, no verdad.

## v1.4 (2026-09-22) — R3 observabilidad pura
- Cobertura por endpoint (chat/tool-calling, completions, embeddings, audio,
  images), registro de fallos de upstream (`status 0`), auto-observacion, enlace
  local llamada->evento. Fix: `llm_calls` no era global en `_start`.

## v1.3 — LLM Inspector (R3 minimo)
- Reverse proxy stdlib en loopback; llamadas con prompt/respuesta/tokens/PID en
  `data/llm_calls.db`.

## v1.2 / v1.1 / v1.0
- PDF export stdlib, SNI por tshark, Sysmon EID 3, triage Jev, LLM local
  explicador, store SQLite, UI con estadisticas y export JSON/CSV.
