# CHANGELOG

Resumido; lo detallado esta en el historial de git y en las notas del vault.

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
