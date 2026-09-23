# CHANGELOG

Resumido; lo detallado esta en el historial de git y en las notas del vault.

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

### Cambiado
- Eventos: nueva columna `ai_layer`. LLM calls: nuevas columnas
  `request_bytes`/`response_bytes` (migracion automatica para bases antiguas).
- Monitor: nuevo ciclo EID 22; un dominio aprendido solo por EID 22 se registra
  solo si el clasificador lo marca IA (no inundar con trafico no-IA).

### Corregido
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
