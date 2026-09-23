# AI NetWatch (v2.0-alpha)

Monitor local de **salidas de red hacia proveedores cloud IA** (OpenAI/Azure, Anthropic, Google, TypeSafe/Jev, Groq, OpenRouter, Mistral, Cohere, Hugging Face, DeepSeek, xAI, Together, Replicate...). Lo que ve: **proceso (+ruta completa con Sysmon) + destino IP/puerto + protocolo TCP/UDP + periodicidad + dominio real por SNI** de cada conexion establecida a un destino IA. Incluye estadisticas diarias (7+ dias), export JSON/CSV y tema claro/oscuro.

- Solo loopback (`127.0.0.1`), puerto 8790.
- **Jev (TypeSafe)** como juez de criticidad, a demanda (boton *Triar eventos con Jev*): clasificacion `expected_ai_use / background_exfil_suspect / telemetry_noise / unrelated`, criticidad 0-3, accion inmediata y **probabilidad de falso positivo** derivada.
- **LLM local** (OpenAI-compatible, SOLO loopback, sin key): explicaciones tecnicas en espanol de los eventos marcados.
- Fail-safe: sin IA configurada la vista clasica funciona igual; ningun error de IA rompe el monitor.
- Sin dependencias nuevas: FastAPI + stdlib (el monitor usa `Get-NetTCPConnection` via PowerShell).

## Limitaciones honestas

- No ve **bytes/payload del trafico TLS remoto**: para un proveedor remoto solo se ve la conexion (proceso/destino/periodicidad) y el dominio (SNI/EID22), no cuanto sale. El egress en bytes SI se mide, pero solo para el LLM local via el proxy inspector (HTTP plano en loopback). Bytes remotos requieren ETW `Kernel-Network` (pywin32/helper nativo, rompe "solo stdlib") o Npcap loopback (adaptador ausente) o MITM.
- El dominio SNI es el declarado en el **handshake TLS** (tshark): definitivo e inmune a CNAME/CDN, pero solo lo ve en sesiones TLS nuevas; una keep-alive que ya estaba establecida cuando arranco la captura no vuelve a decir SNI. Sin tshark, cae al dominio best-effort (cache DNS + resolucion activa del catalogo cada 5 min).
- Sin Sysmon, el polling (5 s) puede perder conexiones muy breves. Con Sysmon activo (recomendado), cada conexion es un evento: nada se pierde.

## tshark: dominio real por SNI (v1.1)

Con `tshark` instalado (Wireshark, `C:\Program Files\Wireshark\tshark.exe`), AI NetWatch arranca una captura continua en la interfaz activa y filtra **ClientHello** (`tls.handshake.type==1` sobre `tcp port 443`): por cada handshake extrae `ip.dst/ipv6.dst + tcp.dstport + SNI` y lo **anexa al evento ya registrado con ese IP:puerto** (columna *Dominio (SNI)*; si el evento no tenia catalogo, se completa con el dominio real).

- Deteccion de interfaz automatica (probe en paralelo; descarta VMware/Bluetooth/VirtualBox en la primera pasada). IPv4 e IPv6.
- Fail-safe: sin tshark o sin interfaz activa, el monitor funciona igual sin SNI. El checkbox *tshark* de la config se desactiva solo si no hay binario.
- El proceso tshark hijo se gestiona siempre (muerto al parar; nunca queda huérfano: un huérfano interfiere con Npcap y con los probes).
- Privacidad: es observacion pasiva del trafico local; los datos viven en el proceso tshark y en memoria, y solo se persiste el par (IP:puerto -> SNI) de destinos que ya son eventos. No se guarda payload ni contenido.
- Nota tecnica: por pipe tshark emite ASCII (UTF-16LE solo al redirigir a fichero); el lector usa `readline()` porque `read(n)` se bloquea en pipes de Windows.

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

## Cobertura universal de proveedores (R1, v2.0-alpha)

Un catalogo de ~20 dominios no es cobertura: cualquier proveedor nuevo o SDK no listado se cuela. R1 lo cierra con dos piezas:

- **Sysmon EventID 22 (DnsQuery)** como fuente adicional: por cada consulta DNS queda `proceso + dominio consultado + IPs resueltos` (`QueryResults`). El join es **proceso -> dominio -> IP real**, no heuristico: una conexion a esa IP se enlaza al dominio que el proceso resolvio, aunque ese dominio no este en el catalogo ni en la cache DNS.
- **Clasificador en 3 capas** (`ai_classifier.py`), por evidencia y no por heuristica sola:
  1. **Catalogo** (evidencia directa): dominio del catalogo -> proveedor conocido, confianza 1.0.
  2. **Heuristica** (senal de revision, NO evidencia): token IA o TLD `.ai` en el dominio -> se muestra para revisar, confianza 0.5, no se afirma.
  3. **LLM local** (opcional, con cache persistente por dominio y fail-safe): para resolver los dominios que quedan en 0.5. Corre **automaticamente** como job periodico del server (hilo propio, no del monitor: una llamada lenta no bloquea el poll de 5 s), con rate-limit entre dominios, backoff si el LLM cae y TTL de reclasificacion (30 d). Sin LLM local configurado es no-op: el dominio queda en 0.5, visible. El catalogo (1.0) siempre gana; el clasificador solo rellena incognitas.

Cada evento lleva su capa (`ai_layer`: catalog/heuristic/llm/unlisted) visible en la UI (columna *IA (capa)*). Un dominio que no cae en ninguna capa queda **"sin clasificar"**: visible, nunca oculto. Para no inundar con trafico no-IA de internet, un dominio aprendido solo por EID 22 se registra **solo si el clasificador lo marca como IA**.

## LLM Inspector (R3, v1.3-v1.4)

Reverse proxy **solo stdlib** en loopback para inspeccionar las llamadas HTTP de un cliente a un LLM local OpenAI-compatible (p. ej. `llama-server`):

- Escucha `127.0.0.1:<puerto>` (por defecto 8098) y reenvia al target configurado (por defecto `127.0.0.1:8099`, **solo loopback**; misma validacion SSRF que `llm_base_url`).
- Registra por llamada en `data/llm_calls.db` (SQLite aparte de `events.db`): path, modelo, **prompt y respuesta completos** (truncados a 64 KB con tamano real), tokens (`usage` si el servidor los reporta), latencia, streaming o no, y PID del cliente (via `iphlpapi`, Windows).
- Cobertura por endpoint: chat/completions (incluido tool-calling), completions legacy, embeddings, audio e imagenes. Embeddings e imagenes no persisten el dato crudo (vectores/b64): solo metadatos. Un intento que no conecta al upstream queda registrado como fallo (`status 0`).
- Streaming SSE: se reenvia byte a byte tal cual; el contenido se acumula para el registro sin tocar el framing.
- **Auto-observacion**: si `llm_base_url` apunta al mismo upstream que el target del proxy, las llamadas propias de NetWatch (explicador y test) tambien pasan por el proxy y quedan registradas. La config no se reescribe; el proxy nunca apunta a si mismo (sin bucle).
- **Egress medido (bytes)**: por llamada se registran `request_bytes` (cuerpo que sale hacia el LLM) y `response_bytes` (bytes totales que vuelven). Es medida real del wire, no estimacion: `response_bytes` cuenta cada chunk recibido en el bucle de proxy, independiente del buffer limitado que se retiene para parsear (por tanto es exacto tambien para respuestas >2 MB, streaming y audio); base del dashboard de egress (v2.1).
- **Enlace local**: cada llamada intenta enlazarse con el evento de red del mismo destino, proceso y ventana temporal (120 s), si ese destino esta siendo vigilado.
- Toggle en vivo en la UI (tarjeta *LLM Inspector*); para inspeccionar, apunta el cliente al puerto del proxy.
- **Limite honesto**: solo cubre el LLM local (HTTP plano en loopback). Un proveedor remoto viaja cifrado y su contenido no se ve; de el se ve la conexion (eventos de red), no el prompt.
- **Privacidad**: prompts/respuestas quedan en claro en `llm_calls.db`. `POST /api/llm/calls/reset` (`{"confirm": true}`) los borra.

## Arranque

El venv ya existe (`C:\Users\Sammi\ai-netwatch\.venv`, creado con `uv`, Python 3.12 +
fastapi 0.141.1 + uvicorn 0.53.0). Arranque unificado con los demas servicios locales
(puerto 8790):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\Sammi\scripts\services-up.ps1 -Service ai-netwatch -Wait
# -Status estado, -Stop parar; log en C:\Users\Sammi\logs\servicios\services-up.log
```

Arranque automatico al iniciar sesion (y tras un reinicio): `services-up.ps1` servicio
`ai-netwatch` (8790), lanzado por `...\Startup\servicios-locales.vbs` con watchdog cada 120 s.
Recrear el entorno desde cero si hace falta:

```powershell
cd C:\Users\Sammi\ai-netwatch
uv venv --python 3.12
uv pip install fastapi uvicorn
```

Abrir `http://127.0.0.1:8790`. La config es **persistente** (`data/config.json`): key Jev, LLM local (URL loopback + modelo), hosts extra (IP o dominio propios que quieras vigilar), toggle Sysmon y toggle tshark sobreviven al reinicio.

## Motor de reglas (v2.2)

`rules.py` evalúa cada 60 s el estado existente con reglas por umbral:
**service_ai_call** (veredicto autónomo/programado llamando a IA no
aprobada), **beacon_unapproved** (beaconing N≥5, CV≤0.3 a proveedor no
aprobado) y **egress_volume_unapproved** (>X MB a IA no aprobada según
bytes remotos; `available=false` sin datos de colector). Cada regla que
pasa a disparar genera una alerta `rule_fired` (una por regla; reset
re-alerta). Config: `rules_enabled`, `rule_egress_mb_per_day`. UI:
tarjeta *Reglas*.

## Bytes remotos (v2.2)

`netcollector.py` es un colector **elevado** (UAC, opt-in) que traza
`Microsoft-Windows-Kernel-Network` con logman/tracerpt (~N s por ciclo),
parsea el XML **por nombre de campo** y suma bytes por destino (solo
copia de datos TCP/UDP; sin loopback ni DNS). El servidor (no elevado)
solo lee el JSONL resultante y lo acumula en `net_bytes`; nunca
interpreta ETLs. Config: `net_bytes_enabled` (off por defecto),
`net_bytes_duration_s`, `net_bytes_cycle_s`. Con datos, el dashboard
muestra `cloud_bytes` real (total + top proveedores); sin admin o sin
datos, "no disponible" con motivo — nunca un cero que engane. El
colector escribe una linea meta de diagnostico (`events_seen`, `rows`,
`xml_ok`, `etl_found`) que el panel expone como `last_meta`: distingue
"corrio y no hubo trafico" de "fallo".

**Elevacion sin prompt (v2.2.1)**: una vez creada la tarea programada
`AI-NETWATCH-NetBytes` ("Run with highest privileges"), cada ciclo se
dispara con `schtasks /run`: sin UAC por ciclo y funciona aunque el
servidor corra desde un proceso de fondo oculto. Setup unico, desde una
consola ELEVADA:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup_netbytes_task.ps1
```

Si la tarea no existe, degrada al UAC por ciclo (solo funciona desde
consola interactiva). Opt-in (`net_bytes_enabled`) y visible a propósito;
el panel muestra `spawn_method` (`task`/`uac`) para saber que camino
corrio.

**Diagnostico**: cada ciclo escribe lineas en `data/netbytes.log`
(arranque del hilo, transiciones de `net_bytes_enabled`, inicio de ciclo
con deteccion de tarea, metodo de spawn, ingesta o fallo). Si el panel
dice "no disponible", ese fichero dice por que.

**Config**: los cambios van por el panel / `POST /api/config` (o editar
`config.json` y reiniciar): el servidor carga el config en memoria al
arrancar; una edicion del fichero con el servidor vivo no se ve hasta
el restart.

## Sesiones y beaconing (F1/D3, v2.1)

**Sesiones (F1)**: una sesión es una transición ausente→presente por clave
(proceso, IP, puerto); un keep-alive largo que sigue presente en cada poll
sigue siendo 1 sesión, un reconnect suma. `events.sessions` + tabla
`sessions_log` (timestamps, prune con la retención). **Beaconing (D3)**: CV
de los inter-arrival sobre la ventana de los últimos 20 timestamps;
beaconing si N≥5 y CV≤0.3 (periodicidad regular → beacon, no keep-alive),
con `iat_cv`/`beacon_score` persistidos, alerta `beaconing_ai_call` (una
por clave IA) y badge `beacon` en la tabla de eventos (columna *Sesiones*;
*Polls* es el antiguo *Veces*). Jev recibe `sessions`, `iat_cv`,
`beaconing`.

## Autonomía (R2, v2.1)

Detectar IA no dice **quién** decide la salida. R2 persiste por evento
`autonomy_score` (0–100) + flags + veredicto `user_driven | autonomous |
scheduled | unknown`, derivado de: sesión bloqueada/pantalla apagada
(LogonUI), usuario inactivo (`GetLastInputInfo`), foreground PID y linaje
del proceso vía Sysmon EID 1 (padre servicio/tarea programada). Jev recibe
`user_active` real; una salida autónoma/programada dispara la alerta
`autonomous_ai_call`. `GET /api/autonomy` expone señales del momento +
eventos con veredicto.

## Panel (v2.0)

`GET /api/dashboard?days=7` (clamp 1..365) agrega lo que ya existe: actividad
diaria, top proveedores/procesos por presencia (`seen_count` = polls, no
sesiones), reparto por capa, nº de shadow AI y LLM Inspector local
(llamadas/tokens/bytes). **Bytes cloud: no disponible para TLS remoto**
(`cloud_bytes.available=false` con motivo; ETW Kernel-Network en v2.2,
requiere admin) — un "no
disponible", no un cero que engane.

## Shadow AI (v2.0)

Detectar IA (catalogo + capas) no es lo mismo que aprobarla. **Shadow AI** =
IA detectada cuyo proveedor no esta aprobado:

- Proveedor de un evento: `sni_domain > catalog_domain > dest_host > dest_ip`.
- Aprobado = catalogo (si `catalog_approved`, por defecto) union
  `approved_providers` (match por sufijo de dominio; IPs, exacto).
- UI: tarjeta *Shadow AI* con boton *Aprobar proveedor* por item.
- Alerta `shadow_ai`: una por proveedor no aprobado (ademas de
  `new_ai_destination`, que sigue siendo "destino IA nuevo", aprobado o no).

## Endpoints

- `GET /api/events?limit=&process=&dest=`
- `GET /api/shadow` (IA detectada no aprobada, agrupado por proveedor)
- `GET /api/dashboard?days=7` (panel: actividad, tops, capas, shadow, LLM local)
- `GET /api/autonomy` (R2: señales globales + eventos autónomos/programados)
- `POST /api/triage` (`{"event_ids": [...]}` opcional; sin ids = todos)
- `GET /api/triages/latest`
- `GET/POST /api/config` (key Jev maskeda en lecturas; incluye `llm_proxy_enabled/port/target`, `catalog_approved`, `approved_providers`)
- `POST /api/test` (`{"target": "jev"|"llm"}`)
- `GET /api/llm/calls?limit=`, `GET /api/llm/calls/{id}`, `POST /api/llm/calls/reset`
- `GET /api/export/json`, `GET /api/export/csv`, `GET /api/export/pdf`

Los tres exports se descargan (`Content-Disposition: attachment`) y se generan en memoria solo con datos del store: **ninguno incluye la config ni API keys** (verificado por tests). El PDF (writer stdlib, sin dependencias) lleva cabecera, eventos, ultimo triaje Jev y estadisticas de 7 dias.

## Contrato Jev (exacto)

Modelo pin `jev-1.13.0`, lotes de hasta 50 eventos por llamada (cubre todos los eventos; si un lote falla, reintenta por trozos de 10). State por evento: `process, dest_ip, dest_port, dest_host, sni_domain, catalog_domain, seen_count, first_seen, last_seen, user_active` (veredicto de autonomía R2), `sessions, iat_cv, beaconing` (F1/D3) (el titulo usa el dominio SNI si existe, porque es el real). Preguntas con criteria contrastivas:

1. **Choice** — `expected_ai_use` / `background_exfil_suspect` / `telemetry_noise` / `unrelated`
2. **Score 0-3** — criticidad de exfiltracion (0 esperado/sin datos; 1 telemetry baja sensibilidad; 2 background a destino ambiguo; 3 probable exfiltracion activa)
3. **Noul** — requiere accion inmediata ahora?

Derivado: `prob_false_positive` = 1−confianza si `expected_ai_use`, confianza en el resto. Coste por triaje ~$0.001-0.002.

## Seguridad

- **Solo loopback**: el servidor solo escucha `127.0.0.1:8790`; no hay auth porque no hay superficie externa.
- **SSRF en `llm_base_url`** (el unico punto de HTTP saliente a destino elegido por el usuario): se exige URL absoluta `http(s)` cuyo host resuelva a loopback. Publico, metadata cloud (`169.254.169.254`), `file://`, `gopher://` y rutas relativas -> 400. Al cargar la config desde disco el mismo check se revalida (un archivo editado a mano no activa una URL peligrosa).
- **Endpoint Jev pinado**: `jev_base_url`/`jev_model` NO son configurables por la API; siempre TypeSafe oficial + modelo pin.
- **Reset protegido**: `POST /api/reset` exige `{"confirm": true}` (400 si no).
- **Exports sin path traversal**: el contenido se genera en memoria; ningun endpoint toma nombres de archivo del usuario.
- **tshark pasivo y gestionado**: la captura solo emite SNIs (sin payload); no hay forma de apuntarla a otra interfaz desde la API (la interfaz la elige el arranque localmente).
- **Proxy inspector en loopback**: `llm_proxy_target` exige `host:port` cuyo host resuelve a loopback (400 si no; revalidado al cargar config). El proxy solo escucha `127.0.0.1`; los logs de llamada son por diseño el contenido de las llamadas (inspeccion local, no exfiltracion).
- **Secretos en reposo (DPAPI)**: la API key de Jev se cifra con DPAPI (`secret_store.py`, ctypes stdlib) y nunca se escribe en claro en `data/config.json`; un config antiguo en claro se migra solo al arrancar. Si DPAPI no esta disponible, la key no se persiste. `data/` esta en `.gitignore`.
- Suite dedicada: `tests/test_security.py` (SSRF, persistencia + revalidacion, reset, inputs, fail-safe) y `tests/test_llm_proxy.py` (reenvio, streaming SSE, target loopback, toggle en vivo, reset).

## Calidad (CI)

CI en GitHub Actions (`.github/workflows/ci.yml`, Windows): `ruff check .`, `mypy .` y `python -m unittest discover tests`. Config de mypy en `mypy.ini` (`ignore_missing_imports`). Licencia MIT (`LICENSE`); politica de seguridad en `SECURITY.md`.

## Guia de uso

Dentro de la propia interfaz (tarjeta *Guia de uso*, enlace en el header): que ve y que no ve, fuentes de datos (polling/Sysmon/tshark), lectura de veredictos Jev, LLM local (explicador, no juez), LLM Inspector (R3), estadisticas/reset, exportacion, configuracion y el modelo de seguridad/privacidad. Contenido estatico: ninguna entrada del usuario se renderiza (sin superficie XSS).

## Tests

```powershell
.\.venv\Scripts\python -m unittest discover tests -v
```

(sin red; HTTP mockeado; incluye la suite de seguridad)
