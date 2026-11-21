# CHANGELOG

Resumido; lo detallado esta en el historial de git y en las notas del vault.

## Proximo

- Pendiente del humano: S-16 (limpieza de `data/`), S-17 (servidor con el Python del `.venv` y
  `--no-server-header`), S-18 (monitor en pausa, inspector LLM parado, re-registro elevado de
  `AI-NETWATCH-NetBytes`).
- Medir el efecto del modo `jev_minimal` (S-07) sobre la concordancia Jev/LAYA.

## v2.8 — JavaScript repartido en scripts pequeños

- A-01: los tests de UI leen todo el JavaScript en orden de carga
- A-02: el sello de assets cubre static/js
- A-03: app.js repartido en 12 scripts clásicos
- V-01: las tablas de triaje arrancan con 10 filas
- C-01: el humo comprueba que se sirven todos los scripts
- C-02: CHANGELOG de la v2.8
- S-20: test de higiene de todo el JavaScript
- S-21: el humo avisa si el servidor se anuncia



## v2.7 (2026-11-21) — UI profesional, seguridad de lecturas y accesibilidad

Plan ejecutado tarjeta a tarjeta por un LLM local (actas en el vault, `ACTA-2026-11-20-v27-*`).

### Bugs

- B-01: el strip lee jev_key_set desde health.sources
- B-02: eje Y sin marcas duplicadas
- B-03: las tablas anchas se desplazan dentro de su contenedor
- B-04: cabecera y contenido centrados
- B-05: etiqueta de autonomía en español en Hallazgos
- B-06: plurales correctos en el panel
- B-07: ortografía de los textos visibles
- B-07b: ortografía de los textos visibles restantes
- B-08: un solo acceso a la guía
- B-09: el strip distingue pausa de fallo y dice desde cuándo
- B-10: el strip muestra el estado real del inspector LLM
- B-11: los procesos sin nombre se agrupan en el filtro
- B-12: el historial de revisiones nace plegado salvo las 3 últimas
- B-13: acciones de hallazgo con texto
- B-14: nombre accesible en todos los controles
- B-15: navegación por teclado en las pestañas

### Seguridad

- S-10: token de sesión comparado en tiempo constante
- S-11: el Origin se valida por esquema, host y puerto
- S-12: Permissions-Policy, COOP, CORP y CSP con object-src y form-action
- S-13a: los exports se descargan con fetch y token
- S-13b: token de sesión obligatorio en lecturas sensibles
- S-14: test genérico de token en todas las rutas que cambian estado
- S-15: confirmación propia para reset y borrado de llamadas
- S-19: SECURITY.md describe el modelo de la consola

### Diseño

- D-01: tokens de escala tipográfica, radios y espacios
- D-02: tipografía en 5 tamaños
- D-03: radios en 4 valores
- D-04: colores solo desde variables de tema
- D-05: cabecera compacta y fija
- D-06: nivel del score con texto
- D-07: reglas de tabla
- D-08: estado de carga en todos los contenedores
- D-09: movimiento reducido y foco visible
- D-10: contraste AA comprobado por test
- D-11: etiqueta del donut fuera del anillo y leyenda con el color de su segmento
- D-12: auditoría de texto recortado (solo informe; sin hallazgos, sin commit)
- D-13: tamaño base del texto y familias desde los tokens
- D-14: las pastillas de leyenda no parten su texto

### UX

- U-01: buscador libre en Eventos
- U-02: última vez en formato relativo
- U-03: detalle de evento generado al abrirlo
- U-04: filas de hallazgo operables por teclado
- U-05: Resumen abre con lo que requiere atención
- U-06: el botón de triaje informa del progreso y del dedup
- U-07: el kill switch explica y confirma
- U-08: columnas esenciales en pantallas estrechas
- U-09: el LLM Inspector arranca con 10 llamadas
- U-10: viewport de móvil y textos largos que parten línea en estrecho

### Calidad

- Q-01: arranque y parada por lifespan
- Q-02: script de humo contra el servidor vivo
- Q-03: CI instala desde requirements.txt
- Q-04: ruff con reglas W
- Q-05: CHANGELOG v2.7 y guía actualizada

## v2.6(6) (2026-10-25) — cierre de la linea 2.6: seguridad, UI visual y segunda opinion local

- U-01: la key de Jev ya no se autodestruye al guardar (la mascara `***`
  devuelta por GET se conserva).
- S2/S3: guard de origen para todos los POST + CORS deny-all + cabeceras de
  seguridad.
- S9/S4: `GET /api/health`, token de sesion inyectado en la index y audit log
  (`data/audit.log`) que registra operaciones sin valores de secretos.
- S4/S2: retencion del colector (artefactos ETL/XML/JSONL huercos se limpian a
  las 24 h) + CSP estricta sin `unsafe-inline` + `esc()` completo (comilla
  simple incluida).
- S-03: prompt y respuesta del LLM Inspector cifrados con DPAPI
  (`llm_calls.db`).
- Bloque 4: CI verde con ruff + mypy y `requirements.txt`.
- U-02: version unica desde `server.VERSION` (UI, /api/health y exports
  JSON/PDF/STIX coinciden).
- S-08: puerto del inspector restringido a 8000-9999 con deteccion de
  colision.
- S-07: modo "solo dominios" (`jev_minimal`): a Jev no salen proceso, IP,
  puerto ni `user_active`. Documentado en el vault
  (`40-IA/PROYECTOS/AI-NETWATCH/S-07-QU-SE-ENVIA-A-JEV.md`).
- #10: el refresco periodico se acota a la pestana visible (38 req/min globales
  -> <= 12 req/min en la pestana activa) mediante `REFRESH_JOBS`.
- #11 (U2): cada fila de eventos tiene boton "detalle" con el registro completo
  (id, destino, SNI, catalogo, capa, anomalia, flags, MITRE) y, en las filas
  agrupadas, los miembros (hasta 10) con sus IPs.
- #6 (continuacion): la Guia pasa a ser una pestana mas (`panel-guia`), ya no un
  bloque suelto al final del `main`. El boton del header lleva a ella.
- Densidad: Config agrupada en 4 bloques (Motor de triaje, LLM local, Fuentes de
  datos, Alertas y retencion); el Panel usa `chips` en lugar de una `.row` por
  item y la tabla de proveedores se pagina (12 filas + "ver los N restantes");
  Autonomia pasa de lista de filas a tabla (`aut-table`) paginada (25 + "mostrar
  mas"); el LLM Inspector pinta 25 llamadas y un boton muestra el resto (antes
  volcaba hasta 100 sin recortar).
- Strip de estado bajo el header (`/api/health`, 1 req/min en Resumen): version,
  estado, kill switch, eventos, llamadas LLM, fuentes activas y key de Jev. Evita
  el "no hay datos" sin explicacion; las tarjetas vacias incluyen un aviso de
  como reanudar el monitoreo.
- Contadores en las pestanas (Hallazgos/Eventos/IA) y pestanas sticky al hacer
  scroll. Atajos 1..6 para cambiar de pestana (ignorados dentro de un campo).
- Cache de assets: `?v={{ASSETV}}` = version + suma de mtimes de app.js/styles.css
  /theme.js. Con `?v=VERSION` el navegador guardaba un app.js viejo aunque el
  codigo cambiara (causa real del "no hay pestanas", medida el 2026-10-25).
- `bind()` va envuelto en try/catch: si la UI no arranca, el strip lo dice en vez
  de dejar la pagina en blanco.
- Panel visual (no solo texto): sparkline de actividad diaria, barra apilada
  del reparto por capa (catalogo/heuristica/LLM/sin capa) con leyenda, gauge
  aprobados vs. no aprobados y barras horizontales por proveedor. Los tamanos
  van en `data-pct`/`data-h`/`data-w` y los aplica `paintBars` (la CSP sigue
  sin permitir `style` inline).
- Panel v2.6(7): las graficas de divs se veian mal con datos escasos (una
  barra de 3 px no es una grafica). Se reemplazan por SVG: serie de barras con
  eje Y, rejilla, etiquetas de dias/horas y tooltip nativo; donut de capas y
  donut de gobernanza (aprobados vs. shadow) con total en el centro; histograma
  de sesiones por hora UTC (las 00-06 se colorean aparte, es la franja de
  autonomia); barras de proveedor con color por capa; KPIs (eventos, presencias,
  procesos, proveedores, LLM local, bytes cloud) y una linea de lectura
  automatica (`panelTakeaway`) que dice que concentra cada cosa. La geometria del
  SVG va en atributos (`x`, `y`, `r`, `stroke-dasharray`), el color en CSS: la
  CSP `style-src 'self'` no se relaja. `/api/dashboard` añade `hourly` (24
  buckets), `sessions` y `verdicts` (veredictos Jev agregados).
- Key de Jev: bloque visual con estado (dot + fingerprint sha256 de 8 chars).
  `/api/config` devuelve `jev_key_fingerprint`; nunca la key. El fingerprint
  permite identificar CUAL key esta puesta sin exponerla.
- Toggle de `net_bytes_enabled` en Config (antes no habia forma de apagar el
  colector elevado desde la UI).
- Ventanas de PowerShell/CMD cada 10 min (v2.6(6)): la tarea
  `AI-NETWATCH-NetBytes` corre `powershell.exe` y Task Scheduler le crea
  consola con `LogonType Interactive`. El wrapper ahora solo lanza
  `pythonw.exe netcollector_task.py` (sin consola) y sale: la ventana vive
  ~50 ms en vez de 30 s. Para eliminarla del todo hay que re-registrar la
  tarea una vez, elevado:
  `powershell -NoProfile -ExecutionPolicy Bypass -File setup_netbytes_task.ps1`
  (el script ya apunta a `pythonw.exe` + `netcollector_task.py`).
- Fallback UAC: se intenta UNA vez por proceso. Antes se reintentaba cada
  ciclo, lo que significaba un prompt de UAC y una ventana cada 10 minutos.
- Tests: `tests/test_pipeline_e2e.py` (3) — pipeline de punta a punta en un
  store temporal: colector -> sesiones -> SNI/DNS/bytes -> baseline -> triaje
  Jev (stub) con dedup por firma -> hallazgos -> shadow -> autonomia -> panel
  -> exports JSON/CSV/PDF/chain/STIX, con comprobacion de que ningun export
  contiene la key y de que alterar una fila rompe la cadena de hashes.
  Suite: 491 OK.

### Cierre de v2.6(6) (2026-10-25, tarde)

- Juicio local en prosa (`llm_local.investigate_event`): ademas de la etiqueta
  tipada (`confirm/refuta/insuficiente`) devuelve `coincide`
  (`coincide/discrepa/dudoso`) y `juicio`, un parrafo en lenguaje llano que
  explica que hace el proceso, que dice el patron temporal y si el veredicto de
  Jev es defendible. Persiste en `llm_reviews` (columnas `coincide`, `juicio`,
  con migracion `ALTER TABLE` idempotente).
- LLM local apuntado al servicio real: `http://127.0.0.1:8080` con
  `qwen3.8-flash-next-q2_0` (antes `:8099` / `dirk-qwen3.8-27b-iq3`, puerto
  cerrado -> `WinError 10061` en las explicaciones).
- Pestanas de triaje reparadas: la CSP `script-src 'self'` bloqueaba los
  `onclick` inline, asi que Jev/LAYA no cambiaban. Ahora `data-tt` + listener
  delegado.
- Bug del contador de acuerdo: se sumaba `cmpN` pero nunca `cmpOk`, el acuerdo
  salia siempre 0 %.
- Panel de **Discrepancias Jev vs LAYA**: tercera pestana con ambas etiquetas,
  ambas confianzas y criticidad; columna "vs LAYA" en la tabla de Jev para verlas
  sin cambiar de pestana.
- Triaje grafico: dos donuts SVG (distribucion de veredictos de Jev y acuerdo
  Jev/LAYA) en lugar de una barra apilada. La regla `.tcompare .bar > div` ganaba
  por especificidad y pintaba todos los segmentos del mismo color.
- Revisiones LLM: `save_review` es upsert por evento (repetir la revision no
  acumula filas duplicadas; antes `#11` aparecia tres veces). El historial
  muestra proceso, destino, badges y el juicio en prosa.
- LLM Inspector: resumen agregado (llamadas, latencia media/mediana/p95, tokens
  prompt/respuesta, llamadas fallidas), histograma SVG de latencia y egress
  total en bytes.
- Ficha de la key de Jev: chip de estado (`activa - fingerprint 73bfffcf`) en
  lugar del estado metido en el `placeholder`; input con `aria-label`.
- LAYA: el lanzador `tools/laya_serve_ft.py` carga por defecto el checkpoint
  fine-tuned `ft-multilingual-2026-10-08-v4` (antes la v1 de 2026-10-04). El
  supervisor `arranque-laya.ps1` sirve el FT (parametros `-FtLauncher` y
  `-Checkpoint`) en lugar del checkpoint publico del Hub.
- Tests: 504 OK (ruff + mypy limpios). Nuevos: juicio en prosa y upsert
  (`test_investigate`), pestanas y graficas (`test_ui_density`).

Medido con la v2.6 real: acuerdo Jev/LAYA 23/29 (79 %); las 6 discrepancias son
`expected_ai_use` de Jev frente a `background_exfil_suspect`/`unrelated` de LAYA.
Jev sigue siendo el juez: la discrepancia se registra, no re-puntua.

## Pendiente del bloque UI

- Re-registrar la tarea `AI-NETWATCH-NetBytes` (elevado) para que el
  ejecutable sea `pythonw.exe` y desaparezca la consola.
- Medir densidad con datos reales (el kill switch esta pausado: 3 eventos).

## Hecho en v2.5(1) (tag v2.5(1))

v2.5(1) N1 — QUIC/HTTP-3: SNI del paquete Initial:
- Un solo proceso tshark captura TCP+UDP 443 a la vez (`udp port 443 or
  tcp port 443` + `tls.handshake.type==1`): el CRYPTO del paquete Initial
  de QUIC se descompone como TLS y el SNI sale en los mismos campos;
  el puerto llega en `udp.dstport`. Cierra el punto ciego HTTP/3 (el
  trafico H3 moderno se veia como conexion UDP 443 sin dominio).
- BPF/Npcap: `(tcp or udp) port 443` NO se parsea; lo valido es
  `udp port 443 or tcp port 443` (medido en vivo).
- Probe verificado en esta maquina (tshark 4.6.6): SNI real de H3
  (`www.google.com`, `www.cloudflare.com`) con Edge headless.
- Fix del punto ciego REAL que el probe revelo: las conexiones UDP a
  proveedores IA NUNCA llegaban a registrarse como eventos, porque
  (medido) `Get-NetUDPEndpoint` no reporta RemoteAddress en sockets UDP
  conectados (92 endpoints, 0 con remoto), Sysmon de esta maquina no
  emite EID3 para msedge.exe, y netstat omite sockets UDP IPv6. Ahora
  `poll_udp_endpoints` usa `netstat -ano -p UDP` (remoto+PID en v4):
  QUIC/HTTP-3 v4 a destino IA se registra con proceso y el SNI del
  paquete Initial se ancla al evento como en TCP.
- Limitacion honesta (medida): QUIC IPv6 sigue ciego de conexion
  (ninguna fuente da remoto+PID para UDP v6); el SNI SI se captura, pero
  sin evento al que anclarlo. Documentado en README.

Hecho en v2.4 (tag v2.4):
- fix prob_falso_positivo: ahora es 1 - conf para TODOS los veredictos
  (la confianza es sobre el veredicto elegido; antes, con veredictos
  sospechosos, salia la confianza cruda, que es lo contrario).
- Investigar con LLM local por evento (asesoria, NO re-puntuacion):
  `POST /api/investigate {event_id}`. Contexto truncado y sin secretos:
  evento + veredicto Jev del ultimo triaje (si existe) + sesiones/iat_cv/
  beaconing + autonomia + provider/kind + SDK del proceso + bytes locales
  del LLM de ese proceso. Respuesta JSON estricto {evaluacion:
  confirm|refuta|insuficiente, porque, evidencia_faltante} (campos
  truncados). Display-only: no altera veredictos ni aprobaciones; Jev
  sigue siendo el juez. Sin LLM configurado degrada a 'no disponible'
  (fail-safe); SSRF cubierto por llm_base_url (solo loopback). Boton
  "Investigar con LLM local" en la fila del evento, visible solo si
  llm_enabled; resultado en bloque debajo de la fila.

Hecho en v2.3 (tag v2.3):
- Evidence exportable: cadena de hashes + bundle STIX 2.1 (`evidence`,
  modulo puro, sin librerias externas). Cadena: cada fila liga indice +
  hash anterior + evento (genesis fijo); alterar cualquier fila rompe el
  resto y es verificable offline (`verify_chain`). STIX 2.1:
  network-traffic/process/ipv4-addr/ipv6-addr/port/domain-name + report;
  IDs deterministas (mismos eventos -> mismo bundle). Endpoints:
  `GET /api/evidence/chain` (JSONL) y `GET /api/evidence/stix`
  (`application/stix+json;version=2.1`), ambos con `?days=` (1..365);
  botones en la tarjeta Exportar.
### Filtros y agrupacion de eventos (v2.3)
- Vista con filtros (capa IA, autonomia, solo-no-aprobados, ocultar CDN,
  proceso/destino) y agrupacion por proveedor: colapsa las IPs
  rotatorias de CDN (python.exe -> huggingface.co: 104 IPs en una fila)
  sumando sesiones/polls.
- GET /api/events con layer/verdict/shadow/hide_cdn/group; cada fila
  lleva provider+kind.
- new_ai_destination deduplica por (proceso, proveedor): fin de las
  alertas repetidas por IP.
- Fingerprinting de SDK IA por proceso + artefactos (`sdk_fingerprint`,
  display-only; no toca deteccion ni aprobaciones): python/node con SDKs
  instalados en su arbol (site-packages / node_modules) -> label
  `python-sdk(...)`/`node-sdk(...)` sin depender del dominio destino.
  Alimentado por Sysmon EID1 (imagen + CommandLine). Superficie:
  `GET /api/processes` (ficha por imagen) y label `sdk` en
  `top_processes` del dashboard. El bloque "Procesos con SDK IA" del
  panel se alimenta de `GET /api/processes` (no hay campo
  sdk_processes en /api/dashboard). Sin artefacto verificable -> None,
  nunca inventa. JA3/JA4
  queda fuera a proposito: huella TLS compartida con navegadores,
  solo confirmacion, y stdlib no parsea TLS.
- `cloud_bytes.by_provider`: mapear los bytes "desconocido" (IPs sin
  evento que las mapee) a proveedor cruzando con dominios resueltos por
  EID22/SNI, no solo con `catalog_domain` de eventos.
- Tabla `dns_resolutions` persistida (ip->dominio desde el ciclo EID 22):
  sobrevive el restart y cierra el hueco de resoluciones que ya salieron
  de la ventana en memoria de los ultimos 300 DnsQuery.
- Label API / web / CDN por hostname (`destination_kind`, heuristica de
  display; no toca deteccion ni aprobaciones) + `host` resuelto en cada
  fila de `by_provider` para identificar el destino aunque el proveedor
  quede "desconocido". El panel dashboard lo renderiza (antes solo
  mostraba la rama "no disponible").

## v2.2.1 — Elevacion sin prompt: tarea programada (bytes remotos)

El colector elevado quedo verificado (B1/B2/B3), pero el spawn desde el
servidor fallaba: UAC desde un proceso de fondo oculto (`services-up`
con `-WindowStyle Hidden`) se niega en silencio. Diseno: una tarea
programada `AI-NETWATCH-NetBytes` con "Run with highest privileges",
creada UNA vez (elevada), que el ciclo dispara con `schtasks /run`:
sin prompt por ciclo, y funciona aunque el servidor corra oculto.

Ademas, fix del triaje Jev: antes `events[:50]` dejaba sin veredicto a
los eventos 51+ (filas vacias en la UI; con 144 eventos, 94 sin
clasificar). Ahora el triaje cubre TODOS los eventos en lotes de 50 y
fusiona veredictos por indice global; si un lote falla, reintenta por
trozos de 10. El destino del triaje usa la identidad IA
(`sni_domain > catalog_domain > dest_host > dest_ip`, mismo orden que
`_provider_of`): en vez de IPs crudas/CDN se ve `platform.deepseek.com`,
`huggingface.co`... La UI marca "no triado" explicito y cuenta
"triados X de Y" cuando hay parcialidad.
- `setup_netbytes_task.ps1`: setup unico desde consola ELEVADA
  (`Register-ScheduledTask`, RunLevel Highest, logon interactivo,
  `AllowStartOnDemand`).
- `netcollector_task.ps1`: accion de la tarea; lee
  `data\netcollector_cmd.json` (python/script/duracion/salida en rutas
  absolutas) y lanza `netcollector.py`. Error =>
  `data\netcollector_task_error.txt`.
- Servidor: si la tarea existe, `schtasks /run` (sin elevarse); si no,
  fallback al UAC por ciclo (solo consola interactiva). El panel expone
  `spawn_method` (`task`/`uac`) en `cloud_bytes`.
- Tests: spawn task vs UAC, contenido del cmd file, coherencia de los
  scripts. Sin admin ni UAC reales (mocks).
- **Fix setup**: `New-ScheduledTaskSettingsSet` no acepta
  `-AllowStartOnDemand` (el on-demand ya es default),
  `-MultipleInstancePolicy` (lo correcto: `-MultipleInstances`) ni
  `-StartWhenAvailable $false` (es un switch; se omite, default false).
  Con esos tres, el script tal cual nunca registraba la tarea.
- **Log de ciclo** `data/netbytes.log`: arranque del hilo, transiciones
  de `net_bytes_enabled`, inicio de ciclo con deteccion de tarea,
  metodo de spawn, ingesta o fallo. Distingue 'el bucle corre' de
  'config false en memoria'.
- Documentado: el config se carga en memoria al arrancar; editar
  `config.json` con el servidor vivo no tiene efecto hasta restart (los
  cambios van por panel / `POST /api/config`).
- **Fix persistencia (causa raiz del path roto)**: `_load_config` no
  cargaba las claves de v2.1/v2.2 (`rules_enabled`,
  `rule_egress_mb_per_day`, `net_bytes_enabled`, `net_bytes_duration_s`,
  `net_bytes_cycle_s`): tras cada restart (el watchdog reinicia a
  menudo) volvian a los defaults y el colector nunca disparaba. Ahora se
  cargan y validan rango (duracion 5..3600 s, ciclo 30..86400 s,
  umbral >0, bools). Test: POST `net_bytes_enabled=true` +
  `rule_egress_mb_per_day=42` => `_load_config()` => sobreviven; valores
  invalidos => defaults.

## Fix colector elevado (v2.2) — B1/B2/B3 + stop -ets

Correccion del camino elevado tras verificacion e2e en escritorio
(tres bugs independientes, todos en `netcollector.py`):
- **B1 keyword**: 0x8000... es el canal *Analytic* del provider, no IP.
  Ahora 0x30 = IPV4|IPV6 (verificado).
- **B2 glob ETL**: con `-ets` el fichero sale `{base}.etl` (sin sufijo
  `_000001`); el glob `{base}*.etl` cubre ambos casos.
- **B3 esquema XML**: tracerpt emite `<Event>` con `<System><Task>/`<EventID>
  y `<EventData><Data Name=...>`, no `<TraceEvent>/<Header>`. El parser
  busca por nombre local (inmune a namespaces). Fixture de test con el
  esquema real (incluye un evento namespaced): se caza sin admin.
- `logman stop <name> -ets` (sin `-ets` la sesion no se cierra).
- **Linea meta de diagnostico** en el JSONL: `{events_seen, rows,
  xml_ok, etl_found}`. El servidor la lee como estado (no bytes) y la
  expone como `last_meta` en `cloud_bytes`: distingue "corrio y no hubo
  trafico" de "fallo".

## Bytes remotos (v2.2) — "cuanto sale" con ETW Kernel-Network

### Anadido
- **`netcollector.py`**: colector ELEVADO (UAC, opt-in). `logman start` ->
  N s -> stop -> `tracerpt -of XML` -> parseo POR NOMBRE (`<Data Name=...>`)
  -> agregar por destino. Mapa EventID verificado en maquina real:
  TCP data 10/18/26/27/34 y UDP 11 (size = bytes); handshake/connect/
  accept/DNS ignorados. Excluye loopback y dport 53. Solo copia de datos
  con size>0; IPv4 e IPv6.
- **Gotchas verificados**: logman escribe `{base}_000001.etl` (se resuelve
  con glob); XML, no CSV (CSV pone User Data en columna posicional);
  sin admin el ETL nunca aparece -> degradacion rapida (~15 s), sin
  esperar la duracion.
- **Store**: tabla `net_bytes` (dest_ip, dest_port, bytes acumulados,
  first/last_seen); `ingest_net_bytes()` acumula entre ciclos (ventanas
  sin solapes); prune y reset la cubren.
- **Servidor**: hilo `_netbytes_loop` (opt-in: `net_bytes_enabled`,
  duracion/ciclo configurables). Lanza el colector elevado via UAC,
  espera el JSONL, lo ingesta y lo borra. El proceso no elevado NUNCA
  interpreta ETLs; si no hay datos, nada.
- **Dashboard**: `cloud_bytes` ahora REAL cuando hay datos (total + top
  proveedores mapeados IP->proveedor via eventos); si no, "no disponible"
  con motivo (nunca un cero que engane).
- **Regla `egress_volume_unapproved`** pasa a available=True con datos:
  dispara si un proveedor NO APROBADO supera `rule_egress_mb_per_day`
  (acumulado desde inicio del colector; sin datos, available=False).
- Tests: parse XML sintetico (solo data, sin loopback/DNS/connect),
  aggregate, ingest acumulativo/reset, dashboard disponible/no,
  regla egress sobre/bajo umbral y aprobada (`tests/test_netcollector.py`).

## Motor de reglas (v2.2) — umbral sobre señales existentes

### Anadido
- **`rules.py`**: motor puro (sin I/O). Reglas evaluadas cada 60 s sobre el
  estado existente (shadow + autonomía + beaconing):
  - `service_ai_call`: veredicto autonomous/scheduled llamando a IA no
    aprobada.
  - `beacon_unapproved`: beaconing (N>=5, CV<=0.3) a proveedor no aprobado.
  - `egress_volume_unapproved`: >X MB/dia a IA no aprobada —
    **available=False** hasta bytes remotos (honestidad: sin dato, no regla).
- **Alerta `rule_fired`**: una por regla en transicion no-firing -> firing;
  reset y cambio de config re-alertan.
- **Config**: `rules_enabled`, `rule_egress_mb_per_day` (0.1..1e6 MB).
- **`GET /api/rules`** + tarjeta *Reglas* (estado en vivo, refresh 60 s).
- **Probe de viabilidad bytes remotos**: `logman`/`tracerpt` presentes,
  pero trazar `Microsoft-Windows-Kernel-Network` **requiere admin**
  (verificado en esta maquina). El colector de bytes sera un modo elevado;
  sin admin, `cloud_bytes.available=false` con motivo.
- Tests: reglas puras (fuego/no-fuego por veredicto, aprobacion, N, CV),
  dedup de alerta, silencio con rules_enabled=False, re-alerta tras reset,
  forma de la API (`tests/test_rules.py`).

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
