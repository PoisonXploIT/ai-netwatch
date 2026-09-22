# AI NetWatch (v1.2)

Monitor local de **salidas de red hacia proveedores cloud IA** (OpenAI/Azure, Anthropic, Google, TypeSafe/Jev, Groq, OpenRouter, Mistral, Cohere, Hugging Face, DeepSeek, xAI, Together, Replicate...). Lo que ve: **proceso (+ruta completa con Sysmon) + destino IP/puerto + protocolo TCP/UDP + periodicidad + dominio real por SNI** de cada conexion establecida a un destino IA. Incluye estadisticas diarias (7+ dias), export JSON/CSV y tema claro/oscuro.

- Solo loopback (`127.0.0.1`), puerto 8790.
- **Jev (TypeSafe)** como juez de criticidad, a demanda (boton *Triar eventos con Jev*): clasificacion `expected_ai_use / background_exfil_suspect / telemetry_noise / unrelated`, criticidad 0-3, accion inmediata y **probabilidad de falso positivo** derivada.
- **LLM local** (OpenAI-compatible, SOLO loopback, sin key): explicaciones tecnicas en espanol de los eventos marcados.
- Fail-safe: sin IA configurada la vista clasica funciona igual; ningun error de IA rompe el monitor.
- Sin dependencias nuevas: FastAPI + stdlib (el monitor usa `Get-NetTCPConnection` via PowerShell).

## Limitaciones honestas

- No ve **bytes** ni **payload**: solo que un proceso abrio/mantiene conexion a un destino IA, con cuantas veces se repite. Bytes/payload requieren ETW/WFP o MITM (fuera de scope).
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

## Arranque

```powershell
cd C:\Users\Sammi\ai-netwatch
python -m venv .venv
.\.venv\Scripts\pip install fastapi uvicorn
.\.venv\Scripts\python -m uvicorn server:app --host 127.0.0.1 --port 8790
```

Abrir `http://127.0.0.1:8790`. La config es **persistente** (`data/config.json`): key Jev, LLM local (URL loopback + modelo), hosts extra (IP o dominio propios que quieras vigilar), toggle Sysmon y toggle tshark sobreviven al reinicio.

## Endpoints

- `GET /api/events?limit=&process=&dest=`
- `POST /api/triage` (`{"event_ids": [...]}` opcional; sin ids = todos)
- `GET /api/triages/latest`
- `GET/POST /api/config` (key Jev maskeda en lecturas)
- `POST /api/test` (`{"target": "jev"|"llm"}`)
- `GET /api/export/json`, `GET /api/export/csv`, `GET /api/export/pdf`

Los tres exports se descargan (`Content-Disposition: attachment`) y se generan en memoria solo con datos del store: **ninguno incluye la config ni API keys** (verificado por tests). El PDF (writer stdlib, sin dependencias) lleva cabecera, eventos, ultimo triaje Jev y estadisticas de 7 dias.

## Contrato Jev (exacto)

Modelo pin `jev-1.13.0`, una llamada batch por triaje (cap 50 eventos). State por evento: `process, dest_ip, dest_port, dest_host, sni_domain, catalog_domain, seen_count, first_seen, last_seen, user_active="unknown"` (el titulo usa el dominio SNI si existe, porque es el real). Preguntas con criteria contrastivas:

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
- Suite dedicada: `tests/test_security.py` (SSRF, persistencia + revalidacion, reset, inputs, fail-safe).

## Guia de uso

Dentro de la propia interfaz (tarjeta *Guia de uso*, enlace en el header): que ve y que no ve, fuentes de datos (polling/Sysmon/tshark), lectura de veredictos Jev, LLM local, estadisticas/reset, exportacion, configuracion y el modelo de seguridad/privacidad. Contenido estatico: ninguna entrada del usuario se renderiza (sin superficie XSS).

## Tests

```powershell
.\.venv\Scripts\python -m unittest discover tests -v
```

(sin red; HTTP mockeado; incluye la suite de seguridad)
