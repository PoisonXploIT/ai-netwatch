# Security Policy

## Supported versions

The latest tagged release on the `main` branch receives fixes. AI NetWatch is
a local, single-host tool for Windows.

## Reporting a vulnerability

Open a private security advisory on GitHub
(https://github.com/PoisonXploIT/ai-netwatch/security/advisories/new) or, if
unavailable, open an issue with the `security` label without including
exploit details. Do not open a public issue with a working exploit before a
fix is available.

Include: affected version/tag, steps to reproduce, impact, and any suggested
fix. Expect an initial response within a few days.

## Design security model (by design)

AI NetWatch is built to run on `127.0.0.1` only; there is no external
attack surface and no authentication because there is no remote exposure.

- **Loopback only**: the server binds `127.0.0.1:8790`.
- **SSRF guard**: the only outbound HTTP endpoints whose destination the user
  controls (`llm_base_url`, `llm_proxy_target`, `alert_webhook_url`) are
  restricted to absolute `http(s)` URLs resolving to loopback, and are
  re-validated when the config is loaded from disk (a hand-edited
  `data/config.json` cannot point them outside).
- **Secrets at rest**: the Jev API key is encrypted with Windows DPAPI
  (`secret_store.py`) and never written to disk in clear. If DPAPI is
  unavailable, the key is not persisted.
- **Exports are secret-free**: JSON/CSV/PDF are generated in memory from the
  store only; they never include the config or API keys (covered by tests).
- **No payload storage by default**: the LLM Inspector can store prompt and
  response content; this is opt-in (`llm_store_content`) and subject to its
  own retention (`retention_days_llm`).

## Out of scope

- Inspecting or decrypting TLS traffic to remote providers (would require a
  MITM with a local CA; intentionally excluded).
- Multi-user or network-exposed deployments.

## Modelo de seguridad de la consola (v2.7)

- El servidor escucha solo en 127.0.0.1. Toda petición con un `Host` que no sea loopback recibe 403.
- Las acciones (POST/PUT/DELETE/PATCH) exigen un token de sesión generado al arrancar, que solo
  vive en memoria y se entrega dentro del HTML de la consola. Se compara en tiempo constante.
- Las lecturas sensibles (`/api/llm/calls`, `/api/export/*`, `/api/evidence/*`) exigen el mismo token.
- Si la petición trae `Origin`, debe ser `http://<loopback>:<mismo puerto>`.
- CORS deny-all. CSP sin `unsafe-inline`; sin objetos, sin marcos, formularios solo a la propia consola.
- Secretos: la key de Jev se guarda cifrada con DPAPI; la API solo devuelve un fingerprint.
  Los prompts y respuestas del inspector se guardan cifrados con DPAPI.
- Límite conocido: un proceso que corre como el mismo usuario de Windows puede leer `data/` y pedir
  la consola para obtener el token. El token protege frente a páginas web y a otros usuarios.
