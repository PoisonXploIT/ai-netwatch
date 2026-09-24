"""Reverse proxy local (solo stdlib) para inspeccionar las llamadas HTTP de un
cliente a un LLM local OpenAI-compatible (p. ej. llama-server).

Escucha en 127.0.0.1:<puerto> y reenvia a <host>:<puerto> del LLM (solo
loopback; la validacion vive en la capa de config del server). Registra por
llamada: path, modelo, prompt/respuesta (truncados con tamano real), tokens
si el upstream los reporta, latencia y si era streaming.

Streaming (SSE): se reenvia byte a byte tal cual; no se toca el framing del
cliente. El proxy solo ve HTTP plano porque ambos extremos son loopback.
"""
from __future__ import annotations

import json
import re
import socket
import threading
import time
from datetime import datetime, timezone

MAX_HEADER = 64 * 1024        # cabeceras de request
MAX_BODY = 64 * 1024 * 1024   # cuerpo de request (prompt)
MAX_PARSE_BUF = 2 * 1024 * 1024  # bytes de respuesta retenidos para parsear
MAX_STORED_TEXT = 65536       # prompt/respuesta guardados por llamada


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


class _Stream:
    """Lectura con buffer sobre el stream de un socket."""

    def __init__(self, sock: socket.socket):
        self._f = sock.makefile("rb")
        self._buf = b""

    def readline(self, cap: int = MAX_HEADER) -> bytes:
        while True:
            i = self._buf.find(b"\n")
            if i != -1:
                line, self._buf = self._buf[: i + 1], self._buf[i + 1:]
                return line
            if len(self._buf) > cap:
                raise ValueError("cabecera demasiado grande")
            chunk = self._f.read1(65536)
            if not chunk:
                raise EOFError("cliente cerró la conexion antes de fin de cabecera")
            self._buf += chunk

    def read(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self._f.read1(65536)
            if not chunk:
                raise EOFError("cuerpo de request truncado")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def close(self) -> None:
        try:
            self._f.close()
        except Exception:
            pass


def _read_chunked(s: _Stream) -> bytes:
    """Decodifica un cuerpo Transfer-Encoding: chunked (solo lectura)."""
    data = b""
    while True:
        line = s.readline(MAX_HEADER)
        size_txt = line.strip().split(b";")[0]
        try:
            size = int(size_txt, 16)
        except ValueError:
            raise ValueError("tamaño de chunk inválido")
        if size == 0:
            while True:  # trailers hasta línea vacía
                t = s.readline(MAX_HEADER)
                if t in (b"\r\n", b"\n"):
                    break
        else:
            data += s.read(size)
            tail = s.readline(64)  # CRLF tras el chunk
            if not tail.endswith(b"\n"):
                raise ValueError("chunk truncado")
        if len(data) > MAX_BODY:
            raise ValueError("cuerpo de request demasiado grande")
    return data


def _parse_sse(text: str):
    """Extrae (modelo, contenido acumulado, usage) de un stream SSE."""
    model, parts, usage = None, [], None
    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            d = json.loads(payload)
        except json.JSONDecodeError:
            continue
        model = model or d.get("model")
        if isinstance(d.get("usage"), dict):
            usage = d["usage"]
        for ch in d.get("choices") or []:
            delta = (ch or {}).get("delta") or {}
            c = delta.get("content")
            if c:
                parts.append(c)
    return model, "".join(parts), usage


def _tool_call_names(msg: dict) -> str:
    tcs = msg.get("tool_calls") or []
    names = [ (tc.get("function") or {}).get("name", "?")
              for tc in tcs if isinstance(tc, dict) ]
    return f" tool_calls=[{', '.join(names)}]" if names else ""


def _extract_prompt(path: str, body: bytes) -> tuple[str, str | None]:
    """(prompt_text, model) segun el endpoint (chat, completions, embeddings,
    audio multipart, images). Nunca volca binario crudo."""
    if not body:
        return "", None
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        if "/audio/" in path:  # multipart: solo metadatos
            m = re.search(rb'filename="([^"]*)"', body)
            name = m.group(1).decode("latin-1") if m else "?"
            return f"[multipart audio] {name}", None
        return "", None
    if not isinstance(data, dict):
        return "", None
    model = data.get("model")
    msgs = data.get("messages") or []
    if msgs:
        parts = []
        for m in msgs:
            if not isinstance(m, dict):
                continue
            content = m.get("content") or ""
            parts.append(f"{m.get('role', '?')}: {content}"
                         f"{_tool_call_names(m)}")
        return "\n\n".join(parts), model
    inp = data.get("input")  # /v1/embeddings
    if isinstance(inp, str):
        return inp, model
    if isinstance(inp, list):
        return "\n".join(str(x) for x in inp), model
    prompt = data.get("prompt")  # completions legacy y /v1/images/*
    if isinstance(prompt, str):
        extra = ""
        if "/images/" in path:
            extra = f" [n={data.get('n', 1)} size={data.get('size', '?')}]"
        return prompt + extra, model
    return "", model


def _extract_response(path: str, resp_raw: bytes, streaming: bool,
                      model: str | None) -> tuple[str, str | None, dict | None]:
    """(resp_text, model, usage). Embeddings e imagenes no persisten el dato."""
    try:
        head, _, body_b = resp_raw.partition(b"\r\n\r\n")
        text = body_b.decode("utf-8", "replace")
        if streaming:
            m2, content, usage = _parse_sse(text)
            return content, model or m2, usage
        d = json.loads(body_b)
    except (json.JSONDecodeError, UnicodeDecodeError, IndexError):
        return resp_raw[:4096].decode("utf-8", "replace"), model, None
    if not isinstance(d, dict):
        return str(d)[:4096], model, None
    usage = d.get("usage") if isinstance(d.get("usage"), dict) else None
    model = model or d.get("model")
    if "error" in d:
        err = d["error"]
        msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
        return f"[error] {msg}", model, usage
    if "/embeddings" in path:
        vecs = d.get("data") or []
        if vecs and isinstance(vecs[0], dict):
            dims = len((vecs[0].get("embedding")) or [])
            return (f"{len(vecs)} vector(es) de {dims} dim "
                    f"(contenido no persistido)"), model, usage
        return str(d)[:4096], model, usage
    if "/audio/" in path:
        return str(d.get("text", "")), model, usage
    if "/images/" in path:
        parts = []
        for it in d.get("data") or []:
            b64 = (it or {}).get("b64_json")
            url = (it or {}).get("url")
            parts.append(f"[imagen b64, {len(b64)} chars]" if b64 else str(url))
        return "; ".join(parts), model, usage
    # /v1/chat/completions y /v1/completions
    choices = d.get("choices") or []
    content, extra = "", ""
    if choices and isinstance(choices[0], dict):
        ch0 = choices[0]
        msg = ch0.get("message") or {}
        content = (msg.get("content") or "") + _tool_call_names(msg)
        fr = ch0.get("finish_reason")
        if fr and fr != "stop":
            extra = f" [finish={fr}]"
    return content + extra, model, usage


def _extract_record(method: str, path: str, status: int, req_body: bytes,
                    resp_raw: bytes, streaming: bool, latency_ms: float,
                    client_addr: str, resp_total: int | None = None) -> dict:
    """Construye el registro de una llamada (prompt/respuesta truncados)."""
    prompt_text, model = _extract_prompt(path, req_body)
    resp_text, model, usage = _extract_response(path, resp_raw, streaming, model)
    if status == 0:
        resp_text = "sin respuesta del upstream (fallo de conexion o timeout)"

    pt = ct = None
    if isinstance(usage, dict):
        pt = usage.get("prompt_tokens")
        ct = usage.get("completion_tokens")

    return {
        "ts": _now(),
        "method": method,
        "path": path,
        "status": status,
        "model": model or "",
        "streaming": 1 if streaming else 0,
        "prompt_chars": len(prompt_text),
        "response_chars": len(resp_text),
        "prompt_tokens": int(pt) if isinstance(pt, int) else None,
        "completion_tokens": int(ct) if isinstance(ct, int) else None,
        # Egress real medido (no estimado): bytes del cuerpo que sale hacia el
        # LLM y bytes totales que vuelven. Base del dashboard de egress.
        "request_bytes": len(req_body),
        # Counter total del bucle de recv (independiente de MAX_PARSE_BUF,
        # que solo limita lo retenido para parsear). Sin el contador, las
        # respuestas >2 MB se subcontaban.
        "response_bytes": resp_total if resp_total is not None else len(resp_raw),
        "latency_ms": round(latency_ms, 1),
        "client_addr": client_addr,
        "prompt": prompt_text[:MAX_STORED_TEXT],
        "response": resp_text[:MAX_STORED_TEXT],
    }


class LlmProxy(threading.Thread):
    """Proxy reverse en loopback. bind() antes de start(); stop() para parar."""

    def __init__(self, bind_host: str = "127.0.0.1", bind_port: int = 8098,
                 target: tuple[str, int] = ("127.0.0.1", 8099),
                 on_call=None):
        super().__init__(name="llm-proxy", daemon=True)
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.target = target
        self.on_call = on_call
        self.bound_port: int | None = None
        self.server_sock: socket.socket | None = None
        self._stop_evt = threading.Event()

    def bind(self) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.bind_host, self.bind_port))
        s.listen(16)
        s.settimeout(0.5)
        self.server_sock = s
        self.bound_port = s.getsockname()[1]
        return self.bound_port

    def stop(self) -> None:
        self._stop_evt.set()
        if self.server_sock:
            try:
                self.server_sock.close()
            except OSError:
                pass
        self.join(timeout=3)

    def run(self) -> None:
        assert self.server_sock is not None
        while not self._stop_evt.is_set():
            try:
                conn, addr = self.server_sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(
                target=self._handle, args=(conn, addr),
                name="llm-proxy-conn", daemon=True,
            ).start()

    def _handle(self, client: socket.socket, addr) -> None:
        t0 = time.monotonic()
        try:
            st = _Stream(client)
            reqline = st.readline(MAX_HEADER).split()
            if len(reqline) < 2:
                return
            method = reqline[0].decode("latin-1")
            path = reqline[1].decode("latin-1")
            headers: dict[bytes, bytes] = {}
            while True:
                line = st.readline(MAX_HEADER)
                if line in (b"\r\n", b"\n"):
                    break
                if b":" in line:
                    k, v = line.split(b":", 1)
                    headers[k.strip().lower()] = v.strip()
            te = headers.get(b"transfer-encoding", b"").lower()
            if b"chunked" in te:
                body = _read_chunked(st)
            elif b"content-length" in headers:
                n = int(headers[b"content-length"] or 0)
                body = st.read(n) if n else b""
            else:
                body = b""
        except (EOFError, ValueError):
            client.close()
            return

        try:
            # El timeout del socket rige TAMBIEN cada recv posterior: una
            # generacion larga (razonamiento) puede tardar >60s sin emitir
            # bytes. Invariante: >= el timeout mayor del cliente (_chat 120s,
            # test 60s); si es menor, el proxy corta la respuesta y el
            # cliente ve RemoteDisconnected (fix: antes era 15s).
            upstream = socket.create_connection(self.target, timeout=300)
        except OSError:
            # Un intento fallido tambien es senal (sobre todo si es periodico).
            if self.on_call:
                try:
                    self.on_call(_extract_record(
                        method, path, 0, body, b"", False,
                        (time.monotonic() - t0) * 1000.0,
                        f"{addr[0]}:{addr[1]}" if isinstance(addr, tuple)
                        else str(addr)))
                except Exception:
                    pass
            client.close()
            return

        out = f"{method} {path} HTTP/1.1\r\n".encode("latin-1")
        for k, v in headers.items():
            if k in (b"connection", b"proxy-connection", b"transfer-encoding",
                     b"keep-alive"):
                continue
            if k == b"host":
                v = f"{self.target[0]}:{self.target[1]}".encode()
            out += k + b": " + v + b"\r\n"
        if body:
            out += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        out += b"Connection: close\r\n\r\n" + body

        resp_raw = b""
        resp_total = 0
        status = 0
        streaming = False
        try:
            upstream.sendall(out)
            while True:
                chunk = upstream.recv(65536)
                if not chunk:
                    break
                client.sendall(chunk)
                resp_total += len(chunk)
                if len(resp_raw) < MAX_PARSE_BUF:
                    resp_raw += chunk
            head, _, _rest = resp_raw.partition(b"\r\n\r\n")
            first = head.splitlines()[0].split() if head else []
            status = int(first[1]) if len(first) >= 2 and first[1].isdigit() else 0
            hdrs_txt = head.decode("latin-1", "replace").lower()
            streaming = "text/event-stream" in hdrs_txt
        except OSError:
            pass
        finally:
            try:
                upstream.close()
            except OSError:
                pass
            client.close()

        if status and self.on_call:
            try:
                self.on_call(_extract_record(
                    method, path, status, body, resp_raw, streaming,
                    (time.monotonic() - t0) * 1000.0,
                    f"{addr[0]}:{addr[1]}" if isinstance(addr, tuple) else str(addr),
                    resp_total,
                ))
            except Exception:
                pass  # el proxy nunca rompe por logging
