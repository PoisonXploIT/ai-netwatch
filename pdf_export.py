"""Export PDF de AI NetWatch — solo stdlib (sin fpdf/reportlab).

Writer minimo de PDF: A4, fuentes base Helvetica / Helvetica-Bold con
WinAnsiEncoding (los acentos espanios son cp1252), texto con wrapping y
saltos de pagina automaticos.

Seguridad: el informe se construye EXCLUSIVAMENTE con datos del store
(eventos/triajes/estadisticas). No recibe input del usuario ni toca la
config: ninguna API key puede aparecer en un export.
"""
from __future__ import annotations

from datetime import datetime, timezone

_PAGE_W = 595.0
_PAGE_H = 842.0
_MARGIN = 45.0
_WRAP_FACTOR = 0.52  # ancho medio de caracter Helvetica (em)


def _to_pdf_text(text: str) -> str:
    """WinAnsiEncoding (cp1252); lo no codificable se convierte a '?'."""
    return str(text).encode("cp1252", "replace").decode("cp1252")


def _escape(text: str) -> str:
    return (_to_pdf_text(text)
            .replace("\\", r"\\")
            .replace("(", r"\(")
            .replace(")", r"\)"))


def wrap_line(text: str, size: float) -> list[str]:
    """Rompe en lineas que caben en la pagina (conserva saltos de linea)."""
    width = _PAGE_W - 2 * _MARGIN
    max_chars = max(10, int(width / (size * _WRAP_FACTOR)))
    out: list[str] = []
    for raw in str(text).splitlines() or [""]:
        line = raw
        while len(line) > max_chars:
            cut = max_chars
            sp = line.rfind(" ", 0, max_chars)
            if sp > max_chars // 2:
                cut = sp
            out.append(line[:cut].rstrip())
            line = line[cut:].lstrip()
        out.append(line)
    return out


class PdfDoc:
    """Acumula lineas (font, size, texto); render() devuelve los bytes PDF."""

    def __init__(self) -> None:
        self._y = _PAGE_H - _MARGIN
        self._pages: list[list[tuple[str, float, str, float]]] = [[]]

    def add(self, text: str, font: str = "F1", size: float = 10.0,
            gap_before: float = 0.0) -> None:
        if gap_before:
            self._y -= gap_before
        for chunk in wrap_line(text, size):
            leading = size * 1.35
            if self._y - leading < _MARGIN:
                self._pages.append([])
                self._y = _PAGE_H - _MARGIN
            self._y -= leading
            self._pages[-1].append((font, size, chunk, self._y))

    def render(self) -> bytes:
        n = len(self._pages)
        kids = " ".join(f"{5 + 2 * i} 0 R" for i in range(n))
        objs: list[bytes] = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            f"<< /Type /Pages /Kids [{kids}] /Count {n} >>".encode(),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
            b"/Encoding /WinAnsiEncoding >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
            b"/Encoding /WinAnsiEncoding >>",
        ]
        for i, page_lines in enumerate(self._pages):
            parts = [
                f"BT /{font} {size:g} Tf {_MARGIN:g} {y:.2f} Td "
                f"({_escape(text)}) Tj ET".encode("cp1252", "replace")
                for font, size, text, y in page_lines
            ]
            stream = b"\n".join(parts)
            objs.append(
                (f"<< /Type /Page /Parent 2 0 R "
                 f"/MediaBox [0 0 {_PAGE_W:g} {_PAGE_H:g}] "
                 f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
                 f"/Contents {6 + 2 * i} 0 R >>").encode())
            objs.append(b"<< /Length " + str(len(stream)).encode()
                        + b" >>\nstream\n" + stream + b"\nendstream")

        buf = b"%PDF-1.4\n"
        offsets: list[int] = []
        for num, body in enumerate(objs, start=1):
            offsets.append(len(buf))
            buf += f"{num} 0 obj\n".encode() + body + b"\nendobj\n"
        xref_pos = len(buf)
        total = len(objs) + 1
        xref = [f"xref\n0 {total}\n".encode(), b"0000000000 65535 f \n"]
        for off in offsets:
            xref.append(f"{off:010d} 00000 n \n".encode())
        buf += b"".join(xref)
        buf += (f"trailer\n<< /Size {total} /Root 1 0 R >>\nstartxref\n"
                f"{xref_pos}\n%%EOF").encode()
        return buf


def build_report_pdf(version: str, events: list[dict],
                     triage: dict | None, daily: list[dict]) -> bytes:
    """Informe completo: cabecera, eventos, ultimo triaje Jev y stats.

    Solo datos del store; nunca config/keys (ver tests de seguridad)."""
    doc = PdfDoc()
    doc.add(f"AI NetWatch {version} - Informe de salidas a nube IA",
            font="F2", size=16)
    doc.add("Generado: " + datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"), size=9, gap_before=4)
    doc.add("Monitor local (solo loopback) de conexiones a proveedores cloud "
            "IA. No incluye bytes ni payload: solo proceso, destino, "
            "protocolo y periodicidad.", size=9)

    doc.add(f"Eventos ({len(events)})", font="F2", size=13, gap_before=10)
    if not events:
        doc.add("Sin eventos registrados.")
    else:
        for e in events[:200]:
            host = (e.get("sni_domain") or e.get("dest_host")
                    or e.get("dest_ip"))
            line = (f"{e['process']}  ->  {host}:{e['dest_port']}  "
                    f"[{e.get('protocol', 'tcp')}]  cat={e.get('catalog_domain') or '-'}  "
                    f"veces={e['seen_count']}")
            doc.add(line, size=9)
        if len(events) > 200:
            doc.add(f"... y {len(events) - 200} mas (exporta JSON/CSV para el "
                   "detalle completo).", size=9)

    if triage:
        doc.add("Ultimo triaje Jev", font="F2", size=13, gap_before=10)
        jev = triage.get("jev") or {}
        doc.add(f"Estado: {jev.get('status') or '-'}  |  "
               f"Modelo: {jev.get('model') or '-'}", size=9)
        verdicts = jev.get("verdicts") or {}
        for i, e in enumerate(triage.get("events") or []):
            v = verdicts.get(str(i), {})
            doc.add(f"{e.get('process')} -> {e.get('dest')}: "
                    f"{v.get('verdict') or '-'}  (conf {v.get('confidence')}, "
                    f"criticidad {v.get('severity_score')}/3, "
                    f"prob.FP {v.get('prob_false_positive')})", size=9)

    doc.add("Estadisticas (ultimos 7 dias)", font="F2", size=13, gap_before=10)
    if not daily:
        doc.add("Sin datos diarios todavia.")
    else:
        for d in daily[-7:]:
            doc.add(f"{d['date']}: {d['events']} eventos, "
                   f"{d['triages']} triajes", size=9)

    doc.add("Seguridad: servidor solo loopback; sin payload capturado; "
           "exports generados en memoria y sin secretos.", size=8, gap_before=10)
    return doc.render()
