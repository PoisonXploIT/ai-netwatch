"""Contraste WCAG de los pares texto/fondo de styles.css. Solo stdlib."""
import re
import sys
from pathlib import Path

CSS = (Path(__file__).resolve().parent.parent / "static" / "styles.css").read_text(encoding="utf-8")
PAIRS = [("--text", "--bg"), ("--text", "--card"), ("--muted", "--bg"), ("--muted", "--card"),
         ("--on-accent", "--accent"), ("--accent-text", "--accent-soft"), ("--accent-text", "--card"),
         ("--v-ok", "--v-ok-bg"), ("--v-bad", "--v-bad-bg"),
         ("--v-warn", "--v-warn-bg"), ("--v-mut", "--v-mut-bg")]


def _vars(block: str) -> dict:
    return dict(re.findall(r"(--[a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\b", block))


def _lum(hex_color: str) -> float:
    def ch(v: int) -> float:
        c = v / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)


def ratio(fg: str, bg: str) -> float:
    a, b = sorted((_lum(fg), _lum(bg)), reverse=True)
    return (a + 0.05) / (b + 0.05)


def _block(pattern: str) -> str:
    m = re.search(pattern, CSS, re.S)
    return m.group(1) if m else ""


def failures(minimum: float = 4.5) -> list:
    light = _vars(_block(r":root\s*\{(.*?)\}"))
    dark = {**light, **_vars(_block(r'html\[data-theme="dark"\]\s*\{(.*?)\}'))}
    out = []
    for name, theme in (("claro", light), ("oscuro", dark)):
        for fg, bg in PAIRS:
            if fg in theme and bg in theme:
                r = ratio(theme[fg], theme[bg])
                if r < minimum:
                    out.append((name, fg, bg, round(r, 2)))
    return out


if __name__ == "__main__":
    bad = failures()
    for row in bad:
        print("FALLA", *row)
    sys.exit(1 if bad else 0)
