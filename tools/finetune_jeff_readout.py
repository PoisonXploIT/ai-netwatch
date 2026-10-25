#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""finetune_jeff_readout.py — finetune de la cabeza readout de Jeff sobre cases.jsonl.

Objetivo: re-entrenar el readout (255 x hidden_dim) de Jeff para que reproduzca las
probabilidades gold de Jev (choice/score/noul) sobre los eventos de ai-netwatch, en vez de
la prior zero-shot (que en el A/B de 2026-10-03 dio 70.97% de acuerdo de verdict).

Como funciona
    - Carga data/finetune/cases.jsonl (217 casos, 3 preguntas por caso: class/sev/act).
    - Para cada (caso, pregunta) construye el prompt EXACTO de Jeff con
      jeff_prompt.decision_messages (codes = A,B,C,... del decision_config.json).
    - Extrae el hidden state del ultimo token llamando al backend de embeddings de Jeff
      (/apply-template + /embedding, mismo formato que el server.py del bundle).
    - Entrena W (softmax cross-entropy sobre la distribucion gold, SGD con numpy; sin torch).
    - Guarda W en readout_ft.npy (float32) y readout_ft.safetensors (BF16, formato del bundle).
    - Evalua acuerdo de verdict contra el gold y lo compara con el baseline zero-shot (70.97%).

Requisitos
    - Backend de embeddings de Jeff corriendo en CPU (-ngl 0): puerto 11435 por defecto
      (el bundle: llama-server --embedding --pooling last --embd-normalize -1).
    - numpy (2.5.3 en el .venv de Jeff). No requiere torch.
    - cases.jsonl ya generado (tools/raw_to_cases.py).

Limitacion conocida (importante)
    - El readout de Jeff es POSICIONAL: la fila 0 = codigo "A" = "primera opcion",
      independientemente de que la pregunta sea class, sev o act. Por eso en el A/B zero-shot
      la severidad colapsaba a 0/3 y el acuerdo era sesgo a la clase mayoritaria.
    - Este script entrena con el MISMO mapeo posicional que usa tools/jeff_ab.py (class:
      filas 0-3; sev: filas 0-3; act: filas 0-1), por lo que la confluencia se mantiene.
      La variante correcta (filas separadas por tipo de pregunta: class 0-3, sev 4-7,
      act 8-9) exige cambiar tambien el mapeo de codigos en la evaluacion; se deja anotada
      como mejora (flag --per-question-rows implementado en train).

Uso
    .venv/Scripts/python.exe tools/finetune_jeff_readout.py --dry-run          # valida datos, sin red
    .venv/Scripts/python.exe tools/finetune_jeff_readout.py --limit 50 --epochs 200
    .venv/Scripts/python.exe tools/finetune_jeff_readout.py --per-question-rows # filas separadas por tipo
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import urllib.request
from pathlib import Path

import numpy as np

# Rutas fijas del proyecto.
AI_NETWATCH = Path(__file__).resolve().parent.parent
JEFF_DIR = Path(r"C:\Users\Sammi\AI\models\Jeff-Gemma4-E2B-Q4_K_M")
CASES = AI_NETWATCH / "data" / "finetune" / "cases.jsonl"
OUT_NPY = AI_NETWATCH / "data" / "finetune" / "readout_ft.npy"
OUT_SFT = AI_NETWATCH / "data" / "finetune" / "readout_ft.safetensors"
CACHE_NPY = AI_NETWATCH / "data" / "finetune" / "jeff_hidden_cache.npy"

# Import de jeff_prompt desde el directorio del bundle (sin cargar server.py).
sys.path.insert(0, str(JEFF_DIR))
import jeff_prompt  # noqa: E402


# ------------------------------------------------------------------ backend
def _post(base: str, path: str, payload: dict, timeout: int = 300) -> object:
    req = urllib.request.Request(
        base.rstrip("/") + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def apply_template(base: str, messages: list[dict]) -> str:
    out = _post(base, "/apply-template", {"messages": messages})
    if not isinstance(out, dict) or not isinstance(out.get("prompt"), str) or not out["prompt"]:
        raise RuntimeError("/apply-template no devolvio prompt")
    return out["prompt"]


def embed(base: str, prompt: str, images_b64: list[str]) -> np.ndarray:
    out = _post(base, "/embedding", {
        "content": {"prompt_string": prompt, "multimodal_data": images_b64},
        "embd_normalize": -1,
    })
    # Mismo parseo que el bundle: body[0].embedding (lista de listas o plana).
    if not isinstance(out, list) or not out or not isinstance(out[0], dict):
        raise RuntimeError("respuesta /embedding mal formada")
    emb = out[0].get("embedding")
    if isinstance(emb, list) and len(emb) == 1 and isinstance(emb[0], list):
        emb = emb[0]
    if not isinstance(emb, list) or not all(isinstance(v, (int, float)) for v in emb):
        raise RuntimeError("hidden state mal formado")
    return np.asarray(emb, dtype=np.float32)


# ------------------------------------------------------------------ datos
def load_cases() -> list[dict]:
    return [json.loads(line) for line in CASES.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def build_samples(cases: list[dict], codes: list[str]) -> list[dict]:
    """Devuelve una muestra por (caso, pregunta): {prompt_messages, N, keys, gold}."""
    samples: list[dict] = []
    for case in cases:
        state = case["state"]
        for qid, question in case["questions"].items():
            gold = case["gold"].get(qid) or {}
            probs = gold.get("probabilities") or {}
            keys, descriptions = jeff_prompt.options(question)
            N = len(keys)
            if N < 1 or N > 26:
                continue
            # gold ordenado por keys (mismo orden que options()).
            y = np.asarray([float(probs.get(k, 0.0)) for k in keys], dtype=np.float64)
            if y.sum() <= 0:
                y = np.ones(N, dtype=np.float64) / N
            y /= y.sum()
            row = {"question": question, "state": state, "images": []}
            messages = jeff_prompt.decision_messages(row, codes[:N], layout="state-first")
            # messages[0] = system; messages[1] = user (parts). Texto unico (sin imagenes).
            user_parts = messages[1]["content"]
            text = "".join(p["text"] for p in user_parts if p.get("type") == "text")
            openai = [
                {"role": "system", "content": messages[0]["content"]},
                {"role": "user", "content": [{"type": "text", "text": text}]},
            ]
            samples.append({"openai": openai, "N": N, "keys": keys, "gold": y,
                            "qid": qid, "event": case["state"].get("title", "")})
    return samples


# ------------------------------------------------------------------ entrenamiento
def _softmax(logits: np.ndarray) -> np.ndarray:
    z = logits - logits.max()
    e = np.exp(z)
    return e / e.sum()


def train(W0: np.ndarray, samples: list[dict], hidden: np.ndarray,
          temperature: float, epochs: int, lr: float,
          per_question_rows: bool = False) -> np.ndarray:
    """SGD con softmax cross-entropy sobre la distribucion gold (distilacion de Jev).

    - Posicional (default): cada pregunta usa las filas 0..N-1 (mismo mapeo que jeff_ab.py).
    - per_question_rows=True: class usa 0-3, sev usa 4-7, act usa 8-9 (filas separadas).
    """
    # qid termina en _class/_sev/_act (p. ej. f0_class).
    ROWS_BY_TYPE = {"class": 0, "sev": 4, "act": 8}
    W = W0.astype(np.float64).copy()
    for epoch in range(epochs):
        total_loss = 0.0
        for s, h in zip(samples, hidden):
            N = s["N"]
            base = 0
            if per_question_rows:
                base = ROWS_BY_TYPE.get(s["qid"].split("_")[-1], 0)
            rows = W[base:base + N]
            logits = rows @ h / temperature
            p = _softmax(logits)
            y = s["gold"]
            total_loss += float(-np.sum(y * np.log(np.clip(p, 1e-12, 1.0))))
            grad_rows = (p - y)[:, None] * h[None, :] / temperature
            if per_question_rows:
                W[base:base + N] -= lr * grad_rows
            else:
                W[:N] -= lr * grad_rows
        if epoch % max(1, epochs // 10) == 0 or epoch == epochs - 1:
            print(f"  epoch {epoch + 1}/{epochs}  loss {total_loss / max(1, len(samples)):.4f}")
    return W


def evaluate(W: np.ndarray, samples: list[dict], hidden: np.ndarray,
             temperature: float, per_question_rows: bool = False) -> dict:
    """Acuerdo de argmax (por tipo) contra el gold."""
    ROWS_BY_TYPE = {"class": 0, "sev": 4, "act": 8}
    correct = 0
    total = 0
    by_type: dict[str, list] = {}
    for s, h in zip(samples, hidden):
        N = s["N"]
        base = ROWS_BY_TYPE.get(s["qid"].split("_")[-1], 0) if per_question_rows else 0
        p = _softmax((W[base:base + N] @ h) / temperature)
        pred = int(np.argmax(p))
        gold = int(np.argmax(s["gold"]))
        correct += (pred == gold)
        total += 1
        by_type.setdefault(s["qid"].split("_")[-1], []).append(pred == gold)
    out = {"acuerdo_total": correct / max(1, total), "n": total}
    for k, v in by_type.items():
        out[f"acuerdo_{k}"] = sum(v) / max(1, len(v))
    return out


# ------------------------------------------------------------------ guardado
def write_bf16_safetensors(W: np.ndarray, path: Path) -> None:
    """Escribe el readout en el formato safetensors BF16 que lee el bundle.

    El bundle carga: readout = ((bits << 16).view('<f4')).reshape((rows, cols)).
    Aqui: float32 -> BF16 (16 bits altos) -> uint16 little-endian."""
    W32 = W.astype(np.float32)
    u = W32.view(np.uint32)
    # round-to-nearest-even en el bit 16
    u = (u + 0x7FFF + ((u >> 16) & 1)) & 0xFFFF0000
    bf16 = (u >> 16).astype(np.uint16)
    data = bf16.tobytes()  # little-endian por defecto en numpy
    header = json.dumps({
        "weight": {
            "dtype": "BF16",
            "shape": list(W.shape),
            "data_offsets": [0, len(data)],
        }
    }, separators=(",", ":")).encode("utf-8")
    with open(path, "wb") as f:
        f.write(len(header).to_bytes(8, "little"))
        f.write(header)
        f.write(data)


# ------------------------------------------------------------------ main
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="http://127.0.0.1:11435")
    ap.add_argument("--limit", type=int, default=0, help="0 = todos los casos")
    ap.add_argument("--epochs", type=int, default=200)
    ap.add_argument("--lr", type=float, default=0.5)
    ap.add_argument("--dry-run", action="store_true", help="valida datos/prompts, sin red ni train")
    ap.add_argument("--per-question-rows", action="store_true",
                    help="filas separadas por tipo (class 0-3, sev 4-7, act 8-9)")
    ap.add_argument("--cache", default=str(CACHE_NPY), help="cache de hidden states (npy)")
    a = ap.parse_args()

    # Config + readout original (como init de W).
    cfg = json.loads((JEFF_DIR / "decision_config.json").read_text(encoding="utf-8"))
    codes = cfg["codes"]
    temperature = float(cfg["temperature"])
    # Leer readout.safetensors en el mismo formato BF16 que el bundle.
    sft = (JEFF_DIR / "readout.safetensors").read_bytes()
    hlen = int.from_bytes(sft[:8], "little")
    hdr = json.loads(sft[8:8 + hlen])
    t = hdr["weight"]
    shape = t["shape"]
    bits = np.frombuffer(sft[8 + hlen:], dtype="<u2").astype(np.uint32)
    W0 = ((bits << 16).view("<f4")).reshape(shape).astype(np.float32)
    hidden_dim = W0.shape[1]
    print(f"readout original: {W0.shape}, temperature {temperature}, codes {len(codes)}")

    cases = load_cases()
    if a.limit:
        cases = cases[:a.limit]
    samples = build_samples(cases, codes)
    print(f"casos {len(cases)} -> muestras {len(samples)} (3 preguntas/caso)")

    if a.dry_run:
        # Verificar que los prompts tienen el formato esperado (opciones + codigo).
        for s in samples[:3]:
            txt = s["openai"][1]["content"][0]["text"]
            print(f"  [{s['qid']}] N={s['N']} keys={s['keys']} prompt_chars={len(txt)}")
        print("dry-run OK: sin red, sin train.")
        return

    # Extraer (o cargar) hidden states.
    cache = Path(a.cache)
    if cache.exists():
        H = np.load(cache)
        print(f"hidden cache cargado: {H.shape}")
    else:
        print(f"extrayendo hidden states de {len(samples)} muestras via {a.backend} ...")
        H = np.zeros((len(samples), hidden_dim), dtype=np.float32)
        for i, s in enumerate(samples):
            prompt = apply_template(a.backend, s["openai"])
            H[i] = embed(a.backend, prompt, [])
            if (i + 1) % 50 == 0:
                print(f"  {i + 1}/{len(samples)}")
        np.save(cache, H)
        print(f"hidden cache guardado: {cache}")

    W = train(W0, samples, H, temperature, a.epochs, a.lr, a.per_question_rows)
    train_eval = evaluate(W, samples, H, temperature, a.per_question_rows)
    base_eval = evaluate(W0, samples, H, temperature, a.per_question_rows)
    print("evaluacion train:", train_eval)
    print("baseline zero-shot:", base_eval)

    np.save(OUT_NPY, W.astype(np.float32))
    write_bf16_safetensors(W, OUT_SFT)
    print(f"guardado: {OUT_NPY} y {OUT_SFT}")

    out_json = AI_NETWATCH / "data" / "finetune" / "jeff_finetune_results.json"
    out_json.write_text(json.dumps({
        "casos": len(cases), "muestras": len(samples),
        "epochs": a.epochs, "lr": a.lr,
        "per_question_rows": a.per_question_rows,
        "baseline_zero_shot": base_eval,
        "finetuned": train_eval,
        "readout_ft_npy": str(OUT_NPY),
        "readout_ft_safetensors": str(OUT_SFT),
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"resultados: {out_json}")


if __name__ == "__main__":
    main()
