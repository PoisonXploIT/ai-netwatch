"""Genera data/finetune/paquete_entrenamiento/ para entrenar laya con casos propios.

- Copia cases.jsonl.
- Adapta el notebook oficial de Kaggle (2xT4) para leer cases.jsonl en vez de
  LocalLLaMA/typed-decisions, y recorta la eval del benchmark (el A/B real se
  hace con tools/compare_backends.py contra Jev).
- Copia el script single-device del repo laya (fallback CPU/1 GPU).
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

REPO = Path("C:/Users/Sammi/AI/laya-repo")
FT = Path("C:/Users/Sammi/ai-netwatch/data/finetune")
PKG = FT / "paquete_entrenamiento"
PKG.mkdir(parents=True, exist_ok=True)

# 1) cases.jsonl
shutil.copy2(FT / "cases.jsonl", PKG / "cases.jsonl")

# 2) script single-device
shutil.copy2(REPO / "research/scripts/finetune_single_device.py",
             PKG / "laya_finetune_single_device.py")

# 3) notebook adaptado
nb = json.loads((REPO / "notebooks"
                 / "laya_finetune_typed_decisions_2xT4_kaggle.ipynb")
                .read_text(encoding="utf-8"))

NEW_CELL6 = r'''import os, json, glob, torch
from transformers import AutoTokenizer
from huggingface_hub import snapshot_download
from laya.agent import _fix_tokenizer_config
from laya.common import build_sequence, render_options, QTYPES

MODEL_ID = "convaiinnovations/laya"
print(f"Fetching tokenizer and config from {MODEL_ID}...")
model_dir = snapshot_download(MODEL_ID)
_fix_tokenizer_config(model_dir)

tok = AutoTokenizer.from_pretrained(os.path.join(model_dir, "tokenizer"))
with open(os.path.join(model_dir, "rl_agent_config.json")) as f:
    cfg = json.load(f)

# --- Dataset PROPIO (AI-NetWatch) en vez de LocalLLaMA/typed-decisions ---
_cands = sorted(glob.glob("/kaggle/input/**/cases.jsonl", recursive=True))
CASE_PATH = _cands[0] if _cands else "/kaggle/input/laya-cases/cases.jsonl"
print("Loading own cases:", CASE_PATH)
rows = [json.loads(l) for l in open(CASE_PATH, encoding="utf-8") if l.strip()]
print(f"{len(rows)} casos propios (state/questions/gold)")

def build_training_item(state, q, gold_q):
    t = q["type"]
    crit = q.get("criteria", {})
    if t == "choice":
        keys = list(crit.keys())
        target = [gold_q["probabilities"].get(k, 0.0) for k in keys]
    elif t == "noul":
        target = [gold_q["probabilities"].get("false", 0.5), gold_q["probabilities"].get("true", 0.5)]
    elif t == "score":
        n_levels = len(crit) if isinstance(crit, list) else 4
        target = [gold_q["probabilities"].get(str(i), 0.0) for i in range(n_levels)]

    s = sum(target)
    target = [v / s for v in target] if s > 0 else [1.0 / len(target)] * len(target)
    label = target.index(max(target))
    k = len(render_options({"t": t, "crit": crit}))

    seq, markers = build_sequence(tok, state, {"t": t, "ins": q["instructions"], "crit": crit}, cfg["max_len"], cfg["head_max_len"])
    if len(markers) != k:
        return None
    return {
        "ids": seq,
        "markers": markers,
        "qtype": QTYPES[t],
        "target": target,
        "label": label
    }

items = []
for row in rows:
    state = row["state"]
    questions = row["questions"]
    gold = row["gold"]
    for qid, q in questions.items():
        if qid in gold:
            it = build_training_item(state, q, gold[qid])
            if it:
                items.append(it)

print(f"Preprocessed {len(items)} training sequences across {len(rows)} cases.")
torch.save(items, "/kaggle/working/train_items.pt")
print("Saved preprocessed items to /kaggle/working/train_items.pt")'''

# celda 6 (indice 6) = preprocess
nb["cells"][6]["source"] = NEW_CELL6.splitlines(keepends=True)

# Titulo
nb["cells"][0]["source"] = [
    "# Fine-Tuning Laya sobre casos propios de AI-NetWatch (Kaggle GPU T4 x2)\n",
    "\n",
    "Entrena `convaiinnovations/laya` (421M) con el dataset propio `cases.jsonl`\n",
    "(schema `{state, questions, gold}`, gold con `probabilities`).\n",
    "\n",
    "Kaggle: Accelerator `GPU T4 x2`, Internet `On`, y subir `cases.jsonl` como\n",
    "dataset privado (`laya-cases`). El A/B contra Jev se hace aparte con\n",
    "`tools/compare_backends.py --ab`.\n",
]

# Recortar celdas 11..18 (eval/publish/report del benchmark oficial)
nb["cells"] = nb["cells"][:11] + [{
    "cell_type": "markdown",
    "metadata": {},
    "source": [
        "## 6. Evaluacion (A/B contra Jev)\n",
        "\n",
        "El checkpoint queda en `/kaggle/working/laya_finetuned_typed_decisions`.\n",
        "Descargalo a la maquina y registra su ruta en\n",
        "`data/finetune/training_state.json` (campo `local_model`). Despues:\n",
        "\n",
        "```\n",
        ".venv\\Scripts\\python tools\\compare_backends.py --ab\n",
        "```\n",
        "\n",
        "Cambiar el default a local solo con acuerdo de verdict >= 85 por ciento.\n",
    ],
}]

(PKG / "laya_finetune_cases_kaggle.ipynb").write_text(
    json.dumps(nb, ensure_ascii=False, indent=1), encoding="utf-8")

print("paquete:", PKG)
for p in sorted(PKG.iterdir()):
    print(" ", p.name, p.stat().st_size)
