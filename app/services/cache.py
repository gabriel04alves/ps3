from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from services.scanner_client import ScanResult
from services.gemini_client import RiskAssessment

CACHE_DIR = Path(__file__).parent.parent / ".cache"
INDEX_FILE = CACHE_DIR / "index.json"
MAX_ENTRIES = 20


def _ensure_dir() -> None:
    CACHE_DIR.mkdir(exist_ok=True)


def _slug(target: str) -> str:
    return (
        target.replace(":", "_")
        .replace(".", "-")
        .replace("/", "_")
        .replace("\\", "_")
    )


def _load_index() -> list[dict]:
    if not INDEX_FILE.exists():
        return []
    try:
        return json.loads(INDEX_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def _save_index(index: list[dict]) -> None:
    _ensure_dir()
    INDEX_FILE.write_text(
        json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def salvar(resultado: ScanResult, risco: RiskAssessment) -> None:
    if not resultado.ok:
        return

    _ensure_dir()
    slug = _slug(resultado.target)
    path = CACHE_DIR / f"{slug}.json"

    payload = {
        "resultado": asdict(resultado),
        "risco": asdict(risco),
        "ts": time.time(),
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    index = [e for e in _load_index() if e.get("target") != resultado.target]
    index.insert(
        0,
        {
            "target": resultado.target,
            "ts": payload["ts"],
            "scanned_at": resultado.scanned_at,
            "total_findings": resultado.total_findings,
            "overall_risk": risco.overall_risk,
            "usou_ia": risco.usou_ia,
            "slug": slug,
        },
    )

    removidos = index[MAX_ENTRIES:]
    for e in removidos:
        p = CACHE_DIR / f"{e['slug']}.json"
        if p.exists():
            p.unlink()

    _save_index(index[:MAX_ENTRIES])


def listar() -> list[dict]:
    return _load_index()


def carregar(slug: str) -> Optional[tuple[ScanResult, RiskAssessment]]:
    path = CACHE_DIR / f"{slug}.json"
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        resultado = ScanResult(**payload["resultado"])
        risco = RiskAssessment(**payload["risco"])
        return resultado, risco
    except (json.JSONDecodeError, TypeError, KeyError, OSError):
        return None


def limpar() -> None:
    if not CACHE_DIR.exists():
        return
    for f in CACHE_DIR.glob("*.json"):
        try:
            f.unlink()
        except OSError:
            pass
