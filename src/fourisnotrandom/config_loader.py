from __future__ import annotations

import json
import shutil
from importlib import resources
from pathlib import Path
from typing import Any

import yaml


DATA_PACKAGE = "fourisnotrandom.data"


def _read_pkg_text(name: str) -> str:
    return resources.files(DATA_PACKAGE).joinpath(name).read_text(encoding="utf-8")


def _pkg_path(name: str) -> Path:
    return Path(str(resources.files(DATA_PACKAGE).joinpath(name)))


def load_fixed_versions(config_path: Path | None = None) -> dict[str, Any]:
    if config_path:
        text = Path(config_path).read_text(encoding="utf-8")
        data = yaml.safe_load(text)
    else:
        data = yaml.safe_load(_read_pkg_text("fixed_versions.yaml"))
    if not isinstance(data, dict):
        raise ValueError("fixed_versions config must be a mapping")
    return data


def load_compromised_hashes(hashes_path: Path | None = None) -> dict[str, Any]:
    if hashes_path:
        data = json.loads(Path(hashes_path).read_text(encoding="utf-8"))
    else:
        data = json.loads(_read_pkg_text("compromised_hashes.json"))
    if not isinstance(data, dict):
        raise ValueError("compromised_hashes config must be a mapping")
    return data


def compromised_hash_set(data: dict[str, Any] | None = None) -> set[str]:
    data = data or load_compromised_hashes()
    out: set[str] = set()
    for entry in data.get("certificates", []):
        h = entry.get("sha256") or entry.get("hash") or entry.get("spki_sha256")
        if h:
            out.add(str(h).lower().replace(":", "").replace(" ", ""))
    # Also accept a flat list under "hashes"
    for h in data.get("hashes", []) or []:
        out.add(str(h).lower().replace(":", "").replace(" ", ""))
    return out


def load_php_apps(config_path: Path | None = None) -> dict[str, Any]:
    if config_path:
        data = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
    else:
        data = yaml.safe_load(_read_pkg_text("php_apps.yaml"))
    if not isinstance(data, dict):
        raise ValueError("php_apps config must be a mapping")
    return data


def update_hashes_file(source: Path, destination: Path | None = None) -> Path:
    """Replace bundled (or user) compromised hash list from an external JSON file."""
    src = Path(source)
    if not src.is_file():
        raise FileNotFoundError(f"Hash file not found: {src}")
    # Validate schema
    data = json.loads(src.read_text(encoding="utf-8"))
    if "certificates" not in data and "hashes" not in data:
        raise ValueError("Hash file must contain 'certificates' or 'hashes'")
    dest = destination or _pkg_path("compromised_hashes.json")
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dest)
    return dest
