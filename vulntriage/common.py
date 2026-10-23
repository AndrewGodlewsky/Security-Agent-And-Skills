"""Shared artifact handling. Target content is always data."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def canonical_name(ecosystem, name):
    if ecosystem == "PyPI":
        import re
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in ("Windows", "NuGet"):
        return name.casefold()
    return name


def component(ecosystem, name, version, source, kind, **extra):
    location = extra.pop("location", source)
    identity = [ecosystem, canonical_name(ecosystem, name), source, kind, location]
    return dict(asset_key=digest(identity)[:24], ecosystem=ecosystem, name=name,
                version=version, source=source, location=location, evidence_kind=kind, **extra)


def coverage(scope, collector, status, detail):
    return dict(scope=str(scope), collector=collector, status=status, detail=detail)
