"""Read local dependency metadata without importing or running target code."""
import json
import os
import re
import tomllib
from email.parser import Parser
from pathlib import Path
from urllib.parse import urlparse
from .common import canonical_name, component, coverage, now

MAX_BYTES = 16 * 1024 * 1024
PRUNE = {".git", "node_modules", ".venv", "venv", "dist", "build", ".next",
         "__pycache__", ".vulnerability-runs"}
UNSUPPORTED = {"pnpm-lock.yaml", "yarn.lock", "Pipfile.lock", "pom.xml",
               "build.gradle", "build.gradle.kts", "Cargo.lock", "go.sum"}
SUPPORTED = {"package-lock.json", "npm-shrinkwrap.json", "package.json", "uv.lock",
             "poetry.lock", "packages.lock.json", "project.assets.json", "requirements.txt", "go.mod"}


def bounded_text(path):
    if path.is_symlink() or path.stat().st_size > MAX_BYTES:
        raise ValueError("Symlink or file over 16 MiB; skipped")
    with path.open("r", encoding="utf-8-sig") as stream:
        value = stream.read(MAX_BYTES + 1)
    if len(value.encode("utf-8")) > MAX_BYTES:
        raise ValueError("File exceeds read limit")
    return value


def npm_identity(item):
    resolved = item.get("resolved", "")
    return "public_registry" if urlparse(resolved).hostname == "registry.npmjs.org" else "unconfirmed"


def parse_file(path):
    source = str(path)
    text = bounded_text(path)
    records, gaps = [], []

    def add(eco, name, version, kind, locator, **extra):
        if not isinstance(name, str) or not name:
            raise ValueError("Missing package name")
        if version is not None and not isinstance(version, str):
            raise ValueError("Version must be text")
        records.append(component(eco, name, version, source, kind,
                                 location=source + "::" + locator, **extra))

    if path.name in ("package-lock.json", "npm-shrinkwrap.json"):
        data = json.loads(text)
        if data.get("lockfileVersion") in (2, 3) and isinstance(data.get("packages"), dict):
            root = data["packages"].get("", {})
            direct = set(root.get("dependencies", {})) | set(root.get("devDependencies", {}))
            for key, item in data["packages"].items():
                if not key or not isinstance(item, dict):
                    continue
                if "node_modules/" not in key or item.get("link"):
                    gaps.append("Workspace/link entry requires source inspection: " + key)
                    continue
                name = item.get("name") or key.rsplit("node_modules/", 1)[-1]
                add("npm", name, item.get("version"), "resolved", key,
                    direct=name in direct and key == "node_modules/" + name,
                    dependency_path=key, development=bool(item.get("dev")), provenance=npm_identity(item))
        elif data.get("lockfileVersion") == 1:
            def visit(items, parents=()):
                for name, item in items.items():
                    chain = parents + (name,)
                    add("npm", name, item.get("version"), "resolved", "/".join(chain),
                        direct=not parents, dependency_path=list(chain), development=bool(item.get("dev")),
                        provenance=npm_identity(item))
                    visit(item.get("dependencies", {}), chain)
            visit(data.get("dependencies", {}))
        else:
            raise ValueError("Unsupported npm lockfile version or malformed packages map")
    elif path.name == "package.json":
        data = json.loads(text)
        for group in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            for name, spec in data.get(group, {}).items():
                # A manifest declares a version; it never proves installation.
                exact = spec if isinstance(spec, str) and re.fullmatch(r"\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?", spec) else None
                add("npm", name, exact, "declared", group + "/" + name,
                    declared_spec=str(spec), direct=True, development=group == "devDependencies")
    elif path.name in ("uv.lock", "poetry.lock"):
        data = tomllib.loads(text)
        for index, item in enumerate(data.get("package", [])):
            package_source = item.get("source", {})
            registry = package_source.get("registry") or package_source.get("url")
            if path.name == "uv.lock":
                public = registry in ("https://pypi.org/simple", "https://pypi.org/simple/")
            else:
                public = not package_source or registry in ("https://pypi.org/simple", "https://pypi.org/simple/")
            if not public:
                gaps.append("Non-PyPI/workspace source needs identity confirmation: " + str(item.get("name")))
                continue
            add("PyPI", item["name"], item.get("version"), "resolved", str(index),
                direct=None, dependency_path=None)
    elif path.name == "packages.lock.json":
        data = json.loads(text)
        for framework, packages in data.get("dependencies", {}).items():
            for name, item in packages.items():
                if item.get("type") == "Project":
                    continue
                add("NuGet", name, item.get("resolved"), "resolved", framework + "/" + name,
                    direct=item.get("type") == "Direct", dependency_path=framework)
    elif path.name == "project.assets.json":
        data = json.loads(text)
        for identity, item in data.get("libraries", {}).items():
            if item.get("type") != "package":
                continue
            name, version = identity.rsplit("/", 1)
            add("NuGet", name, version, "resolved", identity, direct=None)
    elif path.name == "requirements.txt":
        for index, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.fullmatch(r"([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([A-Za-z0-9.!+_-]+)(?:\s*;.*)?(?:\s+#.*)?", line)
            if match:
                add("PyPI", match[1], match[2], "declared", str(index),
                    declared_spec=line, direct=None)
                if ";" in line:
                    gaps.append("Environment marker requires evaluation at line " + str(index))
            else:
                gaps.append("Unresolved requirement/include/options at line " + str(index))
    elif path.name == "go.mod":
        block = False
        replacements = bool(re.search(r"(?m)^\s*replace\b", text))
        for index, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if line.startswith("require ("):
                block = True
                continue
            if block and line == ")":
                block = False
                continue
            match = re.match(r"(?:require\s+)?([^\s()]+)\s+(v[^\s]+)", line) if block or line.startswith("require ") else None
            if match:
                add("Go", match[1], None if replacements else match[2], "declared", str(index),
                    declared_spec=match[2], direct="// indirect" not in line)
        gaps.append("go.mod is declared module selection; built binary and full graph were not inspected")
        if replacements:
            gaps.append("replace directive present: effective module identities/versions require inspection")
    return records, gaps


def collect_repositories(roots, excludes=(), max_files=10000, python_envs=()):
    result = dict(schema_version=1, collected_at=now(), scopes=[], components=[], coverage=[])
    for raw in roots:
        root = Path(raw).absolute()
        scope = str(root)
        result["scopes"].append(scope)
        if not root.is_dir() or root.is_symlink() or (hasattr(root, "is_junction") and root.is_junction()):
            result["coverage"].append(coverage(scope, "repository", "error", "Root missing, inaccessible, or a symlink"))
            continue
        exclusions = {str((root / x).absolute()) for x in excludes}
        count, capped, had_error = 0, False, False
        def walk_error(exc):
            nonlocal had_error
            had_error = True
            result["coverage"].append(coverage(scope, "walk", "error", str(exc)))
        for current, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
            retained = []
            for name in dirs:
                child = Path(current) / name
                if name in PRUNE or str(child.absolute()) in exclusions:
                    continue
                if child.is_symlink() or (hasattr(child, "is_junction") and child.is_junction()):
                    result["coverage"].append(coverage(str(child), "walk", "unsupported", "Directory link not followed"))
                    continue
                retained.append(name)
            dirs[:] = retained
            for name in names:
                count += 1
                if count > max_files:
                    capped = True
                    break
                path = Path(current) / name
                if name in UNSUPPORTED or name.endswith(".csproj"):
                    result["coverage"].append(coverage(path, "repository", "unsupported",
                        "No automatic parser; agent must inspect relevant metadata separately"))
                elif name in SUPPORTED:
                    try:
                        records, gaps = parse_file(path)
                        for record in records:
                            record["scope"] = scope
                        result["components"].extend(records)
                        result["coverage"].append(coverage(path, "repository", "partial" if gaps else "complete",
                            "; ".join(gaps) if gaps else "Read metadata successfully; not runtime evidence"))
                    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
                        result["coverage"].append(coverage(path, "repository", "error", str(exc)))
            if capped:
                break
        result["coverage"].append(coverage(scope, "walk", "partial" if capped or had_error else "complete",
            f"Visited {min(count, max_files)} files. Limit={max_files}. Excluded directories: {sorted(PRUNE)}; explicit={list(excludes)}. "
            "Installed dependencies, build artifacts, running processes, WSL and containers require separate checks."))
    for raw in python_envs:
        env = Path(raw).absolute()
        result["scopes"].append(str(env))
        sites = [env / "Lib" / "site-packages"]
        if (env / "lib").is_dir():
            sites.extend((env / "lib").glob("python*/site-packages"))
        found = 0
        for site in sites:
            if not site.is_dir() or site.is_symlink():
                continue
            for metadata in site.glob("*.dist-info/METADATA"):
                try:
                    if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
                           for p in (metadata.parent, site, env)):
                        raise ValueError("Environment symlink not followed")
                    headers = Parser().parsestr(bounded_text(metadata), headersonly=True)
                    if not headers.get("Name") or not headers.get("Version"):
                        raise ValueError("Distribution metadata missing Name/Version")
                    result["components"].append(component("PyPI", headers["Name"], headers["Version"],
                        str(metadata), "installed", scope=str(env)))
                    found += 1
                except (OSError, ValueError) as exc:
                    result["coverage"].append(coverage(metadata, "python-env", "error", str(exc)))
        result["coverage"].append(coverage(env, "python-env", "complete" if found else "partial",
            f"Read {found} distribution metadata files; loaded process versions not checked"))
    return result


def merge_windows(inventory, windows):
    if windows.get("schema_version") != 1:
        raise ValueError("Unsupported Windows inventory schema")
    inventory["scopes"].extend(windows.get("scopes", []))
    inventory["coverage"].extend(windows.get("coverage", []))
    for item in windows.get("components", []):
        inventory["components"].append(component(item["ecosystem"], item["name"], item.get("version"),
            item["source"], item["evidence_kind"], location=item.get("location", item["source"]),
            scope=item.get("scope", "windows-host"), observed_at=windows.get("collected_at")))
    inventory["windows"] = {key: windows.get(key) for key in ("collected_at", "hotfixes", "context")}
    return inventory

