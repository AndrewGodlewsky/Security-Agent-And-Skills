"""Normalize OSV records; retain unsupported semantics for agent investigation."""
import json
import re
from urllib.parse import quote
from urllib.request import Request, urlopen
from .common import now

MAX_RESPONSE = 8 * 1024 * 1024


def request_json(url, payload=None):
    # Caller builds URLs for a fixed official service, never executes supplied URLs.
    body = None if payload is None else json.dumps(payload).encode()
    request = Request(url, data=body, headers={
        "User-Agent": "local-vulnerability-triage/1",
        "Content-Type": "application/json", "Accept": "application/json"})
    with urlopen(request, timeout=25) as response:
        data = response.read(MAX_RESPONSE + 1)
    if len(data) > MAX_RESPONSE:
        raise ValueError("Advisory response exceeds 8 MiB; incomplete data rejected")
    return json.loads(data)


def fetch_osv(identifier):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:_.-]{1,180}", identifier):
        raise ValueError("Invalid advisory identifier")
    return request_json("https://api.osv.dev/v1/vulns/" + quote(identifier, safe=""))


def normalize_osv(record, source=None):
    if not isinstance(record, dict) or not record.get("id"):
        raise ValueError("OSV record requires an id")
    targets = []
    for affected in record.get("affected", []):
        package = affected.get("package", {})
        if not package.get("name") or not package.get("ecosystem"):
            continue
        ranges = affected.get("ranges", [])
        fixes = [event["fixed"] for item in ranges for event in item.get("events", [])
                 if "fixed" in event]
        targets.append(dict(
            ecosystem=package["ecosystem"], name=package["name"],
            affected_versions=affected.get("versions", []),
            versions_complete=False, osv_ranges=ranges,
            version_scheme="osv", fixed_versions=list(dict.fromkeys(fixes)),
            prerequisites=[], remediation_steps=[]))
    return dict(schema_version=1, id=record["id"], aliases=record.get("aliases", []),
                title=record.get("summary", record["id"]),
                sources=[dict(url=source or "https://osv.dev/vulnerability/" + record["id"],
                              retrieved_at=now())],
                source_status="verified", provider="OSV",
                modified=record.get("modified"), withdrawn=record.get("withdrawn"),
                targets=targets, uncertainties=[] if targets else ["No affected packages in record"],
                references=record.get("references", []))


def template(reported):
    return dict(schema_version=1, id="LOCAL-UNRESOLVED", aliases=[], title=reported,
                sources=[], source_status="unverified", provider="manual",
                targets=[], uncertainties=["Resolve product, affected versions, prerequisites and fix from primary sources"])


def validate_advisory(advisory):
    if advisory.get("schema_version") != 1 or not isinstance(advisory.get("id"), str):
        raise ValueError("Expected schema_version 1 and advisory id")
    if not isinstance(advisory.get("targets"), list):
        raise ValueError("targets must be a list")
    if advisory.get("source_status") == "verified":
        if not advisory.get("sources") or not all(s.get("url") and s.get("retrieved_at")
                                                  for s in advisory["sources"]):
            raise ValueError("Verified advisory needs source URLs and retrieval timestamps")
    for target in advisory["targets"]:
        if not target.get("name") or not target.get("ecosystem"):
            raise ValueError("Each target needs exact name and ecosystem")
        for field in ("fixed_versions", "affected_versions", "prerequisites", "remediation_steps"):
            if field in target and not isinstance(target[field], list):
                raise ValueError(field + " must be a list")
    return advisory


def query_osv(ecosystem, name, version):
    data = request_json("https://api.osv.dev/v1/query",
                        {"package": {"ecosystem": ecosystem, "name": name}, "version": version})
    if not isinstance(data, dict) or data.get("next_page_token"):
        raise ValueError("Incomplete OSV response; pagination requires further investigation")
    if "vulns" in data and not isinstance(data["vulns"], list):
        raise ValueError("Malformed OSV result")
    return data.get("vulns", [])
