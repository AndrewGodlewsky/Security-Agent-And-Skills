"""Small explicit matchers. Unsupported version semantics remain unknown."""
import re

SEMVER = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?")


def version_key(value, scheme):
    if not isinstance(value, str):
        raise ValueError("Missing version")
    if scheme == "numeric":
        if not re.fullmatch(r"\d+(?:\.\d+){0,7}", value):
            raise ValueError("Not a numeric vendor version")
        parts = [int(part) for part in value.split(".")]
        return tuple(parts + [0] * (8 - len(parts)))
    if scheme == "semver":
        match = SEMVER.fullmatch(value)
        if not match:
            raise ValueError("Not strict SemVer")
        major, minor, patch, prerelease, build = match.groups()
        for group in (prerelease, build):
            if group and any(not item for item in group.split(".")):
                raise ValueError("Empty SemVer identifier")
        pre = []
        if prerelease:
            for item in prerelease.split("."):
                if item.isdigit() and len(item) > 1 and item.startswith("0"):
                    raise ValueError("Leading zero in numeric prerelease")
                pre.append((0, int(item)) if item.isdigit() else (1, item))
        return int(major), int(minor), int(patch), 0 if prerelease else 1, tuple(pre)
    raise ValueError("Unsupported version scheme: " + str(scheme))


def interval_match(version, ranges, scheme):
    """Union of explicit vendor ranges; missing/unsupported bounds cannot yield clean."""
    key = version_key(version, scheme)
    unknown = False
    for item in ranges:
        if not isinstance(item, dict) or not item:
            unknown = True
            continue
        if set(item) - {"introduced", "fixed", "last_affected"}:
            unknown = True
            continue
        try:
            lower = item.get("introduced")
            upper = item.get("fixed")
            last = item.get("last_affected")
            if upper and last:
                raise ValueError("Ambiguous upper boundary")
            low_key = version_key(lower, scheme) if lower and lower != "0" else None
            upper_key = version_key(upper, scheme) if upper else None
            last_key = version_key(last, scheme) if last else None
            if low_key is not None and ((upper_key is not None and low_key >= upper_key)
                                        or (last_key is not None and low_key > last_key)):
                raise ValueError("Invalid interval ordering")
            if low_key is not None and key < low_key:
                continue
            if upper_key is not None and key >= upper_key:
                continue
            if last_key is not None and key > last_key:
                continue
            return "affected", "Observed version falls in a sourced affected interval"
        except ValueError:
            unknown = True
    if unknown:
        return "unknown", "Some affected intervals could not be interpreted"
    return "not_affected", "Observed version is outside every supplied affected interval"


def match_version(version, target):
    if not version:
        return "unknown", "No exact version was observed"
    if version in target.get("affected_versions", []):
        return "affected", "Observed version is explicitly listed as affected"
    scheme = target.get("version_scheme")
    if scheme == "osv":
        ranges = target.get("osv_ranges", [])
        # Offline evaluation supports only SEMVER, with strict alternating boundaries.
        if not ranges:
            return "unknown", "No evaluable ranges; non-membership in a version list is insufficient"
        intervals = []
        for entry in ranges:
            if entry.get("type") != "SEMVER":
                return "unknown", "OSV ecosystem/git range requires provider query or ecosystem evaluator"
            start = None
            for event in entry.get("events", []):
                if len(event) != 1:
                    return "unknown", "Malformed OSV range event"
                kind, value = next(iter(event.items()))
                if kind == "introduced" and start is None:
                    start = value
                elif kind in ("fixed", "last_affected") and start is not None:
                    intervals.append({"introduced": start, kind: value})
                    start = None
                else:
                    return "unknown", "Unsupported or unordered OSV range events"
            if start is not None:
                intervals.append({"introduced": start})
        if not intervals:
            return "unknown", "No range intervals"
        return interval_match(version, intervals, "semver")
    ranges = target.get("affected_ranges", [])
    if ranges:
        return interval_match(version, ranges, scheme)
    if target.get("versions_complete") is True and "affected_versions" in target:
        return "not_affected", "Not in the source-confirmed exhaustive affected-version list"
    return "unknown", "No complete, supported affected-version rules"
