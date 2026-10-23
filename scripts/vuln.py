#!/usr/bin/env python3
"""Run from any directory. Only explicit output paths are written."""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vulntriage.advisory import fetch_osv, normalize_osv, template, validate_advisory
from vulntriage.assessment import assess
from vulntriage.common import read_json, write_json
from vulntriage.inventory import collect_repositories, merge_windows
from vulntriage.report import build_plan, render_report
from vulntriage.verification import verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    intake = commands.add_parser("intake", help="Create an advisory template or import an OSV record")
    choice = intake.add_mutually_exclusive_group(required=True)
    choice.add_argument("--reported", help="User report, URL, or identifier; creates an unverified template")
    choice.add_argument("--osv-id", help="Fetch only this ID from OSV (network)")
    choice.add_argument("--osv-file", help="Import an OSV JSON record; retain its provenance separately")
    intake.add_argument("--out", required=True)
    inv = commands.add_parser("inventory", help="Read dependency files and optionally merge a Windows artifact")
    inv.add_argument("--repo", action="append", default=[])
    inv.add_argument("--python-env", action="append", default=[])
    inv.add_argument("--exclude", action="append", default=["research/upstream"])
    inv.add_argument("--max-files", type=int, default=10000)
    inv.add_argument("--windows")
    inv.add_argument("--out", required=True)
    assessment = commands.add_parser("assess", help="Match observed versions; runtime exposure stays unknown")
    assessment.add_argument("--advisory", required=True)
    assessment.add_argument("--inventory", required=True)
    assessment.add_argument("--online", action="store_true", help="Send candidate package identities/versions to OSV")
    assessment.add_argument("--max-age-hours", type=float, default=24)
    assessment.add_argument("--out", required=True)
    report = commands.add_parser("report", help="Write a draft plan and Markdown report")
    report.add_argument("--assessment", required=True)
    report.add_argument("--plan-out", required=True)
    report.add_argument("--out", required=True)
    verification = commands.add_parser("verify", help="Compare before/after assessments without applying fixes")
    verification.add_argument("--before", required=True)
    verification.add_argument("--after", required=True)
    verification.add_argument("--out", required=True)
    args = parser.parse_args()
    if args.command == "intake":
        if args.osv_id:
            record = fetch_osv(args.osv_id)
            output = normalize_osv(record, "https://api.osv.dev/v1/vulns/" + args.osv_id)
            output["requested_id"] = args.osv_id
            output["raw_record"] = record
        elif args.osv_file:
            output = normalize_osv(read_json(args.osv_file))
            output["source_status"] = "unverified"
            output["uncertainties"].append("Imported file provenance must be confirmed against primary source")
        else:
            output = template(args.reported)
        write_json(args.out, output)
    elif args.command == "inventory":
        if args.max_files < 1:
            raise ValueError("--max-files must be positive")
        if not (args.repo or args.python_env or args.windows):
            raise ValueError("Select at least one explicit inventory scope")
        output = collect_repositories(args.repo, args.exclude, args.max_files, args.python_env)
        if args.windows:
            output = merge_windows(output, read_json(args.windows))
        write_json(args.out, output)
    elif args.command == "assess":
        if args.max_age_hours <= 0:
            raise ValueError("--max-age-hours must be positive")
        write_json(args.out, assess(validate_advisory(read_json(args.advisory)),
                                   read_json(args.inventory), args.online, args.max_age_hours))
    elif args.command == "report":
        data = read_json(args.assessment)
        plan = build_plan(data)
        write_json(args.plan_out, plan)
        destination = Path(args.out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(render_report(data, plan), encoding="utf-8")
    elif args.command == "verify":
        write_json(args.out, verify(read_json(args.before), read_json(args.after)))
    print(args.out)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print("Assessment helper failed: " + str(exc), file=sys.stderr)
        sys.exit(2)
