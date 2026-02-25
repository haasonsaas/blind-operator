from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional

from .errors import BlindOpError
from .gateway import Gateway
from .policy import parse_label
from .state import resolve_state_dir


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="blindop")
    p.add_argument("--state-dir", default=None, help="State directory (default: ./.blindop)")

    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("tools", help="List available tools")

    case_p = sub.add_parser("case", help="Case operations")
    case_sub = case_p.add_subparsers(dest="case_cmd", required=True)
    case_create = case_sub.add_parser("create", help="Create a new case")
    case_create.add_argument("--name", default=None)
    case_sub.add_parser("list", help="List cases")

    ingest_p = sub.add_parser("ingest", help="Ingest a file into a case")
    ingest_p.add_argument("--case", dest="case_id", required=True)
    ingest_p.add_argument("--label", required=True, help="public|internal|confidential|restricted")
    ingest_p.add_argument("path")

    art_p = sub.add_parser("artifact", help="Artifact operations")
    art_sub = art_p.add_subparsers(dest="artifact_cmd", required=True)
    art_show = art_sub.add_parser("show")
    art_show.add_argument("handle")
    art_list = art_sub.add_parser("list")
    art_list.add_argument("--case", dest="case_id", required=True)
    art_move = art_sub.add_parser("move")
    art_move.add_argument("handle")
    art_move.add_argument("--case", dest="case_id", required=True)

    tag_p = sub.add_parser("tag", help="Tag operations")
    tag_sub = tag_p.add_subparsers(dest="tag_cmd", required=True)
    tag_add = tag_sub.add_parser("add")
    tag_add.add_argument("handle")
    tag_add.add_argument("tag")
    tag_rm = tag_sub.add_parser("remove")
    tag_rm.add_argument("handle")
    tag_rm.add_argument("tag")

    dedupe_p = sub.add_parser("dedupe", help="Group artifacts by sha256")
    dedupe_p.add_argument("--case", dest="case_id", required=True)
    dedupe_p.add_argument("--include-unique", action="store_true")

    rp_p = sub.add_parser("rulepack", help="Rulepack scanning")
    rp_sub = rp_p.add_subparsers(dest="rp_cmd", required=True)
    rp_scan = rp_sub.add_parser("scan")
    rp_scan.add_argument("handle")
    rp_scan.add_argument("--rules", dest="rules_path", required=True)

    ioc_p = sub.add_parser("iocs", help="IOC extraction")
    ioc_p.add_argument("handle")
    ioc_p.add_argument("--include-hashes", action="store_true")
    ioc_p.add_argument("--top", type=int, default=20)
    ioc_p.add_argument("--k-min", type=int, default=1, help="Only return hashed values with count >= k")

    tl_p = sub.add_parser("timeline", help="Build a timeline")
    tl_p.add_argument("--case", dest="case_id", required=True)
    tl_p.add_argument("--limit", type=int, default=200)

    diff_p = sub.add_parser("diff", help="Diff two artifacts")
    diff_p.add_argument("handle_a")
    diff_p.add_argument("handle_b")

    args = p.parse_args(argv)
    state_dir = resolve_state_dir(args.state_dir)

    gw = Gateway(state_dir=state_dir)
    try:
        if args.cmd == "tools":
            _print(gw.describe_tools())
            return 0

        if args.cmd == "case":
            if args.case_cmd == "create":
                _print(gw.call("case.create", name=args.name))
                return 0
            if args.case_cmd == "list":
                _print(gw.call("case.list"))
                return 0

        if args.cmd == "ingest":
            _print(
                gw.call(
                    "artifact.ingest",
                    case_id=args.case_id,
                    src_path=Path(args.path).expanduser().resolve(),
                    label=parse_label(args.label),
                )
            )
            return 0

        if args.cmd == "artifact":
            if args.artifact_cmd == "show":
                _print(gw.call("artifact.show", handle=args.handle))
                return 0
            if args.artifact_cmd == "list":
                _print(gw.call("artifact.list", case_id=args.case_id))
                return 0
            if args.artifact_cmd == "move":
                _print(gw.call("artifact.move", handle=args.handle, case_id=args.case_id))
                return 0

        if args.cmd == "tag":
            if args.tag_cmd == "add":
                _print(gw.call("tag.add", handle=args.handle, tag=args.tag))
                return 0
            if args.tag_cmd == "remove":
                _print(gw.call("tag.remove", handle=args.handle, tag=args.tag))
                return 0

        if args.cmd == "dedupe":
            _print(
                gw.call(
                    "artifact.dedupe",
                    case_id=args.case_id,
                    include_unique=bool(args.include_unique),
                )
            )
            return 0

        if args.cmd == "rulepack" and args.rp_cmd == "scan":
            _print(
                gw.call(
                    "rulepack.scan",
                    handle=args.handle,
                    rules_path=Path(args.rules_path).expanduser().resolve(),
                )
            )
            return 0

        if args.cmd == "iocs":
            _print(
                gw.call(
                    "iocs.extract",
                    handle=args.handle,
                    include_hashes=bool(args.include_hashes),
                    top=int(args.top),
                    k_min=int(args.k_min),
                )
            )
            return 0

        if args.cmd == "timeline":
            _print(gw.call("timeline.build", case_id=args.case_id, limit=int(args.limit)))
            return 0

        if args.cmd == "diff":
            _print(gw.call("artifact.diff", handle_a=args.handle_a, handle_b=args.handle_b))
            return 0

        _print({"ok": False, "error": "unreachable"})
        return 2
    except BlindOpError as e:
        _print({"ok": False, "error": type(e).__name__, "message": str(e)})
        return 2
    except Exception as e:
        _print({"ok": False, "error": type(e).__name__, "message": str(e)})
        return 1
    finally:
        gw.close()
