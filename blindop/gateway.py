from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

from . import db
from .caps import verify_token
from .errors import PolicyDenied, ToolInputError
from .keys import load_or_create_hmac_key, load_or_create_key
from .policy import Label, ToolPolicy, dominates, join, parse_label
from .pseudonym import pseudonymize
from .safe_output import SafeOutputBudget, sanitize
from .state import StatePaths, ensure_state_paths
from .util import new_id, utc_now_iso
from .vault import BlobStore
from .tools import artifact_tools, case_tools, ioc_tools, rulepack_tools, tag_tools, timeline_tools


def _read_budget_limit(env_name: str, default: int) -> Optional[int]:
    raw = os.getenv(env_name)
    if raw is None or raw.strip() == "":
        return default
    v = raw.strip().lower()
    if v in {"off", "none", "unlimited", "inf", "infinite", "-1"}:
        return None
    try:
        n = int(v)
    except ValueError:
        return default
    if n < 0:
        return None
    return n


@dataclass(frozen=True)
class ToolSpec:
    policy: ToolPolicy
    handler: Callable[..., Any]
    handle_args: Tuple[str, ...] = ()
    case_args: Tuple[str, ...] = ()
    label_args: Tuple[str, ...] = ()


class Gateway:
    def __init__(
        self,
        *,
        state_dir: Path,
        budget: SafeOutputBudget = SafeOutputBudget(),
    ) -> None:
        self.paths: StatePaths = ensure_state_paths(state_dir)
        self.conn = db.connect(self.paths.db_path)
        db.init_db(self.conn)
        self.blob_store = BlobStore(self.paths.blobs_dir)
        self.hmac_key = load_or_create_hmac_key(self.paths.key_path)
        self.caps_key = load_or_create_key(self.paths.caps_key_path, env_var="BLINDOP_CAPS_KEY", length=32)
        self.budget = budget

        self._require_caps = os.getenv("BLINDOP_REQUIRE_CAPS", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

        self._budget_iocs_hashed_per_case = _read_budget_limit("BLINDOP_BUDGET_IOCS_HASHED_PER_CASE", 200)
        self._budget_rulepack_scans_per_case = _read_budget_limit("BLINDOP_BUDGET_RULEPACK_SCANS_PER_CASE", 1000)

        self._tools: Dict[str, ToolSpec] = {
            "case.create": ToolSpec(
                policy=ToolPolicy(
                    name="case.create",
                    max_input_label=Label.restricted,
                    output_label=Label.internal,
                    description="Create a new case (returns opaque case_id).",
                ),
                handler=lambda *, name=None: case_tools.create(self.conn, name=name),
            ),
            "case.list": ToolSpec(
                policy=ToolPolicy(
                    name="case.list",
                    max_input_label=Label.restricted,
                    output_label=Label.internal,
                    description="List cases.",
                ),
                handler=lambda: case_tools.list_(self.conn),
            ),
            "artifact.ingest": ToolSpec(
                policy=ToolPolicy(
                    name="artifact.ingest",
                    max_input_label=Label.restricted,
                    output_label=Label.internal,
                    description="Ingest a file into the vault and return an opaque handle.",
                ),
                handler=lambda *, case_id, src_path, label: artifact_tools.ingest(
                    self.conn,
                    blob_store=self.blob_store,
                    case_id=case_id,
                    src_path=src_path,
                    label=label,
                ),
                case_args=("case_id",),
                label_args=("label",),
            ),
            "artifact.show": ToolSpec(
                policy=ToolPolicy(
                    name="artifact.show",
                    max_input_label=Label.restricted,
                    output_label=Label.internal,
                    description="Show artifact metadata (never raw bytes).",
                ),
                handler=lambda *, handle: artifact_tools.show(self.conn, handle=handle),
                handle_args=("handle",),
            ),
            "artifact.list": ToolSpec(
                policy=ToolPolicy(
                    name="artifact.list",
                    max_input_label=Label.restricted,
                    output_label=Label.internal,
                    description="List artifacts for a case.",
                ),
                handler=lambda *, case_id: artifact_tools.list_(self.conn, case_id=case_id),
                case_args=("case_id",),
            ),
            "artifact.move": ToolSpec(
                policy=ToolPolicy(
                    name="artifact.move",
                    max_input_label=Label.restricted,
                    output_label=Label.internal,
                    description="Move an artifact to a different case.",
                ),
                handler=lambda *, handle, case_id: artifact_tools.move(self.conn, handle=handle, case_id=case_id),
                handle_args=("handle",),
                case_args=("case_id",),
            ),
            "tag.add": ToolSpec(
                policy=ToolPolicy(
                    name="tag.add",
                    max_input_label=Label.restricted,
                    output_label=Label.internal,
                    description="Add a tag to an artifact.",
                ),
                handler=lambda *, handle, tag: tag_tools.add(self.conn, handle=handle, tag=tag),
                handle_args=("handle",),
            ),
            "tag.remove": ToolSpec(
                policy=ToolPolicy(
                    name="tag.remove",
                    max_input_label=Label.restricted,
                    output_label=Label.internal,
                    description="Remove a tag from an artifact.",
                ),
                handler=lambda *, handle, tag: tag_tools.remove(self.conn, handle=handle, tag=tag),
                handle_args=("handle",),
            ),
            "artifact.dedupe": ToolSpec(
                policy=ToolPolicy(
                    name="artifact.dedupe",
                    max_input_label=Label.restricted,
                    output_label=Label.internal,
                    description="Group artifacts by blob sha256.",
                ),
                handler=lambda *, case_id, include_unique=False: artifact_tools.dedupe(
                    self.conn, case_id=case_id, include_unique=include_unique
                ),
                case_args=("case_id",),
            ),
            "rulepack.register": ToolSpec(
                policy=ToolPolicy(
                    name="rulepack.register",
                    max_input_label=Label.restricted,
                    output_label=Label.internal,
                    description="Register a trusted rulepack JSON file and return a rulepack_id.",
                ),
                handler=lambda *, rules_path, name=None: rulepack_tools.register(
                    self.conn,
                    rules_path=rules_path,
                    name=name,
                ),
            ),
            "rulepack.list": ToolSpec(
                policy=ToolPolicy(
                    name="rulepack.list",
                    max_input_label=Label.restricted,
                    output_label=Label.internal,
                    description="List registered rulepacks.",
                ),
                handler=lambda *, limit=200: rulepack_tools.list_(self.conn, limit=limit),
            ),
            "rulepack.scan": ToolSpec(
                policy=ToolPolicy(
                    name="rulepack.scan",
                    max_input_label=Label.restricted,
                    output_label=Label.internal,
                    description="Scan an artifact with a rulepack and return rule IDs only.",
                ),
                handler=lambda *, handle, rulepack_id: rulepack_tools.scan(
                    self.conn, blob_store=self.blob_store, handle=handle, rulepack_id=rulepack_id
                ),
                handle_args=("handle",),
            ),
            "iocs.extract": ToolSpec(
                policy=ToolPolicy(
                    name="iocs.extract",
                    max_input_label=Label.restricted,
                    output_label=Label.internal,
                    description="Extract IOC counts and optionally HMAC-pseudonymized IOCs.",
                ),
                handler=lambda *, handle, include_hashes=False, top=20, k_min=1: ioc_tools.extract(
                    self.conn,
                    blob_store=self.blob_store,
                    hmac_key=self.hmac_key,
                    handle=handle,
                    include_hashes=include_hashes,
                    top=top,
                    k_min=k_min,
                ),
                handle_args=("handle",),
            ),
            "timeline.build": ToolSpec(
                policy=ToolPolicy(
                    name="timeline.build",
                    max_input_label=Label.restricted,
                    output_label=Label.internal,
                    description="Build a coarse event timeline for a case.",
                ),
                handler=lambda *, case_id, limit=200: timeline_tools.build(self.conn, case_id=case_id, limit=limit),
                case_args=("case_id",),
            ),
            "artifact.diff": ToolSpec(
                policy=ToolPolicy(
                    name="artifact.diff",
                    max_input_label=Label.restricted,
                    output_label=Label.internal,
                    description="Diff artifacts via metadata + coarse statistics (no raw content).",
                ),
                handler=lambda *, handle_a, handle_b: artifact_tools.diff(
                    self.conn,
                    blob_store=self.blob_store,
                    handle_a=handle_a,
                    handle_b=handle_b,
                ),
                handle_args=("handle_a", "handle_b"),
            ),
        }

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass

    def describe_tools(self) -> Dict[str, Any]:
        return {
            name: {
                "max_input_label": spec.policy.max_input_label.value,
                "output_label": spec.policy.output_label.value,
                "output_label_mode": "join(input_label, output_label)",
                "description": spec.policy.description,
            }
            for name, spec in sorted(self._tools.items())
        }

    def call(self, tool: str, **kwargs: Any) -> Dict[str, Any]:
        request_id = new_id()
        ts = utc_now_iso()

        caps_tokens = kwargs.pop("caps", None)
        cap_ids: Optional[list[str]] = None

        if tool not in self._tools:
            self._audit(ts, request_id, tool, allowed=False, reason="unknown_tool")
            raise ToolInputError(f"unknown tool: {tool}")

        spec = self._tools[tool]

        if self._require_caps:
            cap_ids = self._authorize_caps(
                ts,
                request_id,
                tool,
                spec,
                kwargs,
                caps_tokens=caps_tokens,
            )

        input_label = self._compute_input_label(spec, kwargs)
        output_label = join([input_label, spec.policy.output_label])

        if not dominates(spec.policy.max_input_label, input_label):
            self._audit(
                ts,
                request_id,
                tool,
                allowed=False,
                reason=f"input_label_too_high:{input_label.value}",
                input_label=input_label,
                output_label=output_label,
                cap_ids=cap_ids,
            )
            raise PolicyDenied(
                f"tool '{tool}' denied for input_label={input_label.value} (max={spec.policy.max_input_label.value})"
            )

        self._enforce_budgets(
            ts,
            request_id,
            tool,
            kwargs,
            input_label=input_label,
            output_label=output_label,
            cap_ids=cap_ids,
        )

        try:
            raw_result = spec.handler(**kwargs)
            viewed = self._apply_safe_view(raw_result, output_label=output_label)
            safe_result = sanitize(viewed, self.budget)
        except Exception as e:
            self._audit(
                ts,
                request_id,
                tool,
                allowed=True,
                reason=f"error:{type(e).__name__}",
                input_label=input_label,
                output_label=output_label,
                cap_ids=cap_ids,
            )
            raise

        self._audit(
            ts,
            request_id,
            tool,
            allowed=True,
            reason="ok",
            input_label=input_label,
            output_label=output_label,
            cap_ids=cap_ids,
        )
        return sanitize(
            {
                "ok": True,
                "request_id": request_id,
                "tool": tool,
                "input_label": input_label.value,
                "output_label": output_label.value,
                "result": safe_result,
            },
            self.budget,
        )

    def _apply_safe_view(self, obj: Any, *, output_label: Label) -> Any:
        if output_label not in (Label.confidential, Label.restricted):
            return obj
        return self._pseudonymize_metadata(obj)

    def _pseudonymize_metadata(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            out: Dict[str, Any] = {}
            for k, v in obj.items():
                if k in ("blob_sha256", "blob_sha256_a", "blob_sha256_b") and isinstance(v, str):
                    out[k] = pseudonymize(self.hmac_key, namespace="blob_sha256", value=v)
                    continue
                if k == "orig_filename" and isinstance(v, str):
                    out[k] = pseudonymize(self.hmac_key, namespace="orig_filename", value=v)
                    continue
                out[k] = self._pseudonymize_metadata(v)
            return out
        if isinstance(obj, list):
            return [self._pseudonymize_metadata(v) for v in obj]
        return obj

    def _compute_input_label(self, spec: ToolSpec, kwargs: Dict[str, Any]) -> Label:
        labels = []
        for arg in spec.handle_args:
            if arg not in kwargs:
                continue
            v = kwargs[arg]
            if isinstance(v, str):
                labels.append(db.artifact_label(self.conn, v))
            elif isinstance(v, (list, tuple)):
                labels.extend(db.artifact_label(self.conn, h) for h in v)
            else:
                raise ToolInputError(f"invalid handle arg '{arg}'")

        for arg in spec.case_args:
            if arg not in kwargs:
                continue
            v = kwargs[arg]
            if isinstance(v, str):
                labels.append(db.case_label(self.conn, v))
            else:
                raise ToolInputError(f"invalid case arg '{arg}'")

        for arg in spec.label_args:
            if arg not in kwargs:
                continue
            v = kwargs[arg]
            if isinstance(v, Label):
                labels.append(v)
            elif isinstance(v, str):
                labels.append(Label(v))
            else:
                raise ToolInputError(f"invalid label arg '{arg}'")

        return join(labels) if labels else Label.public

    def _enforce_budgets(
        self,
        ts: str,
        request_id: str,
        tool: str,
        kwargs: Dict[str, Any],
        *,
        input_label: Label,
        output_label: Label,
        cap_ids: Optional[list[str]] = None,
    ) -> None:
        if tool == "iocs.extract" and bool(kwargs.get("include_hashes")):
            limit = self._budget_iocs_hashed_per_case
            if limit is not None:
                handle = kwargs.get("handle")
                if not isinstance(handle, str):
                    raise ToolInputError("invalid handle")
                case_id = db.artifact_case_id(self.conn, handle)
                used = db.event_count(self.conn, case_id, kind="iocs_hashed_extracted")
                if used >= limit:
                    reason = f"budget_exhausted:iocs_hashed_extracted:{used}/{limit}"
                    self._audit(
                        ts,
                        request_id,
                        tool,
                        allowed=False,
                        reason=reason,
                        input_label=input_label,
                        output_label=output_label,
                        case_id=case_id,
                        cap_ids=cap_ids,
                    )
                    raise PolicyDenied(f"budget exhausted for case {case_id}: iocs_hashed_extracted {used}/{limit}")

        if tool == "rulepack.scan":
            limit = self._budget_rulepack_scans_per_case
            if limit is not None:
                handle = kwargs.get("handle")
                if not isinstance(handle, str):
                    raise ToolInputError("invalid handle")
                case_id = db.artifact_case_id(self.conn, handle)
                used = db.event_count(self.conn, case_id, kind="rulepack_scanned")
                if used >= limit:
                    reason = f"budget_exhausted:rulepack_scanned:{used}/{limit}"
                    self._audit(
                        ts,
                        request_id,
                        tool,
                        allowed=False,
                        reason=reason,
                        input_label=input_label,
                        output_label=output_label,
                        case_id=case_id,
                        cap_ids=cap_ids,
                    )
                    raise PolicyDenied(f"budget exhausted for case {case_id}: rulepack_scanned {used}/{limit}")

    def _authorize_caps(
        self,
        ts: str,
        request_id: str,
        tool: str,
        spec: ToolSpec,
        kwargs: Dict[str, Any],
        *,
        caps_tokens: Any,
    ) -> list[str]:
        tokens: list[str] = []
        if caps_tokens is None:
            tokens = []
        elif isinstance(caps_tokens, str):
            tokens = [caps_tokens]
        elif isinstance(caps_tokens, (list, tuple)):
            tokens = [str(t) for t in caps_tokens]
        else:
            raise ToolInputError("invalid caps")

        if not tokens:
            self._audit(ts, request_id, tool, allowed=False, reason="caps_missing")
            raise PolicyDenied("capabilities required")

        verified = []
        for t in tokens:
            try:
                verified.append(verify_token(self.caps_key, t))
            except ToolInputError:
                self._audit(ts, request_id, tool, allowed=False, reason="caps_invalid")
                raise PolicyDenied("invalid capability token")

        # Pre-filter caps that allow this tool
        usable = []
        for c in verified:
            tools = c.get("tools") or []
            if "*" in tools or tool in tools:
                usable.append(c)

        if not usable:
            self._audit(ts, request_id, tool, allowed=False, reason="caps_tool_not_allowed")
            raise PolicyDenied(f"tool not allowed by capabilities: {tool}")

        required = self._required_resources(spec, kwargs)
        used_cap_ids: list[str] = []

        # Tool-specific case write constraints
        case_write_needs: list[tuple[str, Label]] = []
        if tool == "artifact.ingest":
            case_id = kwargs.get("case_id")
            label_arg = kwargs.get("label")
            if isinstance(case_id, str) and label_arg is not None:
                label = label_arg if isinstance(label_arg, Label) else parse_label(str(label_arg))
                case_write_needs.append((case_id, label))
        if tool == "artifact.move":
            case_id = kwargs.get("case_id")
            handle = kwargs.get("handle")
            if isinstance(case_id, str) and isinstance(handle, str):
                case_write_needs.append((case_id, db.artifact_label(self.conn, handle)))

        # Ensure each required resource is covered
        for rtype, rid in required:
            if not self._has_cap_for_resource(usable, tool, rtype, rid):
                self._audit(ts, request_id, tool, allowed=False, reason=f"caps_missing_resource:{rtype}")
                raise PolicyDenied(f"capability missing for {rtype}:{rid}")

        # Enforce label clearances for required resources
        for rtype, rid in required:
            rlabel = self._resource_label(rtype, rid)
            cap_id = self._pick_cap_for_resource(usable, tool, rtype, rid, min_label=rlabel)
            if cap_id is None:
                self._audit(ts, request_id, tool, allowed=False, reason=f"caps_label_denied:{rtype}:{rlabel.value}")
                raise PolicyDenied(f"capability label denied for {rtype}:{rid}")
            used_cap_ids.append(cap_id)

        # Enforce case write constraints
        for case_id, min_label in case_write_needs:
            cap_id = self._pick_cap_for_resource(
                usable,
                tool,
                "case",
                case_id,
                min_label=min_label,
            )
            if cap_id is None:
                self._audit(
                    ts,
                    request_id,
                    tool,
                    allowed=False,
                    reason=f"caps_case_write_denied:{min_label.value}",
                    case_id=case_id,
                )
                raise PolicyDenied(f"capability denied to write {min_label.value} into case {case_id}")
            used_cap_ids.append(cap_id)

        # Deduplicate while preserving order
        seen = set()
        out = []
        for cid in used_cap_ids:
            if cid in seen:
                continue
            seen.add(cid)
            out.append(cid)
        return out

    def _required_resources(self, spec: ToolSpec, kwargs: Dict[str, Any]) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for arg in spec.handle_args:
            v = kwargs.get(arg)
            if isinstance(v, str):
                out.append(("artifact", v))
            elif v is None:
                continue
            else:
                raise ToolInputError(f"invalid handle arg '{arg}'")

        for arg in spec.case_args:
            v = kwargs.get(arg)
            if isinstance(v, str):
                out.append(("case", v))
            elif v is None:
                continue
            else:
                raise ToolInputError(f"invalid case arg '{arg}'")

        if not out:
            out.append(("global", "*"))
        return out

    def _resource_label(self, rtype: str, rid: str) -> Label:
        if rtype == "artifact":
            return db.artifact_label(self.conn, rid)
        if rtype == "case":
            return db.case_label(self.conn, rid)
        return Label.public

    def _has_cap_for_resource(self, caps: list[Dict[str, Any]], tool: str, rtype: str, rid: str) -> bool:
        return self._pick_cap_for_resource(caps, tool, rtype, rid, min_label=Label.public) is not None

    def _pick_cap_for_resource(
        self,
        caps: list[Dict[str, Any]],
        tool: str,
        rtype: str,
        rid: str,
        *,
        min_label: Label,
    ) -> Optional[str]:
        for c in caps:
            cap_id = c.get("cap_id")
            if not isinstance(cap_id, str):
                continue
            max_label_raw = c.get("max_label")
            if not isinstance(max_label_raw, str):
                continue
            try:
                max_label = parse_label(max_label_raw)
            except Exception:
                continue
            if not dominates(max_label, min_label):
                continue

            if self._cap_covers_resource(c, rtype, rid):
                return cap_id
        return None

    def _cap_covers_resource(self, cap: Dict[str, Any], rtype: str, rid: str) -> bool:
        resources = cap.get("resources") or []
        if not isinstance(resources, list):
            return False

        artifact_case_id: Optional[str] = None
        if rtype == "artifact":
            try:
                artifact_case_id = db.artifact_case_id(self.conn, rid)
            except Exception:
                artifact_case_id = None

        for r in resources:
            if not isinstance(r, dict):
                continue
            rt = r.get("type")
            ri = r.get("id")
            if not isinstance(rt, str) or not isinstance(ri, str):
                continue

            if rt == rtype and (ri == rid or ri == "*"):
                return True

            if rtype == "artifact" and rt == "case" and artifact_case_id is not None:
                if bool(r.get("include_artifacts")) and (ri == artifact_case_id or ri == "*"):
                    return True

        return False

    def _audit(
        self,
        ts: str,
        request_id: str,
        tool: str,
        *,
        allowed: bool,
        reason: str,
        input_label: Optional[Label] = None,
        output_label: Optional[Label] = None,
        case_id: Optional[str] = None,
        cap_ids: Optional[list[str]] = None,
    ) -> None:
        rec = {
            "ts": ts,
            "request_id": request_id,
            "tool": tool,
            "allowed": allowed,
            "reason": reason,
        }
        if input_label is not None:
            rec["input_label"] = input_label.value
        if output_label is not None:
            rec["output_label"] = output_label.value
        if case_id is not None:
            rec["case_id"] = case_id
        if cap_ids is not None:
            rec["cap_ids"] = cap_ids
        try:
            self.paths.audit_log.parent.mkdir(parents=True, exist_ok=True)
            with self.paths.audit_log.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n")
        except Exception:
            pass
