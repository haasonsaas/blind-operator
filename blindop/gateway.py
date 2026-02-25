from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

from . import db
from .errors import PolicyDenied, ToolInputError
from .keys import load_or_create_hmac_key
from .policy import Label, ToolPolicy, dominates, join
from .safe_output import SafeOutputBudget, sanitize
from .state import StatePaths, ensure_state_paths
from .util import new_id, utc_now_iso
from .vault import BlobStore
from .tools import artifact_tools, case_tools, ioc_tools, rulepack_tools, tag_tools, timeline_tools


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
        self.budget = budget

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
            "rulepack.scan": ToolSpec(
                policy=ToolPolicy(
                    name="rulepack.scan",
                    max_input_label=Label.restricted,
                    output_label=Label.internal,
                    description="Scan an artifact with a rulepack and return rule IDs only.",
                ),
                handler=lambda *, handle, rules_path: rulepack_tools.scan(
                    self.conn, blob_store=self.blob_store, handle=handle, rules_path=rules_path
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
                handler=lambda *, handle, include_hashes=False, top=20: ioc_tools.extract(
                    self.conn,
                    blob_store=self.blob_store,
                    hmac_key=self.hmac_key,
                    handle=handle,
                    include_hashes=include_hashes,
                    top=top,
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

        if tool not in self._tools:
            self._audit(ts, request_id, tool, allowed=False, reason="unknown_tool")
            raise ToolInputError(f"unknown tool: {tool}")

        spec = self._tools[tool]
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
            )
            raise PolicyDenied(
                f"tool '{tool}' denied for input_label={input_label.value} (max={spec.policy.max_input_label.value})"
            )

        try:
            raw_result = spec.handler(**kwargs)
            safe_result = sanitize(raw_result, self.budget)
        except Exception as e:
            self._audit(
                ts,
                request_id,
                tool,
                allowed=True,
                reason=f"error:{type(e).__name__}",
                input_label=input_label,
                output_label=output_label,
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
        try:
            self.paths.audit_log.parent.mkdir(parents=True, exist_ok=True)
            with self.paths.audit_log.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n")
        except Exception:
            pass
