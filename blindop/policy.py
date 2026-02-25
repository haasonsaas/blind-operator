from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class Label(str, Enum):
    public = "public"
    internal = "internal"
    confidential = "confidential"
    restricted = "restricted"


_LABEL_ORDER = {
    Label.public: 0,
    Label.internal: 1,
    Label.confidential: 2,
    Label.restricted: 3,
}


def parse_label(value: str) -> Label:
    try:
        return Label(value)
    except ValueError as e:
        raise ValueError(f"unknown label: {value}") from e


def dominates(a: Label, b: Label) -> bool:
    return _LABEL_ORDER[a] >= _LABEL_ORDER[b]


def join(labels: Iterable[Label]) -> Label:
    max_i = -1
    max_label = Label.public
    for lab in labels:
        i = _LABEL_ORDER[lab]
        if i > max_i:
            max_i = i
            max_label = lab
    return max_label


@dataclass(frozen=True)
class ToolPolicy:
    name: str
    max_input_label: Label
    output_label: Label
    description: str = ""
