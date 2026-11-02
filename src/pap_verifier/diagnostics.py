from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import List


@dataclass
class Diagnostic:
    code: str
    severity: str
    scope: str
    message: str

    def to_dict(self):
        return asdict(self)


def sort_diagnostics(diags: List[Diagnostic]) -> List[Diagnostic]:
    rank = {"error": 0, "warning": 1, "info": 2}
    return sorted(diags, key=lambda d: (rank.get(d.severity, 9), d.code, d.scope))