from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


@dataclass
class Finding:
    status: Status
    cve: str
    target: str
    installed: str
    fixed: str
    remediation: str
    detail: str = ""
    detection_method: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Emit the audit JSON schema (plus detail/extra for debugging)."""
        return {
            "cve_id": self.cve,
            "installed_value": self.installed,
            "fixed_value": self.fixed,
            "verdict": self.status.value,
            "detection_method": self.detection_method,
            "remediation_step": self.remediation,
            "target": self.target,
            "detail": self.detail,
            "extra": self.extra,
        }

    def to_legacy_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data
