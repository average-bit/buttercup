from __future__ import annotations

from typing import Dict, Any
from pydantic import BaseModel, Field


class SARIFBroadcastDetail(BaseModel):
    """Model for SARIF broadcast details, matches the model in types.py"""

    metadata: Dict[str, Any] = Field(
        ...,
        description="String to string map containing data that should be attached to outputs like log messages and OpenTelemetry trace attributes for traceability",
    )
    sarif: Dict[str, Any] = Field(..., description="SARIF Report compliant with provided schema")
    sarif_id: str
    task_id: str
