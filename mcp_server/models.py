from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field


class ToolError(BaseModel):
    code: str
    message: str
    detail: str | None = None


class ToolResponse(BaseModel):
    ok: bool
    data: Any | None = None
    error: ToolError | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class InvestigationRequest(BaseModel):
    timespan: str = "P3D"
    max_rows: int = 50


class IncidentInvestigationRequest(InvestigationRequest):
    incident_id: int


class EntityInvestigationRequest(InvestigationRequest):
    value: str


class Finding(BaseModel):
    table: str
    telemetry_domain: str
    matched_entity: str
    summary: str
    count: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    sample_fields: dict[str, Any] = Field(default_factory=dict)


class TimelineEvent(BaseModel):
    timestamp: str | None = None
    source: str
    description: str


class IncidentOverview(BaseModel):
    incident_number: int | None = None
    title: str | None = None
    severity: str | None = None
    status: str | None = None
    owner: str | None = None
    created_time: str | None = None


class RiskAssessment(BaseModel):
    classification: Literal["Low", "Medium", "High"]
    rationale: list[str] = Field(default_factory=list)