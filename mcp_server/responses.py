from __future__ import annotations

from typing import Any
from .models import ToolError, ToolResponse


def ok(data: Any, **meta: Any) -> dict:
    return ToolResponse(ok=True, data=data, meta=meta).model_dump()


def fail(code: str, message: str, detail: str | None = None, **meta: Any) -> dict:
    return ToolResponse(
        ok=False,
        error=ToolError(code=code, message=message, detail=detail),
        meta=meta,
    ).model_dump()