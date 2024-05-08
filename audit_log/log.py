import functools
import json
import uuid
from collections.abc import Callable
from contextvars import ContextVar
from datetime import UTC, datetime
from functools import singledispatch
from typing import Any

from audit_log.schema import (
    SCHEMA_VERSION,
    ActionType,
    OutcomeResult,
    Principal,
    PrincipalType,
)


@singledispatch
def to_serializable(val) -> dict | list | str:
    """Default serialization"""
    return str(val)


@to_serializable.register
def serialize_sets(val: set) -> list:
    """Convert sets to lists for serialization"""
    return list(val)


@to_serializable.register
def serialize_exceptions(val: Exception) -> str:
    """Convert sets to lists for serialization"""
    return repr(val)


json_dumps = functools.partial(json.dumps, default=to_serializable)

# Example use of ContextVar, TBD if this works well
REQ_ID: ContextVar[str | uuid.UUID] = ContextVar("request_id")


def log(
    action_type: ActionType,
    resource_type: str,
    resource_id: Any,
    result: OutcomeResult,
    principal: Principal,
    request_id: str | uuid.UUID | None = None,
    outcome_reason: str | None = None,
    before: Any | None = None,
    after: Any | None = None,
    serializer: Callable[[dict], str | bytes] = json_dumps,
):
    now = datetime.now(tz=UTC).isoformat()
    request_id = request_id or REQ_ID.get()
    print(
        serializer(
            {
                "type": "audit-log",
                "timestamp": now,
                "level": "INFO",
                "version": SCHEMA_VERSION,
                "resource": {"type": resource_type, "id": resource_id},
                "action": {"type": action_type},
                "outcome": {
                    "result": result,
                    "reason": outcome_reason,
                    "before": before,
                    "after": after,
                },
                "context": {"request": {"id": request_id}},
                "principal": dataclasses.asdict(principal),
            }
        )
    )


if __name__ == "__main__":
    log(
        action_type=ActionType.CREATE,
        resource_type="test",
        resource_id=uuid.uuid4(),
        result=OutcomeResult.SUCCEEDED,
        request_id=uuid.uuid4(),
        outcome_reason=ValueError("test"),  # type: ignore[arg-type] # Purposeful mis-type to verify
        principal=Principal(
            type=PrincipalType.USER,
            authority="respect_mime",
            id="eric.cartman@yahoo.com",
        ),
    )
