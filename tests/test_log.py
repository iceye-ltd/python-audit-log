from uuid import UUID

import pytest
from freezegun import freeze_time

from audit_log.exceptions import AuditValidationError
from audit_log.log import log, to_serializable
from audit_log.schema import ActionType, OutcomeResult, Principal, PrincipalType


@pytest.fixture
def sample_principal() -> Principal:
    return Principal(PrincipalType.USER, authority="test", id="pytester")


@pytest.mark.parametrize(
    ("value", "expected_result"),
    [
        (123, "123"),
        ({"key": "value"}, "{'key': 'value'}"),
    ],
)
def test_to_serializable_default(value, expected_result):
    assert to_serializable(value) == expected_result


def test_to_serializable_set():
    value = {1, 2, 3}
    assert to_serializable(value) == [1, 2, 3]


def test_to_serializable_exception():
    val = ValueError("test")
    assert to_serializable(val) == repr(val)


@pytest.mark.parametrize(
    (
        "action_type",
        "resource_type",
        "resource_id",
        "result",
        "request_id",
        "outcome_reason",
        "before",
        "after",
        "expected_log",
    ),
    [
        (
            ActionType.CREATE,
            "test",
            "123e4567-e89b-12d3-a456-426614174000",
            OutcomeResult.SUCCEEDED,
            "123e4567-e89b-12d3-a456-426614174000",
            "Some reason",
            None,
            {"test": "yes"},
            '{"type": "audit-log", "timestamp": "2022-04-20T12:00:00+00:00", "level": "INFO", "version": 1, '
            '"resource": {"type": "test", "id": "123e4567-e89b-12d3-a456-426614174000"}, "action": {"type": '
            '"CREATE"}, "outcome": {"result": "SUCCEEDED", "reason": "Some reason", "before": null, '
            '"after": {"test": "yes"}}, "context": {"request": {"id": "123e4567-e89b-12d3-a456-426614174000"}}, '
            '"principal": {"type": "USER", "authority": "test", "id": "pytester"}}',
        ),
        (
            ActionType.CREATE,
            "test",
            None,
            OutcomeResult.DENIED,
            "123e4567-e89b-12d3-a456-426614174000",
            "Some reason",
            None,
            None,
            '{"type": "audit-log", "timestamp": "2022-04-20T12:00:00+00:00", "level": "INFO", "version": 1, '
            '"resource": {"type": "test", "id": null}, "action": {"type": '
            '"CREATE"}, "outcome": {"result": "DENIED", "reason": "Some reason", "before": null, '
            '"after": null}, "context": {"request": {"id": "123e4567-e89b-12d3-a456-426614174000"}}, '
            '"principal": {"type": "USER", "authority": "test", "id": "pytester"}}',
        ),
        (
            ActionType.UPDATE,
            "test",
            "123e4567-e89b-12d3-a456-426614174000",
            OutcomeResult.SUCCEEDED,
            "123e4567-e89b-12d3-a456-426614174000",
            "Some reason",
            {"test": "maybe"},
            {"test": "yes"},
            '{"type": "audit-log", "timestamp": "2022-04-20T12:00:00+00:00", "level": "INFO", "version": 1, '
            '"resource": {"type": "test", "id": "123e4567-e89b-12d3-a456-426614174000"}, "action": {"type": '
            '"UPDATE"}, "outcome": {"result": "SUCCEEDED", "reason": "Some reason", "before": {"test": "maybe"}, '
            '"after": {"test": "yes"}}, "context": {"request": {"id": "123e4567-e89b-12d3-a456-426614174000"}}, '
            '"principal": {"type": "USER", "authority": "test", "id": "pytester"}}',
        ),
        (
            ActionType.DELETE,
            "test",
            "123e4567-e89b-12d3-a456-426614174000",
            OutcomeResult.SUCCEEDED,
            "123e4567-e89b-12d3-a456-426614174000",
            "Some reason",
            {"test": "yes"},
            None,
            '{"type": "audit-log", "timestamp": "2022-04-20T12:00:00+00:00", "level": "INFO", "version": 1, '
            '"resource": {"type": "test", "id": "123e4567-e89b-12d3-a456-426614174000"}, "action": {"type": '
            '"DELETE"}, "outcome": {"result": "SUCCEEDED", "reason": "Some reason", "before": {"test": "yes"}, '
            '"after": null}, "context": {"request": {"id": "123e4567-e89b-12d3-a456-426614174000"}}, '
            '"principal": {"type": "USER", "authority": "test", "id": "pytester"}}',
        ),
    ],
)
def test_log(
    action_type: ActionType,
    resource_type: str,
    resource_id: str | None,
    result: OutcomeResult,
    request_id: str | UUID | None,
    outcome_reason: str | None,
    before: dict | None,
    after: dict | None,
    expected_log: str,
    capsys: pytest.CaptureFixture,
    sample_principal: Principal,
):
    with freeze_time("2022-04-20T12:00:00+00:00"):
        log(
            action_type=action_type,
            resource_type=resource_type,
            resource_id=resource_id,
            result=result,
            request_id=request_id,
            outcome_reason=outcome_reason,
            principal=sample_principal,
            before=before,
            after=after,
        )
        printed_message = capsys.readouterr().out.strip()
        assert printed_message == expected_log


@pytest.mark.parametrize(
    ("action_type", "resource_id", "before", "after", "expected_error"),
    [
        (ActionType.CREATE, None, None, {"t": 1}, "Missing resource ID"),
        (ActionType.CREATE, 1, None, None, "Missing 'after' with CREATE action"),
        (
            ActionType.UPDATE,
            1,
            None,
            None,
            "Missing 'before' and 'after' with UPDATE action",
        ),
        (
            ActionType.UPDATE,
            1,
            None,
            {"t": 1},
            "Missing 'before' and 'after' with UPDATE action",
        ),
        (
            ActionType.UPDATE,
            1,
            {"t": 1},
            None,
            "Missing 'before' and 'after' with UPDATE action",
        ),
        (ActionType.DELETE, 1, None, None, "Missing 'before' with DELETE action"),
    ],
)
def test_log_validation(
    action_type: ActionType,
    resource_id: int | None,
    before: dict | None,
    after: dict | None,
    expected_error: str,
    sample_principal: Principal,
):
    with pytest.raises(AuditValidationError, match=expected_error):
        log(
            action_type=action_type,
            resource_type="test/test",
            resource_id=resource_id,
            result=OutcomeResult.SUCCEEDED,
            request_id="123e4567-e89b-12d3-a456-426614174000",
            principal=sample_principal,
            before=before,
            after=after,
        )
