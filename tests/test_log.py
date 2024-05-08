import pytest
from freezegun import freeze_time

from audit_log.log import log, to_serializable
from audit_log.schema import ActionType, OutcomeResult, Principal, PrincipalType


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
        "principal",
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
            Principal(
                type=PrincipalType.USER,
                authority="respect_mine",
                id="test.user@test.com",
            ),
            '{"type": "audit-log", "timestamp": "2022-04-20T12:00:00+00:00", "level": "INFO", "version": 1, '
            '"resource": {"type": "test", "id": "123e4567-e89b-12d3-a456-426614174000"}, "action": {"type": '
            '"CREATE"}, "outcome": {"result": "SUCCEEDED", "reason": "Some reason", "before": null, '
            '"after": null}, "context": {"request": {"id": "123e4567-e89b-12d3-a456-426614174000"}}, '
            '"principal": {"type": "USER", "authority": "respect_mine", "id": "test.user@test.com"}}',
        ),
    ],
)
def test_log(
    action_type,
    resource_type,
    resource_id,
    result,
    request_id,
    outcome_reason,
    principal,
    expected_log,
    capsys,
):
    with freeze_time("2022-04-20T12:00:00+00:00"):
        log(
            action_type=action_type,
            resource_type=resource_type,
            resource_id=resource_id,
            result=result,
            request_id=request_id,
            outcome_reason=outcome_reason,
            principal=principal,
        )
        printed_message = capsys.readouterr().out.strip()
        assert printed_message == expected_log
