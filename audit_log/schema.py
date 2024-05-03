from enum import StrEnum

SCHEMA_VERSION = "v1"


class PrincipalType(StrEnum):
    USER = "USER"
    SERVICE = "SERVICE"


class ActionType(StrEnum):
    CREATE = "CREATE"
    READ = "READ"
    UPDATE = "UPDATE"
    DELETE = "DELETE"


class OutcomeResult(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    DENIED = "DENIED"
