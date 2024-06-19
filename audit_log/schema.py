import enum
from dataclasses import dataclass

SCHEMA_VERSION = 1


class StrEnum(str, enum.Enum):
    pass


class PrincipalType(StrEnum):
    USER = "USER"
    SYSTEM = "SYSTEM"


class ActionType(StrEnum):
    CREATE = "CREATE"
    READ = "READ"
    UPDATE = "UPDATE"
    DELETE = "DELETE"


class OutcomeResult(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    DENIED = "DENIED"


@dataclass
class Principal:
    type: PrincipalType
    authority: str
    id: str
