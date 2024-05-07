from enum import StrEnum
from dataclasses import dataclass

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


@dataclass
class Principal:
    type_: PrincipalType
    authority: str
    id: str

    def to_json(self):
        data = self.__dict__.copy()
        data["type"] = data.pop("type_")
        return data
