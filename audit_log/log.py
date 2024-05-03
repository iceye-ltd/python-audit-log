import json
from datetime import datetime, UTC

from audit_log.schema import SCHEMA_VERSION


def log():
    now = datetime.now(tz=UTC).isoformat()
    print(
        json.dumps(
            {
                "type": "audit-log",
                "timestamp": now,
                "level": "INFO",
                "version": SCHEMA_VERSION,
            }
        )
    )


if __name__ == "__main__":
    log()
