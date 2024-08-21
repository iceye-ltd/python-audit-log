class AuditError(Exception):
    """General error in audit library"""


class AuditValidationError(Exception):
    """Audit logging called without proper data"""


class AuditPrincipalError(AuditError):
    """Error with the principal"""
