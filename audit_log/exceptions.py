class AuditError(Exception):
    """General error in audit library"""


class AuditPrincipalError(AuditError):
    """Error with the principal"""
