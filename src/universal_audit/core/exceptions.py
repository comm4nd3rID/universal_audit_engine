
class UniversalAuditError(Exception):
    """Base application exception."""


class InputValidationError(UniversalAuditError):
    pass


class PlatformDiscoveryError(UniversalAuditError):
    pass


class AuditCompatibilityError(UniversalAuditError):
    pass


class ReportValidationError(UniversalAuditError):
    pass
