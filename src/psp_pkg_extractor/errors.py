"""Public exceptions for package and extraction failures."""


class PkgError(Exception):
    """Base class for expected errors."""


class InvalidPackageError(PkgError):
    """The input is malformed, truncated, or unsafe."""


class UnsupportedPackageError(PkgError):
    """The package or entry uses an unsupported format."""


class ExtractionError(PkgError):
    """The destination cannot safely be published."""
