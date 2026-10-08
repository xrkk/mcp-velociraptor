"""Bounded content-layer errors. Context contains identifiers, never content."""


class TransferContentError(Exception):
    def __init__(self, code: str, **context: object) -> None:
        self.code = code
        self.context = {key: value for key, value in context.items()
                        if isinstance(value, (str, int, bool, type(None)))}
        super().__init__(code)


def source_io_error(path, operation: str, exc: OSError) -> TransferContentError:
    """Keep OS diagnostics even when the native exception has no filename."""
    return TransferContentError("source_unavailable", path=str(path), operation=operation,
                                errno=exc.errno, winerror=getattr(exc, "winerror", None),
                                os_error=str(exc)[:4096], os_error_type=type(exc).__name__)


def error_diagnostic(exc: Exception) -> dict:
    """Local log only: stable code plus identifiers and the underlying OS failure."""
    context = dict(exc.context) if isinstance(exc, TransferContentError) else {}
    current = exc
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, OSError):
            context.setdefault("errno", current.errno)
            context.setdefault("winerror", getattr(current, "winerror", None))
            context.setdefault("os_error", str(current)[:4096])
            context.setdefault("os_error_type", type(current).__name__)
            if current.filename is not None:
                context.setdefault("path", str(current.filename))
            break
        current = current.__cause__ or current.__context__
    return {"code": exc.code if isinstance(exc, TransferContentError) else "worker_failed",
            "exception_type": type(exc).__name__, "context": context}
