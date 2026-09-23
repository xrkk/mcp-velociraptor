"""Bounded content-layer errors. Context contains identifiers, never content."""


class TransferContentError(Exception):
    def __init__(self, code: str, **context: object) -> None:
        self.code = code
        self.context = {key: value for key, value in context.items()
                        if isinstance(value, (str, int, bool, type(None)))}
        super().__init__(code)
