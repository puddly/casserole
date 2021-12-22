class ParsingError(ValueError):
    def __init__(self, message=None, remaining=None):
        super().__init__(message)
        self.remaining = remaining


class IncompleteReadError(ParsingError):
    pass
