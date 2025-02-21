__all__ = ["ArgumentNoneError", "InvalidOperationError", "NotSupportedError", "PersonalDataError"]


class ArgumentNoneError(ValueError):
    """The exception that is thrown when a *None* reference
    is passed to a method that does not accept it as a valid argument.
    """

    def __init__(self, argument_name: str):
        super().__init__(f"Value '{argument_name}' cannot be None.")  # pragma: no cover


class InvalidOperationError(Exception):
    """The exception that is thrown when a method call is invalid for the object's current state."""


class NotSupportedError(Exception):
    """The exception that is thrown when an invoked method is not supported,
    typically because it should have been implemented on a subclass.
    """


class PersonalDataError(Exception):
    """The exception that occurs when it is not possible to obtain personal data."""
