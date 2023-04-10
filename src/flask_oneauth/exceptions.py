from flask import current_app


def exc_msg(exc: Exception):
    if current_app.debug:
        current_app.logger.debug(str(exc))
        return str(exc)
    return "Some error occurred. Please try again."


class ImproperlyConfigured(Exception):
    """
    `Flask-OneAuth` is somehow improperly configured.
    """
    def __int__(self, exc):
        super().__init__(exc_msg(exc))
