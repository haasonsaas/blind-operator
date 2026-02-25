class BlindOpError(Exception):
    pass


class PolicyDenied(BlindOpError):
    pass


class ToolInputError(BlindOpError):
    pass


class NotFoundError(BlindOpError):
    pass
