def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


def safe_divide(a: float, b: float):
    """Divide, returning None rather than raising on zero."""
    if b == 0:
        return None
    return a / b
