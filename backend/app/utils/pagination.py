import math


def total_pages(total_elements: int, size: int) -> int:
    if size <= 0:
        raise ValueError("size must be positive")
    return math.ceil(total_elements / size) if total_elements else 0

