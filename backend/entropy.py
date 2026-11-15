import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 = constant, 8.0 = uniformly random).

    Packed or encrypted code tends to score above ~7.0; normal compiled code
    is usually between 5 and 6.5.
    """
    if not data:
        return 0.0
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in Counter(data).values())
