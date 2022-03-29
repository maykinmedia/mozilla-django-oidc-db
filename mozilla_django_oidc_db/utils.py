from typing import Any


def obfuscate_claim(value: Any) -> str:
    """
    Obfuscates the value of a claim, so it can be logged safely
    """
    value = str(value)
    threshold = int(len(value) * 0.75)
    return "".join([x if i > threshold else "*" for i, x in enumerate(value)])
