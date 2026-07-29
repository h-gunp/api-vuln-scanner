from dataclasses import dataclass


@dataclass(slots=True)
class LLMError(Exception):
    code: str
    message: str
    retryable: bool = False

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"
