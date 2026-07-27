import re
from typing import Any


class MaskingService:
    MASKED = "[MASKED]"
    SECRET_KEYS = {
        "authorization",
        "accesstoken",
        "refreshtoken",
        "cookie",
        "sessionid",
        "password",
        "apikey",
    }
    ACCOUNT_KEYS = {"account", "accountnumber", "bankaccount"}
    USER_ID_KEYS = {"userid", "actorid"}

    resident_number = re.compile(r"\b(\d{6})[- ]?(\d{7})\b")
    phone_number = re.compile(r"\b(01[016789])[- ]?(\d{3,4})[- ]?(\d{4})\b")
    email = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")

    def mask(self, value: Any, *, key: str | None = None) -> Any:
        normalized_key = self._normalize_key(key) if key else None
        if normalized_key in self.SECRET_KEYS:
            return self.MASKED
        if normalized_key in self.ACCOUNT_KEYS and isinstance(value, str):
            digits = re.sub(r"\D", "", value)
            return f"{'*' * max(len(digits) - 4, 0)}{digits[-4:]}" if digits else self.MASKED
        if normalized_key in self.USER_ID_KEYS:
            # TODO: User ID masking depends on the final evidence verification contract.
            return value
        if isinstance(value, dict):
            return {
                item_key: self.mask(item_value, key=str(item_key))
                for item_key, item_value in value.items()
            }
        if isinstance(value, list):
            return [self.mask(item, key=key) for item in value]
        if isinstance(value, tuple):
            return tuple(self.mask(item, key=key) for item in value)
        if isinstance(value, str):
            return self._mask_text(value)
        return value

    def _mask_text(self, value: str) -> str:
        value = self.resident_number.sub(lambda match: f"{match.group(1)}-*******", value)
        value = self.phone_number.sub(
            lambda match: f"{match.group(1)}-****-{match.group(3)}",
            value,
        )
        return self.email.sub(self._mask_email, value)

    @staticmethod
    def _mask_email(match: re.Match[str]) -> str:
        local, domain = match.groups()
        visible = local[:1]
        return f"{visible}{'*' * max(len(local) - 1, 3)}@{domain}"

    @staticmethod
    def _normalize_key(value: str) -> str:
        return re.sub(r"[^a-z0-9]", "", value.lower())

