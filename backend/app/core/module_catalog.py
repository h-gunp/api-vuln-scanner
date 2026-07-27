"""Temporary module presentation metadata.

TODO: Replace this catalog when the final scanner module contract is agreed.
"""

MODULE_TITLES: dict[str, str] = {
    "BOLA-001": "객체 수준 인가 검증 실패",
    "AUTHN-001": "인증 검증 실패",
    "INPUT-001": "입력값 검증 미흡",
    "DATA-001": "민감정보 과다 노출",
}

MODULE_SUMMARIES: dict[str, str] = {
    "BOLA-001": "다른 사용자의 객체 정보에 접근할 가능성이 확인되었습니다.",
    "AUTHN-001": "인증 검증을 우회할 가능성이 확인되었습니다.",
    "INPUT-001": "입력값 검증이 충분하지 않은 동작이 확인되었습니다.",
    "DATA-001": "응답에서 민감정보가 과도하게 노출될 가능성이 확인되었습니다.",
}

UNKNOWN_MODULE_TITLE = "검증된 보안 취약점"
UNKNOWN_MODULE_SUMMARY = "규칙 기반 검증에서 보안 문제가 확인되었습니다."

