from typing import Literal, Optional

from pydantic import BaseModel, Field, HttpUrl


class Finding(BaseModel):
    vulnerability: str
    endpoint: str
    parameter: Optional[str] = None

    severity: str
    confidence: float

    cwe: str

    evidence: str
    detection_method: str

    exploitation_performed: bool = False

    recommendation: str

    difficulty: str = "easy"
    assessment_mode: str = "blackbox"


class ScanRequest(BaseModel):
    target: HttpUrl

    mode: Literal[
        "blackbox",
        "whitebox",
    ] = "blackbox"

    difficulty: Literal[
        "easy",
        "medium",
        "hard",
        "expert",
    ] = "easy"

    modules: list[str] = Field(
        default_factory=lambda: [
            "xss",
            "sqli",
            "lfi",
            "traversal",
            "rfi",
            "auth",
        ]
    )

    source_path: Optional[str] = None


class ScanResponse(BaseModel):
    target: str
    mode: str
    difficulty: str

    status: str

    security_score: int

    endpoints_discovered: int
    parameters_discovered: int

    findings: list[Finding]

    whitebox_hits: list[dict] = Field(
        default_factory=list
    )
