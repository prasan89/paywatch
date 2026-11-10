from pydantic import BaseModel, Field
from typing import Literal


class CitedLine(BaseModel):
    ref: int
    file: str
    line: str


class Verdict(BaseModel):
    package: str
    version: str
    malicious: bool
    confidence: float = Field(ge=0.0, le=1.0)
    label: Literal["clean", "suspicious", "malicious"]
    cited_lines: list[CitedLine] = []
    summary: str
    persuasion_detected: bool = False  # package text tried to argue it's safe


class TriageResult(BaseModel):
    package: str
    version: str
    score: float
    reasons: list[str]
    send_to_model: bool


class SandboxResult(BaseModel):
    package: str
    version: str
    credential_exfiltrated: bool
    merchant_id_swapped: bool
    webhook_suppressed: bool
    captured_requests: list[str] = []
    confirmed_fraud: bool
