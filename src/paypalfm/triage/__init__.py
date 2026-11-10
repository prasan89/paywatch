from paypalfm.triage.typosquat import is_paypal_typosquat, typosquat_of
from paypalfm.triage.meta import score_metadata
from paypalfm.triage.content import score_content
from paypalfm.schema import TriageResult


def triage(name: str, version: str, pkg: dict, tarball: bytes | None = None) -> TriageResult:
    score = 0.0
    reasons: list[str] = []

    # Metadata signals
    meta_score, meta_reasons = score_metadata(name, version, pkg)
    score += meta_score
    reasons.extend(meta_reasons)

    # Content signals (static analysis of tarball)
    if tarball:
        content_score, content_reasons = score_content(tarball)
        score += content_score
        reasons.extend(content_reasons)

    return TriageResult(
        package=name,
        version=version,
        score=min(score, 1.0),
        reasons=reasons,
        send_to_model=score >= 0.3 or any("critical" in r for r in reasons),
    )
