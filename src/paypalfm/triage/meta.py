"""Metadata-level triage signals."""
import time
from paypalfm.triage.typosquat import typosquat_of


def score_metadata(name: str, version: str, pkg: dict) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []

    # Typosquat
    match = typosquat_of(name)
    if match:
        score += 0.5
        reasons.append(f"critical:typosquat of {match}")

    # Brand-new publisher (first ever publish)
    if pkg.get("_npmUser") and not pkg.get("_npmOperationalInternal"):
        maintainers = pkg.get("maintainers", [])
        if len(maintainers) == 1:
            score += 0.2
            reasons.append("new-single-maintainer")

    # Install hooks present (preinstall / postinstall / install)
    scripts = pkg.get("scripts", {})
    hook_keys = {"preinstall", "install", "postinstall"}
    found_hooks = hook_keys & scripts.keys()
    if found_hooks:
        score += 0.3
        reasons.append(f"critical:install-hooks:{','.join(found_hooks)}")

    # Dependency on an unscoped package with a PayPal-sounding name
    for dep_name in list(pkg.get("dependencies", {}).keys()):
        if "paypal" in dep_name.lower() and not dep_name.startswith("@paypal"):
            score += 0.2
            reasons.append(f"suspicious-dep:{dep_name}")

    # Very recent creation (< 7 days)
    created = pkg.get("_time", {}).get("created", "") if isinstance(pkg.get("_time"), dict) else ""
    if created:
        try:
            import datetime
            age = (datetime.datetime.utcnow() - datetime.datetime.fromisoformat(created.replace("Z", ""))).days
            if age < 7:
                score += 0.15
                reasons.append(f"new-package-age:{age}d")
        except Exception:
            pass

    return score, reasons
