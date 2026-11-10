"""
Static content analysis of a package tarball.
Never executes code — reads file contents in memory only.
Looks for PayPal-specific fraud patterns:
  - credential exfiltration (client_id / secret sent over network)
  - merchant ID / account swap
  - webhook handler suppression
  - obfuscated strings containing PayPal endpoints
"""
import io
import re
import tarfile
import gzip

# Patterns that indicate credential capture + exfiltration
_CRED_CAPTURE = re.compile(
    r"(fetch|axios|http\.request|XMLHttpRequest|request\().{0,300}"
    r"(client[_-]?id|client[_-]?secret|access[_-]?token)"
    r"|(client[_-]?id|client[_-]?secret|access[_-]?token).{0,300}"
    r"(fetch|axios|http\.request|XMLHttpRequest|request\()",
    re.IGNORECASE | re.DOTALL,
)

# Patterns that indicate merchant ID being replaced
_MERCHANT_SWAP = re.compile(
    r"merchant[_-]?id\s*[=:]\s*['\"][A-Z0-9]{10,}['\"]",
    re.IGNORECASE,
)

# Patterns that indicate webhook payload being suppressed or modified
_WEBHOOK_SUPPRESS = re.compile(
    r"(res\.send|res\.json|response\.send)\s*\(\s*\{\s*\}\s*\)"
    r"|event_type.{0,60}(PAYMENT|ORDER|CAPTURE).{0,60}return",
    re.IGNORECASE | re.DOTALL,
)

# Obfuscated exfil: base64-encoded or hex-encoded URLs
_OBFUSCATED_EXFIL = re.compile(
    r"(atob|Buffer\.from|fromCharCode).{0,200}(paypal|braintree|venmo)",
    re.IGNORECASE | re.DOTALL,
)

# Unofficial PayPal-like domains (likely exfil targets)
_FAKE_PAYPAL_DOMAIN = re.compile(
    r"https?://[a-z0-9.-]*(paypa1|paypai|pay-pal|paypalcdn|paypaljs)[a-z0-9.-]*/",
    re.IGNORECASE,
)


def _read_tarball(data: bytes) -> dict[str, str]:
    """Returns {filepath: content} for all JS/JSON files in the tarball."""
    files = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                if not member.name.endswith((".js", ".mjs", ".cjs", ".json", ".ts")):
                    continue
                if member.size > 500_000:
                    continue
                f = tf.extractfile(member)
                if f:
                    try:
                        files[member.name] = f.read().decode("utf-8", errors="replace")
                    except Exception:
                        pass
    except Exception:
        pass
    return files


def score_content(tarball: bytes) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []
    files = _read_tarball(tarball)

    for path, content in files.items():
        if _CRED_CAPTURE.search(content):
            score += 0.4
            reasons.append(f"critical:credential-capture-exfil:{path}")

        if _MERCHANT_SWAP.search(content):
            score += 0.35
            reasons.append(f"critical:merchant-id-hardcoded:{path}")

        if _WEBHOOK_SUPPRESS.search(content):
            score += 0.3
            reasons.append(f"suspicious:webhook-suppression:{path}")

        if _OBFUSCATED_EXFIL.search(content):
            score += 0.35
            reasons.append(f"critical:obfuscated-exfil:{path}")

        if _FAKE_PAYPAL_DOMAIN.search(content):
            score += 0.5
            reasons.append(f"critical:fake-paypal-domain:{path}")

    return min(score, 1.0), reasons
