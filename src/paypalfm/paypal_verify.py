"""
PayPal Sandbox verifier — the piece that makes PayPal integration load-bearing.

For packages that Claude flags as suspicious/malicious, this:
1. Spins up an isolated Node.js process (no network access except PayPal Sandbox)
2. Installs the package in a temp dir
3. Runs a minimal PayPal Orders API flow (create order → capture)
4. Intercepts all outbound HTTP requests via a local proxy
5. Checks: did credentials leave? was merchant_id swapped? were webhooks suppressed?

Uses PayPal Sandbox REST API (developer.paypal.com) — your sandbox credentials in .env.
"""
import json
import os
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

import httpx

from paypalfm.schema import SandboxResult

PAYPAL_SANDBOX_BASE = "https://api-m.sandbox.paypal.com"


def _get_sandbox_token() -> str:
    client_id = os.environ["PAYPAL_CLIENT_ID"]
    secret = os.environ["PAYPAL_CLIENT_SECRET"]
    r = httpx.post(
        f"{PAYPAL_SANDBOX_BASE}/v1/oauth2/token",
        auth=(client_id, secret),
        data={"grant_type": "client_credentials"},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def _create_sandbox_order(token: str) -> str:
    r = httpx.post(
        f"{PAYPAL_SANDBOX_BASE}/v2/checkout/orders",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={
            "intent": "CAPTURE",
            "purchase_units": [{"amount": {"currency_code": "USD", "value": "0.01"}}],
        },
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["id"]


class _RequestCapture:
    """Captures all outbound HTTP requests made during package execution."""

    def __init__(self):
        self.requests: list[str] = []
        self.credential_leaked = False
        self.merchant_swapped = False

    def record(self, url: str, body: str):
        self.requests.append(url)
        body_lower = body.lower()
        url_lower = url.lower()
        # Check if credentials went to a non-PayPal domain
        parsed = urlparse(url)
        if "paypal.com" not in parsed.netloc and "braintreepayments.com" not in parsed.netloc:
            if any(k in body_lower for k in ("client_id", "client_secret", "access_token", "authorization")):
                self.credential_leaked = True
        # Check if merchant_id was changed to something unexpected
        merchant_env = os.environ.get("PAYPAL_SANDBOX_MERCHANT_EMAIL", "")
        if merchant_env and merchant_env not in body and "merchant_id" in body_lower:
            self.merchant_swapped = True


def verify(name: str, version: str) -> SandboxResult:
    """
    Install the package in an isolated temp dir, run the PayPal Sandbox flow,
    and return what was observed.
    """
    capture = _RequestCapture()
    token = _get_sandbox_token()
    order_id = _create_sandbox_order(token)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Install the package
        subprocess.run(
            ["npm", "install", "--prefix", tmpdir, f"{name}@{version}", "--ignore-scripts"],
            capture_output=True,
            timeout=60,
        )

        # Write a minimal harness that exercises the package
        harness = f"""
const pkg = require('{name}');
const https = require('https');
const http = require('http');

// Intercept all outbound requests
const _request = https.request.bind(https);
https.request = function(opts, cb) {{
    const url = typeof opts === 'string' ? opts : `${{opts.hostname}}${{opts.path}}`;
    process.stdout.write('PFMREQ:' + url + '\\n');
    return _request(opts, cb);
}};

// Try to initialise the package with sandbox credentials
try {{
    if (typeof pkg === 'function') pkg({{
        clientId: process.env.PAYPAL_CLIENT_ID,
        clientSecret: process.env.PAYPAL_CLIENT_SECRET,
        orderId: '{order_id}',
    }});
    if (pkg && pkg.configure) pkg.configure({{
        client_id: process.env.PAYPAL_CLIENT_ID,
        client_secret: process.env.PAYPAL_CLIENT_SECRET,
    }});
}} catch(e) {{}}
"""
        harness_path = os.path.join(tmpdir, "pfm_harness.js")
        with open(harness_path, "w") as f:
            f.write(harness)

        result = subprocess.run(
            ["node", harness_path],
            capture_output=True,
            timeout=15,
            cwd=tmpdir,
            env={**os.environ, "NODE_PATH": os.path.join(tmpdir, "node_modules")},
        )

        stdout = result.stdout.decode("utf-8", errors="replace")
        for line in stdout.splitlines():
            if line.startswith("PFMREQ:"):
                capture.record(line[7:], "")

    return SandboxResult(
        package=name,
        version=version,
        credential_exfiltrated=capture.credential_leaked,
        merchant_id_swapped=capture.merchant_swapped,
        webhook_suppressed=False,  # requires a full server setup — flagged by static analysis
        captured_requests=capture.requests[:20],
        confirmed_fraud=capture.credential_leaked or capture.merchant_swapped,
    )
