"""Actual HTTPS transport tests against a private loopback server only."""

import base64
import json
import shutil
import ssl
import subprocess
import threading
import time
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from ingestion.dns.adapters.adguard import AdGuardAdapter, AdGuardAPIError
from ingestion.dns.config import AdGuardConfig


@pytest.fixture(scope="module")
def certificate(tmp_path_factory):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is required for local HTTPS integration tests.")
    folder = tmp_path_factory.mktemp("dns-https-cert")
    cert, key = folder / "cert.pem", folder / "key.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ],
        check=True,
        capture_output=True,
        timeout=15,
    )
    return cert, key


@pytest.fixture
def https(certificate):
    cert, key = certificate
    state = {"requests": [], "status": 200, "delay": 0}
    expected = "Basic " + base64.b64encode(b"fixture-user:fixture-password").decode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["requests"].append((self.path, self.headers.get("Authorization")))
            time.sleep(state["delay"])
            status = state["status"]
            if self.headers.get("Authorization") != expected:
                status = 401
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            if status == 302:
                self.send_header("Location", "https://must-not-contact.invalid/")
            self.end_headers()
            payload = {
                "data": [
                    {
                        "time": "2026-10-21T12:00:00.123456789Z",
                        "client": "192.0.2.1",
                        "question": {"name": "example.net", "type": "A"},
                    }
                ],
                "oldest": "2026-10-21T12:00:00.123456789Z",
            }
            try:
                self.wfile.write(json.dumps(payload).encode())
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                # The timeout test deliberately disconnects before the write.
                return

        def log_message(self, format, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    config = AdGuardConfig(
        f"https://localhost:{server.server_port}",
        "fixture-user",
        "fixture-password",
        ca_bundle=str(cert),
    )
    try:
        yield config, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_verified_https_basic_auth_and_query_parameters(https, monkeypatch):
    config, state = https
    # Ambient proxies must not affect the explicit connection configuration.
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    with AdGuardAdapter(config) as adapter:
        page = adapter.fetch_page(limit=1, older_than="2026-10-21T13:00:00Z", offset=2)
    assert len(page.events) == 1
    path, authorization = state["requests"][0]
    assert authorization.startswith("Basic ")
    assert urlsplit(path).path == "/control/querylog"
    assert parse_qs(urlsplit(path).query) == {
        "limit": ["1"],
        "older_than": ["2026-10-21T13:00:00Z"],
        "offset": ["2"],
    }


def test_untrusted_certificate_rejected_before_authentication(https):
    config, state = https
    with (
        AdGuardAdapter(replace(config, ca_bundle=None)) as adapter,
        pytest.raises(AdGuardAPIError, match="TLS verification"),
    ):
        adapter.fetch_page(limit=1)
    assert state["requests"] == []


def test_wrong_server_name_rejected_before_authentication(https):
    config, state = https
    config = replace(config, base_url=config.base_url.replace("localhost", "127.0.0.1"))
    with (
        AdGuardAdapter(config) as adapter,
        pytest.raises(AdGuardAPIError, match="TLS verification"),
    ):
        adapter.fetch_page(limit=1)
    assert state["requests"] == []


def test_actual_authentication_error_is_safe(https):
    config, state = https
    with (
        AdGuardAdapter(replace(config, password="wrong-fixture-secret")) as adapter,
        pytest.raises(AdGuardAPIError) as error,
    ):
        adapter.fetch_page(limit=1)
    assert len(state["requests"]) == 1
    assert "wrong-fixture-secret" not in str(error.value)


def test_https_redirect_is_not_followed(https):
    config, state = https
    state["status"] = 302
    with (
        AdGuardAdapter(config) as adapter,
        pytest.raises(AdGuardAPIError, match="HTTP 302"),
    ):
        adapter.fetch_page(limit=1)
    assert len(state["requests"]) == 1


def test_actual_socket_read_timeout(https):
    config, state = https
    state["delay"] = 0.2
    with (
        AdGuardAdapter(replace(config, read_timeout=0.02)) as adapter,
        pytest.raises(AdGuardAPIError, match="timed out"),
    ):
        adapter.fetch_page(limit=1)
