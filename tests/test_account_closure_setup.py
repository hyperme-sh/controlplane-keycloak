"""Fail-closed inputs, default-off CLI and private provisioning transport."""

import importlib.util
import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("closure_setup", ROOT / "keycloak/account_closure.py")
setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup)


@pytest.mark.parametrize("reader,worker,other", [
    ("short", "w" * 64, ()), ("r" * 64, "short", ()),
    ("same" * 16, "same" * 16, ()), ("r" * 64, "w" * 64, ("r" * 64,)),
    ("r" * 64, "w" * 64, ("w" * 64,)), ("r" * 513, "w" * 64, ()),
    ("r" * 32 + "\n", "w" * 64, ()), ("é" * 64, "w" * 64, ()),
])
def test_invalid_credentials_cannot_contact_or_modify_a_provider(reader, worker, other):
    class NoProvider:
        def __getattr__(self, name):
            raise AssertionError("Invalid credentials contacted provider")

    with pytest.raises(setup.ClosureSetupError, match="credential"):
        setup.configure(NoProvider(), reader, worker, other_secrets=other)


def test_cli_defaults_to_a_reviewable_plan_without_authentication(monkeypatch, capsys):
    def unexpected(*args, **kwargs):
        raise AssertionError("Plan contacted provider")

    monkeypatch.setattr(setup.NativeAdmin, "login", unexpected)
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_READER_SECRET", "private-reader" * 4)
    subject = str(uuid.uuid4())
    assert setup.main(["--human-user-id", subject]) == 0
    output = capsys.readouterr().out
    assert "private-reader" not in output
    assert json.loads(output) == {
        "clients": [setup.READER, setup.WORKER], "enabled": False,
        "human_user_ids": [subject], "service_user_ids": [],
    }


def test_apply_rejects_reused_service_credentials_before_authentication(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("Invalid setup authenticated")

    monkeypatch.setattr(setup.NativeAdmin, "login", unexpected)
    monkeypatch.setenv("KEYCLOAK_INTERNAL_URL", "https://issuer.example.invalid")
    monkeypatch.setenv("KC_BOOTSTRAP_ADMIN_USERNAME", "provisioner")
    monkeypatch.setenv("KC_BOOTSTRAP_ADMIN_PASSWORD", "unrelated-bootstrap" * 4)
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_READER_SECRET", "r" * 64)
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET", "w" * 64)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 64)
    with pytest.raises(setup.ClosureSetupError, match="distinct"):
        setup.main(["--apply"])


@pytest.mark.parametrize("subject", ["person@example.invalid", "username", ".", "..", "apikey:" + str(uuid.UUID(int=1)), " "])
def test_operator_arguments_require_exact_native_user_ids(subject):
    with pytest.raises(setup.ClosureSetupError, match="exact native user UUID"):
        setup.main(["--human-user-id", subject])


@pytest.mark.parametrize("base", ["http://issuer.example.invalid", "https://user:secret@issuer.example.invalid", "https://issuer.example.invalid?token=private", "https://issuer.example.invalid#private"])
def test_provisioning_transport_rejects_unsafe_administrator_urls(base):
    with pytest.raises(setup.ClosureSetupError, match="Trusted HTTPS"):
        setup.NativeAdmin(base, "controlplane", "private-token")


def test_realm_declares_no_automatic_closure_operator_grants():
    realm = json.loads((ROOT / "keycloak/import/controlplane-realm.json").read_text())
    roles = [role for role in realm["roles"]["realm"] if role["name"] == setup.ROLE]
    assert len(roles) == 1 and roles[0]["composite"] is roles[0]["clientRole"] is False
    assert setup.ROLE not in realm.get("defaultRoles", [])
    for group in realm.get("groups", []):
        assert setup.ROLE not in group.get("realmRoles", [])
    for user in realm.get("users", []):
        assert setup.ROLE not in user.get("realmRoles", [])


@pytest.mark.local_http
def test_private_transport_refuses_redirects_proxies_malformed_and_oversize_bodies(monkeypatch):
    paths = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            paths.append(self.path)
            if self.path.endswith("/redirect"):
                self.send_response(307)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/sink")
                self.end_headers()
                return
            body = b'{}'
            if self.path.endswith("/malformed"):
                body = b'private-token provider failure is not JSON'
            elif self.path.endswith("/oversize"):
                body = b' ' * (2 * 1024 * 1024 + 16)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        running = threading.Thread(target=server.serve_forever, daemon=True)
        running.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            monkeypatch.setenv("http_proxy", base)
            monkeypatch.setenv("HTTP_PROXY", base)
            monkeypatch.setenv("no_proxy", "")
            monkeypatch.setenv("NO_PROXY", "")
            admin = setup.NativeAdmin(base, "controlplane", "private-token")
            assert admin.get("/plain") == {}
            for suffix in ("redirect", "malformed", "oversize"):
                with pytest.raises(setup.ClosureSetupError) as failure:
                    admin.get("/" + suffix)
                assert "private-token" not in str(failure.value)
            assert paths == ["/admin/realms/controlplane/" + suffix for suffix in ("plain", "redirect", "malformed", "oversize")]
        finally:
            server.shutdown()
            running.join(timeout=5)
