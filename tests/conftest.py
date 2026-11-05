"""Offline tooling tests cannot reach a deployed administrative endpoint."""
import socket
import urllib.request

import pytest


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch, request):
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def guarded(original):
        def connect(connection, address):
            if (request.node.get_closest_marker("local_http")
                    and isinstance(address, tuple)
                    and address[0] in {"127.0.0.1", "::1"}):
                return original(connection, address)
            raise AssertionError("Offline tooling tests cannot access the network")
        return connect

    def refuse(*args, **kwargs):
        raise AssertionError("Offline tooling tests cannot access the network")

    monkeypatch.setattr(socket.socket, "connect", guarded(original_connect))
    monkeypatch.setattr(socket.socket, "connect_ex", guarded(original_connect_ex))
    monkeypatch.setattr(urllib.request, "urlopen", refuse)
