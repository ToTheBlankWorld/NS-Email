"""Shared fixtures for backend tests."""

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture(name="client")
def client_fixture() -> TestClient:
    return TestClient(create_app())
