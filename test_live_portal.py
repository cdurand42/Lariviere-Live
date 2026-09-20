"""Targeted unit tests for Lariviere-Live public portal security & loader."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch
import pytest

from auth import (
    generate_password_hash,
    is_auth_configured,
    verify_credentials,
    verify_password_hash,
)
from loader import (
    _sanitize_message,
    fetch_private_app_archive,
    load_and_run_lariviere,
    resolve_private_app_path,
)


def test_generate_and_verify_password_hash():
    """Verify PBKDF2-HMAC-SHA256 format and verification."""
    password = "LariviereSecurePassword2026!"
    stored_hash = generate_password_hash(password, iterations=100_000)

    parts = stored_hash.split("$")
    assert len(parts) == 4
    assert parts[0] == "pbkdf2_sha256"
    assert parts[1] == "100000"
    assert len(parts[2]) == 32  # 16 bytes hex
    assert len(parts[3]) == 64  # sha256 hex

    assert verify_password_hash(password, stored_hash) is True
    assert verify_password_hash("WrongPassword", stored_hash) is False


def test_verify_credentials():
    """Verify username and password verification against PBKDF2 hash."""
    username = "admin"
    password = "CorrectHorseBatteryStaple"
    stored_hash = generate_password_hash(password, iterations=100_000)

    # Valid
    assert verify_credentials(
        input_username=username,
        input_password=password,
        expected_username=username,
        expected_password_hash=stored_hash,
    ) is True

    # Wrong password
    assert verify_credentials(
        input_username=username,
        input_password="IncorrectPassword",
        expected_username=username,
        expected_password_hash=stored_hash,
    ) is False

    # Wrong username
    assert verify_credentials(
        input_username="other_user",
        input_password=password,
        expected_username=username,
        expected_password_hash=stored_hash,
    ) is False


def test_verify_credentials_malformed_hash_fail_closed():
    """Malformed or invalid hash formats must fail closed."""
    username = "admin"
    password = "Password123"

    bad_hashes = [
        "",
        "plain_text_password",
        "pbkdf2_sha256$bad_iter$salt$hash",
        "pbkdf2_sha256$50000$salt$hash",  # iterations < 100k
        "md5$100000$salt$hash",
        "pbkdf2_sha256$100000$not_hex$hash",
    ]

    for bad in bad_hashes:
        assert verify_credentials(
            input_username=username,
            input_password=password,
            expected_username=username,
            expected_password_hash=bad,
        ) is False


def test_is_auth_configured_fail_closed(monkeypatch):
    """Missing auth config must fail closed."""
    monkeypatch.setenv("LIVE_USERNAME", "")
    monkeypatch.setenv("LIVE_PASSWORD_HASH", "")
    assert is_auth_configured() is False

    monkeypatch.setenv("LIVE_USERNAME", "admin")
    monkeypatch.setenv("LIVE_PASSWORD_HASH", "bad_hash")
    assert is_auth_configured() is False


def test_loader_unauthenticated_blocked():
    """Calling load_and_run_lariviere without authentication must raise PermissionError."""
    with patch("loader.is_authenticated", return_value=False):
        with pytest.raises(PermissionError, match="sans authentification"):
            load_and_run_lariviere()


def test_loader_never_puts_token_in_url():
    """Security Requirement: GITHUB_TOKEN is NEVER placed in URL, only in Authorization header."""
    secret_pat = "github_pat_SUPER_SECRET_VALUE_12345"
    captured_request = {}

    def mock_get(url, headers=None, timeout=None):
        captured_request["url"] = url
        captured_request["headers"] = headers
        mock_resp = MagicMock()
        mock_resp.status_code = 401  # Stop early after capturing request
        return mock_resp

    with patch("requests.get", side_effect=mock_get):
        with pytest.raises(RuntimeError, match="401"):
            fetch_private_app_archive(
                repo="cdurand42/lariviere-ai-demo",
                ref="feat/streamlit-auth-gateway",
                token=secret_pat,
                target_dir="/tmp/test_dir",
            )

    # 1. Secret token must NOT appear anywhere in the request URL
    assert secret_pat not in captured_request["url"]
    # 2. Secret token must be passed in the Authorization Bearer header
    assert captured_request["headers"]["Authorization"] == f"Bearer {secret_pat}"


def test_sanitize_message_strips_token():
    """Exception and log sanitizer must replace sensitive tokens."""
    token = "github_pat_11AAAAA22BBBBB"
    msg = f"Failed to connect using token {token} to remote host."
    sanitized = _sanitize_message(msg, token)

    assert token not in sanitized
    assert "***TOKEN***" in sanitized


def test_resolve_local_sibling():
    """Local path resolution successfully finds local LariviereAI directory."""
    resolved = resolve_private_app_path()
    assert os.path.exists(resolved)
    assert os.path.exists(os.path.join(resolved, "app.py"))
