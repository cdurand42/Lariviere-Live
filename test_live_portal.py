"""Targeted unit tests for Lariviere-Live public portal security & loader."""

import io
import os
import sys
import tarfile
import time
from unittest.mock import MagicMock, patch
import pytest

from auth import (
    generate_password_hash,
    hide_sidebar,
    is_auth_configured,
    logout,
    render_header_session,
    verify_credentials,
    verify_password_hash,
)
from loader import (
    _REMOTE_SHA_CACHE,
    _sanitize_message,
    cleanup_residual_cache_dirs,
    fetch_private_app_archive,
    get_local_commit_sha,
    get_remote_commit_sha,
    invalidate_cached_modules,
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
    with patch("auth.st.secrets", {}):
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


def test_hide_sidebar_suppresses_sidebar_elements():
    """hide_sidebar must inject CSS to hide stSidebar, collapsedControl, and nav."""
    mock_st = MagicMock()
    with patch("auth.st", mock_st):
        hide_sidebar()
        mock_st.markdown.assert_called_once()
        css_payload = mock_st.markdown.call_args[0][0]
        assert '[data-testid="stSidebar"]' in css_payload
        assert '[data-testid="collapsedControl"]' in css_payload
        assert "display: none !important" in css_payload


def test_render_header_session_renders_without_sidebar():
    """render_header_session must render in header columns and NEVER access st.sidebar."""
    mock_st = MagicMock()
    col1, col2 = MagicMock(), MagicMock()
    mock_st.columns.return_value = (col1, col2)
    mock_st.session_state = {"authenticated": True, "username": "admin_user"}
    mock_st.button.return_value = False

    with patch("auth.st", mock_st):
        render_header_session()

        # st.sidebar must NEVER be used
        mock_st.sidebar.assert_not_called()
        # st.columns must be used for layout
        mock_st.columns.assert_called_once()
        # st.button for logout must be present
        mock_st.button.assert_called_once()
        args, kwargs = mock_st.button.call_args
        assert "Déconnexion" in args or kwargs.get("key") == "btn_logout"

        # Ensure container top padding CSS is injected to clear header toolbar
        markdown_calls = [c[0][0] for c in mock_st.markdown.call_args_list if c[0]]
        css_calls = [c for c in markdown_calls if '[data-testid="stMainBlockContainer"]' in c]
        assert len(css_calls) >= 1
        assert "padding-top" in css_calls[0]


def test_logout_resets_session_state():
    """logout must reset authentication and clear session keys."""
    mock_st = MagicMock()
    session_dict = {
        "authenticated": True,
        "username": "admin_user",
        "private_app_data": {"brief": "123"},
    }
    mock_st.session_state = session_dict
    with patch("auth.st", mock_st):
        logout()
        assert session_dict["authenticated"] is False
        assert "username" not in session_dict
        assert "private_app_data" not in session_dict


def _create_tarball(files: dict[str, str], prefix: str = "lariviere-ai-demo-abc1234/") -> bytes:
    """Helper to synthesize in-memory tar.gz archives matching GitHub's format."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel_path, content in files.items():
            data = content.encode("utf-8")
            ti = tarfile.TarInfo(name=f"{prefix}{rel_path}")
            ti.size = len(data)
            ti.mtime = int(time.time())
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def test_get_remote_commit_sha_and_ttl_caching():
    """Verify get_remote_commit_sha fetches SHA and reuses in-memory cache within TTL."""
    _REMOTE_SHA_CACHE.clear()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"sha": "sha_remote_111222333"}

    with patch("requests.get", return_value=mock_resp) as mock_get:
        sha1 = get_remote_commit_sha("test-repo", "feat-branch", "secret-token", ttl=60)
        assert sha1 == "sha_remote_111222333"
        assert mock_get.call_count == 1

        # Second call within TTL should return cached SHA without making network request
        sha2 = get_remote_commit_sha("test-repo", "feat-branch", "secret-token", ttl=60)
        assert sha2 == "sha_remote_111222333"
        assert mock_get.call_count == 1

        # Third call with ttl=0 should bypass cache and fetch again
        sha3 = get_remote_commit_sha("test-repo", "feat-branch", "secret-token", ttl=0)
        assert sha3 == "sha_remote_111222333"
        assert mock_get.call_count == 2


def test_get_remote_commit_sha_never_leaks_token():
    """get_remote_commit_sha must sanitize token in error messages."""
    _REMOTE_SHA_CACHE.clear()
    token = "ghp_VERY_SECRET_PAT_987654321"

    with patch("requests.get", side_effect=Exception(f"Connection failed: https://{token}@github.com")):
        with pytest.raises(RuntimeError) as exc_info:
            get_remote_commit_sha("repo", "ref", token)

        err_msg = str(exc_info.value)
        assert token not in err_msg
        assert "***TOKEN***" in err_msg


def test_get_local_commit_sha(tmp_path):
    """get_local_commit_sha reads .commit_sha file correctly or returns empty string."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    # Empty/missing file
    assert get_local_commit_sha(str(cache_dir)) == ""

    # Written file
    (cache_dir / ".commit_sha").write_text("  commit_sha_abc123  \n", encoding="utf-8")
    assert get_local_commit_sha(str(cache_dir)) == "commit_sha_abc123"


def test_cleanup_residual_cache_dirs(tmp_path):
    """cleanup_residual_cache_dirs cleans only temporary and old directories."""
    target_dir = tmp_path / "_lariviere_app"
    target_dir.mkdir()
    tmp1 = tmp_path / "_lariviere_app_tmp_1a2b"
    tmp1.mkdir()
    old1 = tmp_path / "_lariviere_app_old_3c4d"
    old1.mkdir()
    unrelated = tmp_path / "other_app_dir"
    unrelated.mkdir()

    cleanup_residual_cache_dirs(str(target_dir))

    assert target_dir.exists()
    assert unrelated.exists()
    assert not tmp1.exists()
    assert not old1.exists()


def test_fetch_private_app_archive_atomic_swap_and_sha(tmp_path):
    """fetch_private_app_archive extracts tarball atomically and records .commit_sha."""
    target_dir = tmp_path / "_lariviere_app"
    tarball_bytes = _create_tarball({
        "app.py": "def main():\n    return 'hello from lariviere'\n",
        "submodule/__init__.py": "# submodule\n",
    })

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = tarball_bytes

    with patch("requests.get", return_value=mock_resp):
        res_path = fetch_private_app_archive(
            repo="repo",
            ref="ref",
            token="pat_token",
            target_dir=str(target_dir),
            commit_sha="remote_sha_45678",
        )

    assert os.path.abspath(res_path) == str(target_dir)
    assert (target_dir / "app.py").is_file()
    assert (target_dir / "submodule" / "__init__.py").is_file()
    assert (target_dir / ".commit_sha").read_text(encoding="utf-8") == "remote_sha_45678"

    # Verify no residual directories remain in tmp_path
    remaining = [p.name for p in tmp_path.iterdir()]
    assert remaining == ["_lariviere_app"]


def test_fetch_private_app_archive_rollback_on_corrupt_archive(tmp_path):
    """If extraction or validation fails, previous target directory is preserved."""
    target_dir = tmp_path / "_lariviere_app"
    target_dir.mkdir()
    (target_dir / "app.py").write_text("def main(): return 'original'", encoding="utf-8")
    (target_dir / ".commit_sha").write_text("original_sha_123", encoding="utf-8")

    # Corrupt archive missing app.py
    corrupt_tar = _create_tarball({"README.md": "# No app.py here"})

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = corrupt_tar

    with patch("requests.get", return_value=mock_resp):
        with pytest.raises(RuntimeError, match="app.py manquant"):
            fetch_private_app_archive(
                repo="repo",
                ref="ref",
                token="pat_token",
                target_dir=str(target_dir),
                commit_sha="corrupted_new_sha",
            )

    # Rollback verification: target_dir remains with original code
    assert target_dir.exists()
    assert "original" in (target_dir / "app.py").read_text(encoding="utf-8")
    assert (target_dir / ".commit_sha").read_text(encoding="utf-8") == "original_sha_123"


def test_resolve_private_app_path_reuses_matching_sha(tmp_path):
    """resolve_private_app_path reuses cache when SHA matches and downloads when SHA changes."""
    cache_dir = tmp_path / "_lariviere_app"
    cache_dir.mkdir()
    (cache_dir / "app.py").write_text("def main(): pass", encoding="utf-8")
    (cache_dir / ".commit_sha").write_text("sha_match_000", encoding="utf-8")

    # Force resolve_private_app_path to use our test cache_dir and mock credentials
    with patch("loader.RUNTIME_CACHE_DIR", str(cache_dir)), \
         patch("loader.get_config", side_effect=lambda k, d="": {
             "GITHUB_REPO": "test-repo",
             "GITHUB_REF": "main",
             "GITHUB_TOKEN": "token_123",
             "LARIVIERE_LOCAL_PATH": "",
         }.get(k, d)), \
         patch("loader.os.path.isdir", side_effect=lambda p: False if "LariviereAI" in p else os.path.isdir(p)), \
         patch("loader.fetch_private_app_archive") as mock_fetch:

        # 1. Matching SHA: do NOT download
        with patch("loader.get_remote_commit_sha", return_value="sha_match_000"):
            path = resolve_private_app_path()
            assert path == str(cache_dir)
            mock_fetch.assert_not_called()

        # 2. Changed SHA: download new version
        with patch("loader.get_remote_commit_sha", return_value="sha_new_111"), \
             patch("loader.invalidate_cached_modules") as mock_invalidate:
            mock_fetch.return_value = str(cache_dir)
            path = resolve_private_app_path()
            assert path == str(cache_dir)
            mock_fetch.assert_called_once_with(
                repo="test-repo",
                ref="main",
                token="token_123",
                target_dir=str(cache_dir),
                commit_sha="sha_new_111",
            )
            mock_invalidate.assert_called_once_with(str(cache_dir))


def test_invalidate_cached_modules_targeted(tmp_path):
    """invalidate_cached_modules purges target_dir modules but NEVER third-party packages."""
    target_dir = str(tmp_path / "_lariviere_app")
    os.makedirs(target_dir, exist_ok=True)

    file_inside = os.path.join(target_dir, "feature.py")
    mod_inside = MagicMock(__file__=file_inside)
    app_mod = MagicMock(__file__=os.path.join(target_dir, "app.py"))
    streamlit_mod = MagicMock(__file__="C:/Python/lib/site-packages/streamlit/__init__.py")
    requests_mod = MagicMock(__file__="C:/Python/lib/site-packages/requests/__init__.py")
    auth_mod = MagicMock(__file__="D:/Lariviere-Live/auth.py")

    sys.modules["cached_feature"] = mod_inside
    sys.modules["app"] = app_mod
    sys.modules["streamlit"] = streamlit_mod
    sys.modules["requests"] = requests_mod
    sys.modules["auth"] = auth_mod

    try:
        purged = invalidate_cached_modules(target_dir)

        assert "cached_feature" in purged
        assert "app" in purged
        assert "cached_feature" not in sys.modules
        assert "app" not in sys.modules

        # Protected modules must remain
        assert "streamlit" in sys.modules
        assert "requests" in sys.modules
        assert "auth" in sys.modules
    finally:
        sys.modules.pop("cached_feature", None)


