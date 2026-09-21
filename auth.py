"""Authentication and session management for Lariviere-Live portal.

Implements a fail-closed, secure authentication gate:
- Username + password verification.
- Passwords verified strictly via PBKDF2-HMAC-SHA256 (salted & iterated).
- Constant-time comparison (hmac.compare_digest) to prevent timing attacks.
- Session managed via st.session_state.
- Fail-closed: halts if configuration is absent or hash is malformed.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import os
import secrets
from typing import Optional
import streamlit as st

DEFAULT_ITERATIONS = 600_000
HASH_ALGORITHM = "pbkdf2_sha256"


def get_config(key: str, default: str = "") -> str:
    """Retrieve configuration from st.secrets first, falling back to environment variables."""
    try:
        if hasattr(st, "secrets") and key in st.secrets:
            val = st.secrets[key]
            if val is not None and str(val).strip():
                return str(val).strip()
    except Exception:
        pass
    env_val = os.getenv(key, default)
    return env_val.strip() if env_val else default


def generate_password_hash(password: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    """Derive a secure, salted PBKDF2-HMAC-SHA256 hash formatted for storage.

    Format: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    salt_bytes = secrets.token_bytes(16)
    salt_hex = salt_bytes.hex()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations)
    return f"{HASH_ALGORITHM}${iterations}${salt_hex}${dk.hex()}"


def verify_password_hash(password: str, stored_hash: str) -> bool:
    """Verify password against a stored PBKDF2-HMAC-SHA256 hash.

    Fail-closed: returns False if format is invalid, iterations < 100k, or values missing.
    """
    if not password or not stored_hash:
        return False

    parts = stored_hash.strip().split("$")
    if len(parts) != 4:
        return False

    algo, iter_str, salt_hex, expected_hex = parts
    if algo != HASH_ALGORITHM:
        return False

    try:
        iterations = int(iter_str)
        if iterations < 100_000:
            return False
        salt_bytes = bytes.fromhex(salt_hex)
    except (ValueError, TypeError):
        return False

    try:
        computed_dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations)
        return hmac.compare_digest(computed_dk.hex().lower(), expected_hex.lower())
    except Exception:
        return False


def verify_credentials(
    input_username: str,
    input_password: str,
    expected_username: str,
    expected_password_hash: str,
) -> bool:
    """Safely verify username and password against PBKDF2-HMAC-SHA256 hash."""
    if not input_username or not input_password or not expected_username or not expected_password_hash:
        return False

    user_match = hmac.compare_digest(
        input_username.strip().encode("utf-8"),
        expected_username.strip().encode("utf-8"),
    )
    if not user_match:
        return False

    return verify_password_hash(input_password, expected_password_hash)


def is_auth_configured() -> bool:
    """Check whether necessary authentication configuration is present and valid."""
    username = get_config("LIVE_USERNAME")
    pwd_hash = get_config("LIVE_PASSWORD_HASH")
    if not username or not pwd_hash:
        return False
    parts = pwd_hash.strip().split("$")
    return len(parts) == 4 and parts[0] == HASH_ALGORITHM


def is_authenticated() -> bool:
    """Return True if the current Streamlit session is authenticated."""
    return bool(st.session_state.get("authenticated", False))


def login(username: str, password: str) -> tuple[bool, Optional[str]]:
    """Attempt login against configured credentials."""
    expected_username = get_config("LIVE_USERNAME")
    expected_hash = get_config("LIVE_PASSWORD_HASH")

    if not expected_username or not expected_hash:
        return False, "Configuration d'accès manquante sur le serveur."

    if verify_credentials(
        username,
        password,
        expected_username=expected_username,
        expected_password_hash=expected_hash,
    ):
        st.session_state["authenticated"] = True
        st.session_state["username"] = username.strip()
        return True, None
    return False, "Identifiant ou mot de passe incorrect."


def logout() -> None:
    """Clear session authentication state and cached application keys."""
    st.session_state["authenticated"] = False
    st.session_state.pop("username", None)
    # Clear session keys to reset private application flow
    for key in list(st.session_state.keys()):
        if key not in ("authenticated", "username"):
            st.session_state.pop(key, None)


def render_login_form() -> None:
    """Render the login card and handle form submission."""
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown(
            """
            <div style="text-align: center; margin-top: 2rem; margin-bottom: 1.5rem;">
                <h2 style="color: #091d3b; margin-bottom: 0.3rem;">Éditions Larivière</h2>
                <p style="color: #52627a; font-size: 0.95rem;">Portail Live · Accès restreint</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        with st.form("login_form", clear_on_submit=False):
            username_input = st.text_input("Identifiant", key="login_username_input").strip()
            password_input = st.text_input("Mot de passe", type="password", key="login_password_input")
            submitted = st.form_submit_button("Connexion", use_container_width=True)

            if submitted:
                if not username_input or not password_input:
                    st.error("Veuillez renseigner un identifiant et un mot de passe.")
                else:
                    success, err_msg = login(username_input, password_input)
                    if success:
                        st.success("Connexion réussie.")
                        st.rerun()
                    else:
                        st.error(err_msg or "Identifiants invalides.")


def hide_sidebar() -> None:
    """Inject CSS to completely suppress Streamlit sidebar and its toggle button."""
    st.markdown(
        """
        <style>
            [data-testid="stSidebar"],
            [data-testid="collapsedControl"],
            [data-testid="stSidebarCollapseButton"],
            [data-testid="stSidebarNav"],
            section[data-testid="stSidebar"] {
                display: none !important;
                visibility: hidden !important;
                width: 0 !important;
                height: 0 !important;
                margin: 0 !important;
                padding: 0 !important;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_header_session() -> None:
    """Render visible session status and logout button in the top page header."""
    hide_sidebar()
    st.markdown(
        """
        <style>
            /* Ensure main container has sufficient top padding to clear Streamlit header toolbar */
            [data-testid="stMainBlockContainer"] {
                padding-top: 4.5rem !important;
            }
            .st-key-btn_logout button {
                border-radius: 8px !important;
                font-weight: 600 !important;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )
    c_info, c_btn = st.columns([4.5, 1.5])
    with c_info:
        current_user = html.escape(str(st.session_state.get("username", "Utilisateur")))
        st.markdown(
            f"""
            <div style="display: flex; align-items: center; height: 38px; color: #475569; font-size: 0.88rem;">
                <span style="display: inline-block; width: 8px; height: 8px; background-color: #10b981; border-radius: 50%; margin-right: 8px;"></span>
                <span>Session active : <strong style="color: #0f172a;">{current_user}</strong></span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c_btn:
        if st.button("Déconnexion", key="btn_logout", help="Se déconnecter du portail", use_container_width=True):
            logout()
            st.rerun()


# Alias for backward compatibility
render_sidebar_session = render_header_session


if __name__ == "__main__":
    import getpass
    print("Générateur d'empreinte PBKDF2-HMAC-SHA256 pour LIVE_PASSWORD_HASH")
    raw_pwd = getpass.getpass("Saisir le mot de passe : ")
    if raw_pwd:
        generated = generate_password_hash(raw_pwd)
        print(f"\nLIVE_PASSWORD_HASH = \"{generated}\"\n")
