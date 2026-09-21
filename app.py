"""Larivière Live — Portail Streamlit Public Sécurisé.

Strictly PUBLIC-SAFE:
- 100% public repository safe.
- Contains NO business algorithms, private datasets, or plain secrets.
- Requires USER + PASSWORD authentication (PBKDF2-HMAC-SHA256, 600k iterations).
- Dynamically loads and runs private LariviereAI code strictly AFTER authentication.
- Calls st.set_page_config() once safely at portal root.
- Suppresses Streamlit sidebar completely (discrete header session & logout).
"""

from __future__ import annotations

import streamlit as st

from auth import (
    hide_sidebar,
    is_auth_configured,
    is_authenticated,
    render_header_session,
    render_login_form,
)
from loader import load_and_run_lariviere


def main() -> None:
    # ---------------------------------------------------------
    # Single Initial Page Configuration
    # ---------------------------------------------------------
    st.set_page_config(
        page_title="Éditions Larivière · AI Partnership · ZCube",
        page_icon="◼",
        layout="centered",
        initial_sidebar_state="collapsed",
    )
    hide_sidebar()

    # ---------------------------------------------------------
    # GATE 1: Security Configuration Check (Fail-Closed)
    # ---------------------------------------------------------
    if not is_auth_configured():
        st.title("🔒 Portail Éditions Larivière — Non configuré")
        st.error(
            "Le portail ne peut pas démarrer en mode non sécurisé.\n\n"
            "Veuillez configurer `LIVE_USERNAME` et `LIVE_PASSWORD_HASH` dans les secrets du serveur."
        )
        st.stop()

    # ---------------------------------------------------------
    # GATE 2: User Authentication Gate
    # ---------------------------------------------------------
    if not is_authenticated():
        render_login_form()
        st.stop()

    # ---------------------------------------------------------
    # Authenticated Session: Header Session & Logout Controls
    # ---------------------------------------------------------
    render_header_session()

    # ---------------------------------------------------------
    # GATE 3: Secure Execution of Larivière AI Application
    # ---------------------------------------------------------
    try:
        load_and_run_lariviere()
    except Exception as exc:
        st.error(f"⚠️ Erreur lors du chargement de Larivière : {exc}")


if __name__ == "__main__":
    main()
