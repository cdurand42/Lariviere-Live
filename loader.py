"""Secure loader for LariviereAI private repository.

Guarantees:
- GITHUB_TOKEN is NEVER put in URLs, git CLI commands, or logs.
- GitHub REST API tarball endpoint used exclusively with in-memory Bearer token.
- Local extraction cached in container filesystem to prevent redownload on each rerun.
- Safe tarball extraction (path traversal mitigation).
- Local dev directory fallback for offline and local testing.
- Entrypoint execution via main() or run().
"""

from __future__ import annotations

import importlib
import io
import logging
import os
import sys
import tarfile
from typing import Any
import requests

from auth import get_config, is_authenticated

LOGGER = logging.getLogger(__name__)

DEFAULT_REPO = "cdurand42/lariviere-ai-demo"
DEFAULT_REF = "feat/streamlit-auth-gateway"
RUNTIME_CACHE_DIR = "_lariviere_app"


def _sanitize_message(message: str, token: str) -> str:
    """Strip token occurrences from error strings or logs."""
    if token and token in message:
        return message.replace(token, "***TOKEN***")
    return message


def fetch_private_app_archive(
    repo: str,
    ref: str,
    token: str,
    target_dir: str,
    timeout: int = 30,
) -> str:
    """Download and extract private repository tarball via GitHub REST API.

    Security:
    - Token is passed strictly in the Authorization header.
    - Token is NEVER put in the URL or command line.
    """
    if not token:
        raise RuntimeError("Jeton GITHUB_TOKEN manquant pour l'accès au dépôt privé.")
    if not repo:
        raise RuntimeError("Nom du dépôt GITHUB_REPO manquant.")

    api_url = f"https://api.github.com/repos/{repo.strip()}/tarball/{ref.strip()}"
    headers = {
        "Authorization": f"Bearer {token.strip()}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "LariviereLive-SecureGateway",
    }

    try:
        resp = requests.get(api_url, headers=headers, timeout=timeout)
    except Exception as exc:
        clean_msg = _sanitize_message(str(exc), token)
        raise RuntimeError(f"Erreur réseau lors de la communication avec GitHub : {clean_msg}") from None

    if resp.status_code == 401:
        raise RuntimeError("Accès non autorisé (401) : GITHUB_TOKEN invalide ou expiré.")
    if resp.status_code == 403:
        raise RuntimeError(
            "Accès refusé (403) : le PAT GitHub doit avoir la permission 'Contents: Read-only' sur le dépôt."
        )
    if resp.status_code == 404:
        raise RuntimeError(f"Dépôt ou référence GitHub introuvable (404) : {repo}@{ref}.")
    if resp.status_code != 200:
        raise RuntimeError(f"Erreur GitHub API (HTTP {resp.status_code}).")

    os.makedirs(target_dir, exist_ok=True)

    try:
        with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:gz") as tar:
            # GitHub tarballs prefix files with '{owner}-{repo}-{sha}/'
            members = tar.getmembers()
            if not members:
                raise RuntimeError("Archive GitHub vide.")

            prefix = members[0].name.split("/")[0] + "/"

            for member in members:
                if not member.name.startswith(prefix):
                    continue
                rel_path = member.name[len(prefix):]
                if not rel_path or rel_path.startswith("/") or ".." in rel_path.split("/"):
                    continue

                dest_path = os.path.join(target_dir, rel_path)
                if member.isdir():
                    os.makedirs(dest_path, exist_ok=True)
                elif member.isfile():
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    with open(dest_path, "wb") as f_out:
                        f_in = tar.extractfile(member)
                        if f_in is not None:
                            f_out.write(f_in.read())
    except Exception as exc:
        raise RuntimeError(f"Erreur lors de l'extraction de l'archive GitHub : {exc}") from None

    return target_dir


def resolve_private_app_path() -> str:
    """Determine the path to the private LariviereAI code.

    Priority:
    1. Explicit local path override (LARIVIERE_LOCAL_PATH).
    2. Local sibling directory (D:/LariviereAI or ../LariviereAI) if valid.
    3. Cached in-container extraction (_lariviere_app/).
    4. Download from GitHub REST API via fine-grained PAT.
    """
    # 1. Local environment or explicit config
    local_override = get_config("LARIVIERE_LOCAL_PATH")
    if local_override and os.path.isdir(local_override) and os.path.exists(os.path.join(local_override, "app.py")):
        return os.path.abspath(local_override)

    # 2. Local sibling path detection (local dev convenience)
    possible_locals = [
        "D:/LariviereAI",
        "D:\\LariviereAI",
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "LariviereAI")),
    ]
    for candidate in possible_locals:
        if os.path.isdir(candidate) and os.path.exists(os.path.join(candidate, "app.py")):
            return os.path.abspath(candidate)

    # 3. Cached runtime directory in container
    target_dir = os.path.abspath(RUNTIME_CACHE_DIR)
    app_entry = os.path.join(target_dir, "app.py")
    if os.path.exists(app_entry) and os.path.getsize(app_entry) > 0:
        return target_dir

    # 4. Download from GitHub REST API
    repo = get_config("GITHUB_REPO", DEFAULT_REPO)
    ref = get_config("GITHUB_REF", DEFAULT_REF)
    token = get_config("GITHUB_TOKEN")

    if not token:
        raise RuntimeError(
            "Configuration manquante : GITHUB_TOKEN doit être configuré dans Streamlit Secrets pour charger Larivière."
        )

    return fetch_private_app_archive(repo=repo, ref=ref, token=token, target_dir=target_dir)


def load_and_run_lariviere() -> None:
    """Securely load and execute the private LariviereAI application.

    Must only be called AFTER authentication is verified.
    """
    if not is_authenticated():
        raise PermissionError("Tentative de chargement du module privé sans authentification préalable.")

    app_path = resolve_private_app_path()

    if app_path not in sys.path:
        sys.path.insert(0, app_path)

    # Import the private app module
    if "app" in sys.modules:
        lariviere_module = sys.modules["app"]
    else:
        lariviere_module = importlib.import_module("app")

    # Execute main or run entrypoint
    if hasattr(lariviere_module, "main") and callable(lariviere_module.main):
        lariviere_module.main()
    elif hasattr(lariviere_module, "run") and callable(lariviere_module.run):
        lariviere_module.run()
    else:
        raise RuntimeError("Le module LariviereAI ne dispose ni d'un point d'entrée main() ni de run().")
