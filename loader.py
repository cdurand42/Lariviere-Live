"""Secure loader for LariviereAI private repository.

Guarantees:
- GITHUB_TOKEN is NEVER put in URLs, git CLI commands, or logs.
- GitHub REST API tarball endpoint used exclusively with in-memory Bearer token.
- Dynamic commit SHA detection with short in-memory TTL (~60s) to detect updates.
- Atomic cache directory replacement with rollback on extraction failure.
- Targeted Python sys.modules invalidation upon new commit arrival.
- Safe tarball extraction (path traversal mitigation).
- Local dev directory fallback for offline and local testing.
- Entrypoint execution via main() or run().
"""

from __future__ import annotations

import importlib
import io
import logging
import os
import secrets
import shutil
import sys
import tarfile
import time
from typing import Any, Optional
import requests

from auth import get_config, is_authenticated

LOGGER = logging.getLogger(__name__)

DEFAULT_REPO = "cdurand42/lariviere-ai-demo"
DEFAULT_REF = "main"
RUNTIME_CACHE_DIR = "_lariviere_app"
COMMIT_SHA_FILENAME = ".commit_sha"
DEFAULT_SHA_CACHE_TTL_SECONDS = 60

# In-memory TTL cache for remote commit SHAs: key (repo@ref) -> (sha, timestamp)
_REMOTE_SHA_CACHE: dict[str, tuple[str, float]] = {}


def _sanitize_message(message: str, token: str) -> str:
    """Strip token occurrences from error strings or logs."""
    if token and token in message:
        return message.replace(token, "***TOKEN***")
    return message


def get_remote_commit_sha(
    repo: str,
    ref: str,
    token: str,
    timeout: int = 15,
    ttl: int = DEFAULT_SHA_CACHE_TTL_SECONDS,
) -> str:
    """Fetch current commit SHA for repo@ref via GitHub API with an in-memory TTL cache.

    Security:
    - Token passed strictly in Authorization header.
    - Token is NEVER put in URL, logs, or error messages.
    """
    if not token:
        raise RuntimeError("Jeton GITHUB_TOKEN manquant pour l'accès au dépôt privé.")
    if not repo:
        raise RuntimeError("Nom du dépôt GITHUB_REPO manquant.")
    if not ref:
        raise RuntimeError("Référence GITHUB_REF manquante.")

    cache_key = f"{repo.strip()}@{ref.strip()}"
    now = time.time()
    cached = _REMOTE_SHA_CACHE.get(cache_key)
    if cached is not None and ttl > 0:
        cached_sha, cached_time = cached
        if (now - cached_time) < ttl:
            return cached_sha

    api_url = f"https://api.github.com/repos/{repo.strip()}/commits/{ref.strip()}"
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

    try:
        data = resp.json()
        sha = data.get("sha")
        if not sha or not isinstance(sha, str):
            raise ValueError("Réponse GitHub commits invalide : SHA manquant.")
    except Exception as exc:
        clean_msg = _sanitize_message(str(exc), token)
        raise RuntimeError(f"Erreur de décodage du SHA GitHub : {clean_msg}") from None

    clean_sha = sha.strip()
    _REMOTE_SHA_CACHE[cache_key] = (clean_sha, now)
    return clean_sha


def get_local_commit_sha(target_dir: str) -> str:
    """Retrieve locally stored commit SHA from cache directory."""
    sha_path = os.path.join(target_dir, COMMIT_SHA_FILENAME)
    if os.path.isfile(sha_path):
        try:
            with open(sha_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            return ""
    return ""


def cleanup_residual_cache_dirs(target_dir: str) -> None:
    """Clean up any leftover temporary or old extraction directories."""
    parent_dir = os.path.dirname(os.path.abspath(target_dir))
    base_name = os.path.basename(os.path.abspath(target_dir))
    if not os.path.isdir(parent_dir):
        return

    try:
        for entry in os.listdir(parent_dir):
            if entry.startswith(f"{base_name}_tmp") or entry.startswith(f"{base_name}_old"):
                full_path = os.path.join(parent_dir, entry)
                if os.path.isdir(full_path):
                    shutil.rmtree(full_path, ignore_errors=True)
    except Exception:
        pass


def invalidate_cached_modules(target_dir: str) -> list[str]:
    """Purge exclusively modules loaded from target_dir from sys.modules and invalidate caches.

    Safeguards:
    - importlib.invalidate_caches() called.
    - Never purges third-party dependencies (streamlit, requests, auth, loader, etc.).
    - Purges only modules whose __file__ is inside target_dir or 'app' if located in target_dir.
    """
    importlib.invalidate_caches()
    target_abs = os.path.normcase(os.path.abspath(target_dir))
    purged: list[str] = []

    for mod_name, mod in list(sys.modules.items()):
        if mod is None:
            continue
        # Never purge standard lib or critical third-party packages
        if mod_name.startswith(("streamlit", "requests", "urllib", "pytest", "encodings", "unittest")):
            continue
        # Never purge portal host modules
        if mod_name in ("auth", "loader"):
            continue

        mod_file = getattr(mod, "__file__", None)
        if mod_file:
            try:
                mod_file_abs = os.path.normcase(os.path.abspath(mod_file))
                if mod_file_abs.startswith(target_abs + os.sep) or mod_file_abs == target_abs:
                    purged.append(mod_name)
            except Exception:
                pass
        elif mod_name == "app":
            purged.append(mod_name)

    for mod_name in purged:
        sys.modules.pop(mod_name, None)

    return purged


def fetch_private_app_archive(
    repo: str,
    ref: str,
    token: str,
    target_dir: str,
    commit_sha: str = "",
    timeout: int = 30,
) -> str:
    """Download and extract private repository tarball atomically via GitHub REST API.

    Security:
    - Token is passed strictly in Authorization header.
    - Token is NEVER put in URL or command line.

    Atomic guarantees:
    - Downloads and extracts into temporary directory target_dir_tmp.
    - Writes .commit_sha into target_dir_tmp.
    - Validates app.py before swapping.
    - Renames target_dir -> target_dir_old (if exists).
    - Swaps target_dir_tmp -> target_dir.
    - If swap fails, immediately restores target_dir_old.
    - Removes target_dir_old only after successful swap.
    """
    if not token:
        raise RuntimeError("Jeton GITHUB_TOKEN manquant pour l'accès au dépôt privé.")
    if not repo:
        raise RuntimeError("Nom du dépôt GITHUB_REPO manquant.")

    target_dir_abs = os.path.abspath(target_dir)
    parent_dir = os.path.dirname(target_dir_abs)
    base_name = os.path.basename(target_dir_abs)
    os.makedirs(parent_dir, exist_ok=True)

    cleanup_residual_cache_dirs(target_dir_abs)

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

    tmp_dir = os.path.join(parent_dir, f"{base_name}_tmp_{secrets.token_hex(4)}")
    old_dir = os.path.join(parent_dir, f"{base_name}_old_{secrets.token_hex(4)}")

    try:
        os.makedirs(tmp_dir, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:gz") as tar:
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

                dest_path = os.path.join(tmp_dir, rel_path)
                if member.isdir():
                    os.makedirs(dest_path, exist_ok=True)
                elif member.isfile():
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    with open(dest_path, "wb") as f_out:
                        f_in = tar.extractfile(member)
                        if f_in is not None:
                            f_out.write(f_in.read())

        # Validate extracted contents
        app_entry = os.path.join(tmp_dir, "app.py")
        if not os.path.isfile(app_entry) or os.path.getsize(app_entry) == 0:
            raise RuntimeError("Extraction invalide : app.py manquant ou vide dans l'archive téléchargée.")

        # Persist commit SHA in temp directory before swapping
        if commit_sha:
            with open(os.path.join(tmp_dir, COMMIT_SHA_FILENAME), "w", encoding="utf-8") as f_sha:
                f_sha.write(commit_sha.strip())

        # Atomic swap with rollback
        target_existed = os.path.exists(target_dir_abs)
        if target_existed:
            os.rename(target_dir_abs, old_dir)

        try:
            os.rename(tmp_dir, target_dir_abs)
        except Exception as swap_exc:
            # Immediate rollback if tmp -> target fails
            if target_existed and os.path.exists(old_dir) and not os.path.exists(target_dir_abs):
                os.rename(old_dir, target_dir_abs)
            raise RuntimeError(f"Échec de bascule atomique du cache : {swap_exc}") from None

        # Remove old directory only after successful swap
        if os.path.exists(old_dir):
            shutil.rmtree(old_dir, ignore_errors=True)

        return target_dir_abs

    except Exception:
        # Clean up temp dir on error
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)
        raise


def resolve_private_app_path() -> str:
    """Determine the path to the private LariviereAI code.

    Priority:
    1. Explicit local path override (LARIVIERE_LOCAL_PATH).
    2. Local sibling directory (D:/LariviereAI or ../LariviereAI) if valid.
    3. Remote GitHub check:
       - Fetch remote commit SHA for GITHUB_REPO@GITHUB_REF (with 60s memory TTL).
       - If _lariviere_app/app.py exists and local_sha == remote_sha: reuse cache.
       - Otherwise: download fresh tarball, extract atomically, update .commit_sha,
         and invalidate cached modules in sys.modules.
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

    # 3. Dynamic GitHub download with SHA-based cache invalidation
    repo = get_config("GITHUB_REPO", DEFAULT_REPO)
    ref = get_config("GITHUB_REF", DEFAULT_REF)
    token = get_config("GITHUB_TOKEN")

    if not token:
        raise RuntimeError(
            "Configuration manquante : GITHUB_TOKEN doit être configuré dans Streamlit Secrets pour charger Larivière."
        )

    target_dir = os.path.abspath(RUNTIME_CACHE_DIR)
    app_entry = os.path.join(target_dir, "app.py")

    # Fetch remote commit SHA (with in-memory TTL)
    remote_sha = get_remote_commit_sha(repo=repo, ref=ref, token=token)
    local_sha = get_local_commit_sha(target_dir)

    # If cache exists and SHA matches, reuse cached extraction
    if os.path.isfile(app_entry) and os.path.getsize(app_entry) > 0 and local_sha and local_sha == remote_sha:
        LOGGER.info("PRIVATE_APP repo=%s ref=%s commit=%s source=cache", repo, ref, remote_sha[:7])
        return target_dir

    # Otherwise, download new archive atomically and invalidate python module cache
    extracted_path = fetch_private_app_archive(
        repo=repo,
        ref=ref,
        token=token,
        target_dir=target_dir,
        commit_sha=remote_sha,
    )
    invalidate_cached_modules(target_dir)
    LOGGER.info("PRIVATE_APP repo=%s ref=%s commit=%s source=download", repo, ref, remote_sha[:7])
    return extracted_path


def load_and_run_lariviere() -> None:
    """Securely load and execute the private LariviereAI application.

    Must only be called AFTER authentication is verified.
    """
    if not is_authenticated():
        raise PermissionError("Tentative de chargement du module privé sans authentification préalable.")

    app_path = resolve_private_app_path()

    if app_path not in sys.path or sys.path[0] != app_path:
        if app_path in sys.path:
            sys.path.remove(app_path)
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
