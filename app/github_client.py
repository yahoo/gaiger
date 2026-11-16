# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""
Thin async wrapper around PyGithub for the AI debugger's create_github_pr tool.

Targets github.com by default — base URL is overridable via GITHUB_API_BASE
for GitHub Enterprise Server hosts (e.g. https://ghe.example.com/api/v3). Token is optional: when
unset, self.enabled is False and the agent's write tool is silently disabled.

PyGithub is synchronous; methods here wrap calls in asyncio.to_thread to fit
the rest of the async codebase.
"""

import asyncio
import logging
import os
from typing import Callable, Optional

from github import Github, GithubException

from app import secret_provider
from app.egress_governance import repo_path_allowed
from app.egress_policy import GITHUB_DEFAULT_ALLOWED_HOSTS, validate_destination

logger = logging.getLogger(__name__)

# Listing cap: beyond this the tree is cut and `truncated` is reported.
LIST_FILES_CAP = 500


class BranchExistsError(Exception):
    """Deliberate refusal to reuse an existing branch (see _open_pr_sync).

    Its own type — not ValueError — so the structured "already exists" refusal
    can never be produced by an unrelated ValueError subclass raised later in
    the flow (UnicodeEncodeError from update_file is one), which would report a
    misleading reason and leave the just-created ref behind."""


class GitHubClient:
    def __init__(self, token: Optional[str] = None, api_base: Optional[str] = None):
        self.token = token or os.getenv("GITHUB_TOKEN", "")
        # Fail closed at construction: the repo-scoped PAT follows this URL on
        # every call, so a plaintext or off-allowlist destination must stop the
        # pod from starting. No legitimate loopback case exists for GitHub.
        # With no operator allowlist (EGRESS_ALLOWED_HOSTS unset — the shipped
        # state) the host must be one of the built-in known GitHub API hosts;
        # an operator extends that by listing the extra host in
        # EGRESS_ALLOWED_HOSTS (together with every other pinned destination).
        self.api_base = validate_destination(
            api_base or os.getenv("GITHUB_API_BASE", "https://api.github.com"),
            name="GITHUB_API_BASE", require_https=True, allow_loopback=False,
            default_allowed_hosts=GITHUB_DEFAULT_ALLOWED_HOSTS,
        )
        # Set TARGET_REPO to the org/repo the agent should target for PR creation,
        # or pass `repo` explicitly in each create_github_pr call. When unset, the
        # GitHub tools refuse to register (see langgraph_agent gating).
        self.default_repo = os.getenv("TARGET_REPO", "")
        self.enabled = bool(self.token)

        if self.enabled:
            self._gh = Github(base_url=self.api_base, login_or_token=self.token)
            logger.info(
                "GitHub integration enabled (api_base=%s, default_repo=%s)",
                self.api_base, self.default_repo or "none",
            )
        else:
            self._gh = None
            logger.warning(
                "GitHub integration disabled — GITHUB_TOKEN not set "
                "(create_github_pr will be a no-op)"
            )

    def _refresh_token_if_rotated(self) -> None:
        """Rebuild the PyGithub client when the provider's cached PAT differs
        from the one this client was built with. The getter re-fetches from
        the secret backend once its cache TTL expires; runs inside the asyncio.to_thread
        worker, so the subprocess fetch never blocks the event loop.

        Propagates the getter's fail-closed error: after an invalidation (the
        PAT just 401'd) a failed re-fetch must fail the call rather than reuse
        the client built with the known-bad PAT. A TTL re-fetch failure never
        raises (the getter serves the cached value with a back-off)."""
        current = secret_provider.get_github_token()
        if current and current != self.token:
            logger.info("GitHub PAT rotated — rebuilding GitHub client")
            self.token = current
            self._gh = Github(base_url=self.api_base, login_or_token=current)

    @staticmethod
    def _note_auth_failure(e: GithubException) -> None:
        """Invalidate the cached PAT on an authentication failure so the next
        call re-fetches a fresh one from the secret backend (invalidate-on-401)."""
        if getattr(e, "status", None) == 401:
            secret_provider.invalidate_github_token()

    async def read_file(
        self,
        repo: str,
        file_path: str,
        ref: str = "main",
    ) -> dict:
        """Fetch the current content of a file from the configured GitHub repository.

        Returns {"success": True, "content": str, "sha": str, "path": str,
        "size": int} or {"success": False, "error": str}. The agent uses this
        before proposing a PR so it can reason about the actual source rather
        than guessing or asking the operator to paste it.
        """
        if not self.enabled:
            return {
                "success": False,
                "error": "GitHub not configured — set GITHUB_TOKEN",
            }

        try:
            return await asyncio.to_thread(self._read_file_sync, repo, file_path, ref)
        except GithubException as e:
            self._note_auth_failure(e)
            logger.exception("GitHub API error reading %s from %s@%s", file_path, repo, ref)
            return {
                "success": False,
                "error": f"GitHub API error ({e.status}): {e.data.get('message', str(e))}",
            }
        except Exception as e:
            logger.exception("Unexpected error reading %s from %s@%s", file_path, repo, ref)
            return {"success": False, "error": f"Unexpected error: {e}"}

    async def list_files(
        self,
        repo: str,
        path_filter: Optional[str] = None,
        ref: str = "main",
        path_allowed: Optional[Callable[[str], bool]] = None,
    ) -> dict:
        """List source files in the repo so the agent can discover the right path
        instead of guessing. Returns {"success": True, "files": [paths...]}.

        path_filter, when set, restricts to paths starting with that prefix
        (e.g. "src/main/java" to skip tests and resources). path_allowed, when
        set, is applied BEFORE the size cap so `count` / `truncated` describe
        the visible listing (filtering after the cap silently under-reported).
        """
        if not self.enabled:
            return {
                "success": False,
                "error": "GitHub not configured — set GITHUB_TOKEN",
            }
        try:
            return await asyncio.to_thread(
                self._list_files_sync, repo, path_filter, ref, path_allowed
            )
        except GithubException as e:
            self._note_auth_failure(e)
            logger.exception("GitHub API error listing files in %s@%s", repo, ref)
            return {
                "success": False,
                "error": f"GitHub API error ({e.status}): {e.data.get('message', str(e))}",
            }
        except Exception as e:
            logger.exception("Unexpected error listing files in %s@%s", repo, ref)
            return {"success": False, "error": f"Unexpected error: {e}"}

    def _list_files_sync(
        self,
        repo: str,
        path_filter: Optional[str],
        ref: str,
        path_allowed: Optional[Callable[[str], bool]] = None,
    ) -> dict:
        self._refresh_token_if_rotated()
        gh_repo = self._gh.get_repo(repo)
        commit = gh_repo.get_commit(ref)
        tree = gh_repo.get_git_tree(commit.sha, recursive=True)
        # Symlinks are blobs too (mode 120000); read_file refuses them, so do
        # not offer them.
        files = [e.path for e in tree.tree if e.type == "blob" and e.mode != _SYMLINK_MODE]
        if path_filter:
            files = [p for p in files if p.startswith(path_filter)]
        if path_allowed is not None:
            files = [p for p in files if path_allowed(p)]
        truncated = False
        if len(files) > LIST_FILES_CAP:
            files = files[:LIST_FILES_CAP]
            truncated = True
        return {
            "success": True,
            "repo": repo,
            "ref": ref,
            "path_filter": path_filter,
            "count": len(files),
            "truncated": truncated,
            "files": files,
        }

    def _read_file_sync(self, repo: str, file_path: str, ref: str) -> dict:
        if not repo_path_allowed(file_path):   # canonical, permitted path only
            return {"success": False, "error": "that file path is not permitted"}
        self._refresh_token_if_rotated()
        gh_repo = self._gh.get_repo(repo)
        # Pin the ref to one commit so the tree walk and the content read see
        # the same snapshot.
        commit_sha = gh_repo.get_commit(ref).sha
        refusal = _refuse_link_or_non_file(gh_repo, commit_sha, file_path)
        if refusal is not None:
            return refusal
        contents = gh_repo.get_contents(file_path, ref=commit_sha)
        if isinstance(contents, list):
            return {
                "success": False,
                "error": f"{file_path} is a directory — provide a file path",
            }
        if getattr(contents, "type", "file") != "file" or getattr(contents, "path", None) != file_path:
            logger.warning("read_file: refused a path that resolves to a different file")
            return {
                "success": False,
                "error": "that path resolves to a different file and cannot be read",
            }
        # decoded_content is bytes; the agent typically wants text.
        try:
            text = contents.decoded_content.decode("utf-8")
        except UnicodeDecodeError:
            return {
                "success": False,
                "error": f"{file_path} is not UTF-8 text (binary content not supported)",
            }
        return {
            "success": True,
            "content": text,
            "sha": contents.sha,
            "path": contents.path,
            "size": contents.size,
            "ref": ref,
        }

    async def open_pr_with_file_change(
        self,
        repo: str,
        branch_name: str,
        file_path: str,
        new_content: str,
        commit_message: str,
        pr_title: str,
        pr_body: str,
        base_branch: str = "main",
    ) -> dict:
        """Create a branch, commit a single-file change, and open a PR.

        Returns {"success": bool, "pr_url": str, "branch": str, ...} or
        {"success": False, "error": str} on failure. Does NOT raise — the agent
        gets a structured response either way.
        """
        if not self.enabled:
            return {
                "success": False,
                "error": "GitHub not configured — set GITHUB_TOKEN",
            }

        try:
            return await asyncio.to_thread(
                self._open_pr_sync,
                repo, branch_name, file_path, new_content,
                commit_message, pr_title, pr_body, base_branch,
            )
        except BranchExistsError as e:
            # Deliberate refusal — structured, not a crash. Only this exact type:
            # a ValueError from later in the flow must not be reported as this.
            logger.warning("Refused PR on %s: %s", repo, e)
            return {"success": False, "error": str(e)}
        except GithubException as e:
            self._note_auth_failure(e)
            logger.exception("GitHub API error opening PR on %s", repo)
            return {
                "success": False,
                "error": f"GitHub API error ({e.status}): {e.data.get('message', str(e))}",
            }
        except Exception as e:
            logger.exception("Unexpected error opening PR on %s", repo)
            return {"success": False, "error": f"Unexpected error: {e}"}

    def _open_pr_sync(
        self,
        repo: str,
        branch_name: str,
        file_path: str,
        new_content: str,
        commit_message: str,
        pr_title: str,
        pr_body: str,
        base_branch: str,
    ) -> dict:
        self._refresh_token_if_rotated()
        gh_repo = self._gh.get_repo(repo)

        base_ref = gh_repo.get_branch(base_branch)
        base_sha = base_ref.commit.sha

        new_ref = f"refs/heads/{branch_name}"
        try:
            gh_repo.create_git_ref(ref=new_ref, sha=base_sha)
        except GithubException as e:
            if e.status == 422 and "already exists" in str(e.data).lower():
                # Never reuse an existing branch: update_file(branch=...) below
                # would land the commit directly on it — including the base
                # branch — even though the subsequent create_pull() fails, i.e.
                # a failure report over an already-landed commit. Refuse instead.
                logger.warning("Refusing to reuse existing branch %s on %s", branch_name, repo)
                raise BranchExistsError("branch already exists; supply a new branch name")
            else:
                raise

        # From here the ref exists. Any failure before the PR is open (a
        # UnicodeEncodeError from update_file, a GitHub error, ...) must delete
        # it, or the slug is refused forever as "already exists" while the
        # branch carries no PR — the orphan the review reproduced.
        try:
            try:
                existing = gh_repo.get_contents(file_path, ref=branch_name)
                gh_repo.update_file(
                    path=file_path,
                    message=commit_message,
                    content=new_content,
                    sha=existing.sha,
                    branch=branch_name,
                )
            except GithubException as e:
                if e.status == 404:
                    gh_repo.create_file(
                        path=file_path,
                        message=commit_message,
                        content=new_content,
                        branch=branch_name,
                    )
                else:
                    raise

            pr = gh_repo.create_pull(
                title=pr_title,
                body=pr_body,
                head=branch_name,
                base=base_branch,
            )
        except Exception:
            self._delete_ref_quietly(gh_repo, branch_name, repo)
            raise

        logger.info("Opened PR #%d on %s: %s", pr.number, repo, pr.html_url)
        return {
            "success": True,
            "pr_url": pr.html_url,
            "pr_number": pr.number,
            "branch": branch_name,
            "repo": repo,
        }

    @staticmethod
    def _delete_ref_quietly(gh_repo, branch_name: str, repo: str) -> None:
        """Best-effort cleanup of a branch this client just created. Never
        raises: the original failure is what the caller must see."""
        try:
            gh_repo.get_git_ref(f"heads/{branch_name}").delete()
            logger.info("Deleted orphan branch %s on %s after a failed PR flow", branch_name, repo)
        except Exception:  # noqa: BLE001 — cleanup must not mask the real error
            logger.warning(
                "Could not delete branch %s on %s after a failed PR flow; "
                "an operator must remove it before the name can be reused",
                branch_name, repo,
            )


# Git tree entry modes. A symlink is a blob with mode 120000; a submodule is a
# "commit" entry with mode 160000.
_SYMLINK_MODE = "120000"
_REGULAR_FILE_MODES = ("100644", "100755")


def _refuse_link_or_non_file(gh_repo, commit_sha: str, file_path: str) -> Optional[dict]:
    """Walk the git tree at commit_sha one path component at a time and refuse
    (never follow) a symlink anywhere on the path (CWE-59).

    The contents API cannot be used for this check: for a symlink to a file it
    answers with type "file" at the REQUESTED path and the TARGET's content, so
    "src/notes.txt" -> "../.github/workflows/deploy.yml" looks like a regular
    file. Only the trees API exposes the link (mode 120000). A symlinked parent
    directory is refused the same way. Returns None when the path is a regular
    file, else a structured refusal."""
    refused = {
        "success": False,
        "error": "that path is a symbolic link or passes through one and cannot be read",
    }
    parts = file_path.split("/")
    tree = gh_repo.get_git_tree(commit_sha)
    for depth, part in enumerate(parts):
        entry = next((e for e in tree.tree if e.path == part), None)
        if entry is None:
            return {"success": False, "error": f"{file_path} not found at this ref"}
        if entry.mode == _SYMLINK_MODE:
            logger.warning("read_file: refused a path through a symbolic link")
            return refused
        last = depth == len(parts) - 1
        if not last:
            if entry.type != "tree":
                return {"success": False, "error": f"{file_path} not found at this ref"}
            tree = gh_repo.get_git_tree(entry.sha)
        elif entry.type == "tree":
            return {
                "success": False,
                "error": f"{file_path} is a directory — provide a file path",
            }
        elif entry.type != "blob" or entry.mode not in _REGULAR_FILE_MODES:
            logger.warning("read_file: refused a path that is not a regular file")
            return {"success": False, "error": "that path is not a regular file and cannot be read"}
    return None
