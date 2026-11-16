# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Unit tests for GitHubClient — fully mocked, no network.

Uses asyncio.run() directly rather than pytest-asyncio so these run under the
same plain `pytest` command the project's other tests use."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from app.github_client import GitHubClient
from github import GithubException


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


@pytest.fixture
def disabled_client():
    return GitHubClient(token=None)


@pytest.fixture
def enabled_client(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
    monkeypatch.setenv("TARGET_REPO", "owner/repo")
    with patch("app.github_client.Github") as mock_gh:
        client = GitHubClient()
        client._mock_gh = mock_gh
        yield client


def test_disabled_when_no_token(disabled_client):
    assert disabled_client.enabled is False
    result = _run(disabled_client.open_pr_with_file_change(
        repo="owner/repo",
        branch_name="fix/x",
        file_path="src/Job.java",
        new_content="new content",
        commit_message="fix",
        pr_title="Fix",
        pr_body="Body",
    ))
    assert result["success"] is False
    assert "not configured" in result["error"].lower()


def test_happy_path_returns_pr_url(enabled_client):
    mock_repo = MagicMock()
    mock_branch = MagicMock()
    mock_branch.commit.sha = "deadbeef"
    mock_repo.get_branch.return_value = mock_branch

    mock_pr = MagicMock()
    mock_pr.number = 42
    mock_pr.html_url = "https://github.com/owner/repo/pull/42"
    mock_repo.create_pull.return_value = mock_pr

    mock_repo.get_contents.side_effect = GithubException(404, {"message": "Not Found"}, {})

    enabled_client._gh.get_repo.return_value = mock_repo

    result = _run(enabled_client.open_pr_with_file_change(
        repo="owner/repo",
        branch_name="fix/skew",
        file_path="src/main/java/Job.java",
        new_content="public class Job {}",
        commit_message="Fix skew",
        pr_title="Fix skew",
        pr_body="Diagnosed celebrity-key skew on userId=123.",
    ))

    assert result["success"] is True
    assert result["pr_url"] == "https://github.com/owner/repo/pull/42"
    assert result["pr_number"] == 42
    assert result["branch"] == "fix/skew"

    mock_repo.create_git_ref.assert_called_once_with(
        ref="refs/heads/fix/skew", sha="deadbeef"
    )
    mock_repo.create_file.assert_called_once()
    mock_repo.create_pull.assert_called_once_with(
        title="Fix skew",
        body="Diagnosed celebrity-key skew on userId=123.",
        head="fix/skew",
        base="main",
    )


def test_refuses_existing_branch(enabled_client):
    """Reusing an existing branch would land the commit directly on it (including
    the base branch) even though create_pull later fails — must refuse instead,
    with a structured error and NO commit or PR call."""
    mock_repo = MagicMock()
    mock_branch = MagicMock()
    mock_branch.commit.sha = "deadbeef"
    mock_repo.get_branch.return_value = mock_branch

    mock_repo.create_git_ref.side_effect = GithubException(
        422, {"message": "Reference already exists"}, {}
    )

    enabled_client._gh.get_repo.return_value = mock_repo

    result = _run(enabled_client.open_pr_with_file_change(
        repo="owner/repo",
        branch_name="ai-debugger/x",
        file_path="src/Job.java",
        new_content="updated",
        commit_message="Update",
        pr_title="Update",
        pr_body="Body",
    ))

    assert result["success"] is False
    assert "already exists" in result["error"]
    mock_repo.update_file.assert_not_called()
    mock_repo.create_file.assert_not_called()
    mock_repo.create_pull.assert_not_called()


def test_refusal_is_its_own_exception_type():
    from app.github_client import BranchExistsError
    assert issubclass(BranchExistsError, Exception)
    assert not issubclass(BranchExistsError, ValueError)


def test_failure_after_ref_creation_deletes_orphan_ref_and_is_not_reported_as_exists(enabled_client):
    """Review #42: `except ValueError` also caught the UnicodeEncodeError that
    update_file raises for a lone surrogate — AFTER create_git_ref had run — so
    the tool reported "branch already exists" for a brand-new branch and the
    orphan ref then made the slug refused forever. The ref must be cleaned up
    and the real error surfaced."""
    mock_repo = MagicMock()
    mock_branch = MagicMock()
    mock_branch.commit.sha = "deadbeef"
    mock_repo.get_branch.return_value = mock_branch
    mock_repo.get_contents.return_value = MagicMock(sha="filesha")
    mock_repo.update_file.side_effect = UnicodeEncodeError("utf-8", "\udcff", 0, 1, "surrogates not allowed")
    enabled_client._gh.get_repo.return_value = mock_repo

    result = _run(enabled_client.open_pr_with_file_change(
        repo="owner/repo",
        branch_name="ai-debugger/lone-surrogate",
        file_path="src/Job.java",
        new_content="\udcff",
        commit_message="Update",
        pr_title="Update",
        pr_body="Body",
    ))

    assert result["success"] is False
    assert "already exists" not in result["error"]
    assert "surrogates" in result["error"]
    mock_repo.create_git_ref.assert_called_once()
    mock_repo.get_git_ref.assert_called_once_with("heads/ai-debugger/lone-surrogate")
    mock_repo.get_git_ref.return_value.delete.assert_called_once()
    mock_repo.create_pull.assert_not_called()


def test_failure_at_create_pull_also_cleans_up_the_ref(enabled_client):
    mock_repo = MagicMock()
    mock_repo.get_branch.return_value = MagicMock(commit=MagicMock(sha="deadbeef"))
    mock_repo.get_contents.side_effect = GithubException(404, {"message": "Not Found"}, {})
    mock_repo.create_pull.side_effect = GithubException(422, {"message": "Validation Failed"}, {})
    enabled_client._gh.get_repo.return_value = mock_repo

    result = _run(enabled_client.open_pr_with_file_change(
        repo="owner/repo", branch_name="ai-debugger/x", file_path="src/Job.java",
        new_content="c", commit_message="m", pr_title="t", pr_body="b",
    ))
    assert result["success"] is False and "422" in result["error"]
    mock_repo.get_git_ref.return_value.delete.assert_called_once()


def test_ref_cleanup_failure_does_not_mask_the_real_error(enabled_client):
    mock_repo = MagicMock()
    mock_repo.get_branch.return_value = MagicMock(commit=MagicMock(sha="deadbeef"))
    mock_repo.get_contents.side_effect = GithubException(404, {"message": "Not Found"}, {})
    mock_repo.create_pull.side_effect = GithubException(500, {"message": "boom"}, {})
    mock_repo.get_git_ref.side_effect = GithubException(403, {"message": "no delete"}, {})
    enabled_client._gh.get_repo.return_value = mock_repo

    result = _run(enabled_client.open_pr_with_file_change(
        repo="owner/repo", branch_name="ai-debugger/x", file_path="src/Job.java",
        new_content="c", commit_message="m", pr_title="t", pr_body="b",
    ))
    assert result["success"] is False
    assert "500" in result["error"] and "boom" in result["error"]


def test_existing_branch_refusal_does_not_touch_refs(enabled_client):
    """The 422 path never created anything, so it must not delete anything."""
    mock_repo = MagicMock()
    mock_repo.get_branch.return_value = MagicMock(commit=MagicMock(sha="deadbeef"))
    mock_repo.create_git_ref.side_effect = GithubException(422, {"message": "Reference already exists"}, {})
    enabled_client._gh.get_repo.return_value = mock_repo

    result = _run(enabled_client.open_pr_with_file_change(
        repo="owner/repo", branch_name="ai-debugger/x", file_path="src/Job.java",
        new_content="c", commit_message="m", pr_title="t", pr_body="b",
    ))
    assert "already exists" in result["error"]
    mock_repo.get_git_ref.assert_not_called()


def _tree(paths):
    tree = MagicMock()
    tree.tree = [MagicMock(path=p, type="blob") for p in paths]
    return tree


def test_list_files_applies_path_predicate_before_the_cap(enabled_client):
    """Review #43: the denylist ran AFTER the 500 cap, so `count` and
    `truncated` described the pre-filter listing. Filtering first makes them
    describe what the caller receives."""
    from app.github_client import LIST_FILES_CAP
    denied = [f".github/workflows/w{i}.yml" for i in range(LIST_FILES_CAP)]
    allowed = [f"src/A{i}.java" for i in range(LIST_FILES_CAP + 10)]
    mock_repo = MagicMock()
    mock_repo.get_commit.return_value = MagicMock(sha="c0ffee")
    mock_repo.get_git_tree.return_value = _tree(denied + allowed)
    enabled_client._gh.get_repo.return_value = mock_repo

    result = _run(enabled_client.list_files(
        "owner/repo", None, "main", path_allowed=lambda p: not p.startswith(".github/")
    ))
    assert result["success"] is True
    assert result["files"] == allowed[:LIST_FILES_CAP]      # nothing denied, cap on the VISIBLE set
    assert result["count"] == LIST_FILES_CAP
    assert result["truncated"] is True


def test_list_files_without_predicate_is_unchanged(enabled_client):
    mock_repo = MagicMock()
    mock_repo.get_commit.return_value = MagicMock(sha="c0ffee")
    mock_repo.get_git_tree.return_value = _tree(["a.java", "b.java"])
    enabled_client._gh.get_repo.return_value = mock_repo
    result = _run(enabled_client.list_files("owner/repo"))
    assert result["files"] == ["a.java", "b.java"]
    assert result["count"] == 2 and result["truncated"] is False


def test_github_exception_returns_structured_error(enabled_client):
    mock_repo = MagicMock()
    mock_repo.get_branch.side_effect = GithubException(
        401, {"message": "Bad credentials"}, {}
    )
    enabled_client._gh.get_repo.return_value = mock_repo

    result = _run(enabled_client.open_pr_with_file_change(
        repo="owner/repo",
        branch_name="fix/x",
        file_path="src/Job.java",
        new_content="new",
        commit_message="fix",
        pr_title="Fix",
        pr_body="Body",
    ))

    assert result["success"] is False
    assert "401" in result["error"]
    assert "Bad credentials" in result["error"]


# ── link following: a read must refuse symlinks, never follow them ─────────
#
# Mocks follow the real GitHub API shapes (checked live on git/git, where
# RelNotes is a symlink):
#   GET /repos/git/git/contents/RelNotes
#     -> {"type": "file", "path": "RelNotes", "size": 17747, ...}
#        i.e. type "file" at the REQUESTED path with the TARGET's content
#   GET /repos/git/git/git/trees/<tree>
#     -> {"path": "RelNotes", "mode": "120000", "type": "blob", "size": 34, ...}
# so only the trees API reveals the link.

def _entry(path, mode, type_, sha=None):
    return MagicMock(path=path, mode=mode, type=type_, sha=sha or f"sha-{path}")


def _repo_with_trees(trees, contents):
    """trees: {tree_sha: [entries]}, root tree keyed by the commit sha."""
    repo = MagicMock()
    repo.get_commit.return_value = MagicMock(sha="c0ffee")
    repo.get_git_tree.side_effect = lambda sha, **_: MagicMock(tree=trees[sha])
    repo.get_contents.return_value = contents
    return repo


def _contents_as_github_returns_it(requested_path, content):
    # What the contents API returns for a regular file AND for a symlink to a
    # file: type "file" at the requested path, with whatever content is there.
    return MagicMock(path=requested_path, type="file", decoded_content=content,
                     sha="s", size=len(content))


def test_read_refuses_a_symlink_to_a_refused_path(enabled_client):
    """src/notes.txt -> ../.github/workflows/deploy.yml. The contents API
    answers as if it were a regular file; the tree entry has mode 120000."""
    trees = {
        "c0ffee": [_entry("src", "040000", "tree", "t-src")],
        "t-src": [_entry("notes.txt", "120000", "blob")],
    }
    repo = _repo_with_trees(trees, _contents_as_github_returns_it(
        "src/notes.txt", b"deploy: secret-workflow"))
    enabled_client._gh.get_repo.return_value = repo
    result = _run(enabled_client.read_file("owner/repo", "src/notes.txt", "main"))
    assert result["success"] is False
    assert "content" not in result
    assert "symbolic link" in result["error"]
    repo.get_contents.assert_not_called()       # refused before any content read


def test_read_refuses_a_path_through_a_symlinked_directory(enabled_client):
    trees = {
        "c0ffee": [_entry("src", "120000", "blob")],     # src -> .github
    }
    repo = _repo_with_trees(trees, _contents_as_github_returns_it(
        "src/deploy.yml", b"x"))
    enabled_client._gh.get_repo.return_value = repo
    result = _run(enabled_client.read_file("owner/repo", "src/deploy.yml", "main"))
    assert result["success"] is False and "symbolic link" in result["error"]
    repo.get_contents.assert_not_called()


def test_read_refuses_a_submodule(enabled_client):
    trees = {"c0ffee": [_entry("vendor", "160000", "commit")]}
    repo = _repo_with_trees(trees, _contents_as_github_returns_it("vendor", b"x"))
    enabled_client._gh.get_repo.return_value = repo
    result = _run(enabled_client.read_file("owner/repo", "vendor", "main"))
    assert result["success"] is False and "content" not in result
    repo.get_contents.assert_not_called()


def test_read_of_a_missing_path_is_refused_without_a_content_read(enabled_client):
    trees = {"c0ffee": [_entry("src", "040000", "tree", "t-src")], "t-src": []}
    repo = _repo_with_trees(trees, _contents_as_github_returns_it("src/a.txt", b"x"))
    enabled_client._gh.get_repo.return_value = repo
    result = _run(enabled_client.read_file("owner/repo", "src/a.txt", "main"))
    assert result["success"] is False and "not found" in result["error"]
    repo.get_contents.assert_not_called()


def test_read_of_a_regular_file_still_works_and_is_pinned_to_one_commit(enabled_client):
    trees = {
        "c0ffee": [_entry("src", "040000", "tree", "t-src")],
        "t-src": [_entry("notes.txt", "100644", "blob")],
    }
    repo = _repo_with_trees(trees, _contents_as_github_returns_it("src/notes.txt", b"hello"))
    enabled_client._gh.get_repo.return_value = repo
    result = _run(enabled_client.read_file("owner/repo", "src/notes.txt", "main"))
    assert result["success"] is True and result["content"] == "hello"
    repo.get_contents.assert_called_once_with("src/notes.txt", ref="c0ffee")


def test_read_of_an_executable_file_works(enabled_client):
    trees = {"c0ffee": [_entry("run.sh", "100755", "blob")]}
    repo = _repo_with_trees(trees, _contents_as_github_returns_it("run.sh", b"echo"))
    enabled_client._gh.get_repo.return_value = repo
    result = _run(enabled_client.read_file("owner/repo", "run.sh", "main"))
    assert result["success"] is True


def test_list_files_does_not_offer_symlinks(enabled_client):
    mock_repo = MagicMock()
    mock_repo.get_commit.return_value = MagicMock(sha="c0ffee")
    mock_repo.get_git_tree.return_value = MagicMock(tree=[
        _entry("a.java", "100644", "blob"), _entry("link.java", "120000", "blob"),
    ])
    enabled_client._gh.get_repo.return_value = mock_repo
    result = _run(enabled_client.list_files("owner/repo"))
    assert result["files"] == ["a.java"]
