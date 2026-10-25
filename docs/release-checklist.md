# GitHub publication and formal Release checklist

This is a **maintainer-only checklist**, not authorization to publish. **Current version: 2.2.0a3.** The public source-alpha branch and downloadable binaries have different acceptance thresholds.

## Stage A — Public source-alpha review (NO TAG / NO RELEASE)

For the final 2.2.0a3 GUI revision, use [current acceptance](gui-final-2.2.0a3.md) and the supplied exact-tree manifest. GUI-01/02/03 are fixed; do not reuse the earlier `a753…` source or matching old EXEs as current evidence. Re-run all checks if the source changes. Confirm repository URL, public Git identity, owner approval, pending remote CI and the documented native DPI/VM limits.

Follow [Source Alpha publication](source-alpha-publication.md). Before any push, obtain the owner's explicit approval of the exact source tree and GitHub destination; inspect staged content, legal/public identity, MIT and third-party notices, privacy risks and relevant history. Run the source consistency check, complete tests, embedded tests and publication audit. The audit is not an exhaustive secrets scan. Never stage local validation evidence, passwords, HMAC keys, WFP XML, repair journals or unsigned EXEs.

Only after approval, an authorized maintainer may use the separately reviewed clean publication checkout. The development checkout retains an older staged foundation and private rollback references; its index is not the proposed publication tree. Inspect the supplied file manifest and exact commit/tree before configuring a remote. Do not bulk-stage the development checkout.

```powershell
# FIRST: inspect both the worktree and staged changes before committing.
git status --short
git ls-files
git log --format=fuller
git show --stat HEAD
# Compare HEAD and the supplied manifest with the owner's approved tree.
# Configure a destination only after explicit owner approval.
# Do NOT create a version tag or GitHub Release yet.
```

Use an owner-approved public Git identity or GitHub no-reply identity. Repository creation, remote addition, visibility changes, push, and any release require separate explicit user approval. GitHub repository configuration must be checked by the owner: branch protection/rules, private vulnerability reporting, secret scanning where available, and CI permissions.

## Stage B — Formal binary / tagged release (BLOCKED)

The actual workflow at `.github/workflows/release.yml` responds to version tags but runs `scripts/check_release_gate.py` **before builds**. It will fail while `release-gate.json` has `formal_release_ready=false`; tags alone do **not** create a draft release. A manual `workflow_dispatch` request for a draft also requires a matching reviewed version tag, successful checks, and the `release` environment approval. Never interpret the workflow definition as permission to publish.

Before allowing a formal release for the exact reviewed version and source digest:

- [ ] Controlled WinINET write / restore / conflict-protection acceptance in a recoverable Windows environment.
- [ ] Clean Windows 11 VM validation of the exact newly built GUI and CLI EXEs with no Python installed.
- [ ] Real UAC cancel/accept and privileged WFP export acceptance; validate GUI manually.
- [ ] Inspect and retain original Windows/CI logs, privacy and signing state, SHA-256 manifest and build provenance.
- [ ] Manually review/update release notes and versioned documentation for this revision.
- [ ] With evidence and explicit owner approval, update the precise gate fields and reviewed source digest, then run `scripts/check_release_gate.py`.
- [ ] Review the exact tag, GitHub release draft and all assets before publishing anything.

`actions/attest` provenance shows where an artifact was built, not that it is safe or code-signed. Unsigned EXEs may trigger Windows protections; never tell users to disable security software automatically. Review GitHub repository settings and permissions before any remote workflow executes.

## Version transitions

Do not copy old `v2.2.0a1` / `v2.2.0a2` tag examples into a 2.2.0a3 release. For any later version, update `pyproject.toml`, `winnetdiff/core/models.py`, release notes, validation evidence, generated single file, source digest and gate coherently. A passing Source Alpha CI job is not evidence sufficient to flip the formal binary release gate.
