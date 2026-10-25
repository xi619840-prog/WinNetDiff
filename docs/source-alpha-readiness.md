# Final 2.2.0a3 Source Alpha readiness — 2026-10-25

**Local source preparation is complete for owner review. NOT published. No source-publication blocker was identified in the tested local scope. Formal Release / EXE remains blocked.** Public use remains an Alpha source preview with explicit platform/repair limitations.

The latest task repairs GUI-01/02/03, rather than accepting their earlier risks. [Current implementation, tests and GUI evidence](gui-final-2.2.0a3.md). Runtime version stays 2.2.0a3; generated SHA-256 is `e4b0dee1dfce0129461f258139248758b10915a4f1178a17c1ecbc11237b3db8`. Older `a753…` logs and unsigned EXEs are historical and do not validate this source.

| Area | Current evidence |
|---|---|
| GUI-01 privacy | Ordinary exports always redact; fresh acknowledged separate full export. Enter/Escape/cancel/window-close denial and all full formats covered by actual Tk tests. Native keyboard cancellation inspected. |
| GUI-02 save location | Existing-folder check, deliberate folder selection, cancellation, missing selected parent, overwrite consent and failed replacement integrity tested. Native normal Save As/cancel inspected. |
| GUI-03 lifecycle | Completed / Cancelled / Failed / Partial labels; partial evidence retained, no overlapping start, worker completion before re-enable, restart and language-switch status tested. Actual synthetic cancel/restart inspected. |
| Full Windows regression | **476 passed, no skips**; independent 14 and 19-case self-tests recorded separately, not added to this count. |
| Read-only native source entry points | **6/6**, module and standalone in three languages; no remote probes or live repair. |
| Actual GUI / display | Three languages, basic/expert, synthetic reports, isolated profile, native 150%/144 DPI and narrower window during the GUI fixes. Final additional WFP guard has real-Tk tests; its extra native visual check failed at the automation helper and is **NOT TESTED**. Other native scales and OS light/full app dark coverage **NOT TESTED**. |
| Publication audit / history / licensing | Exact proposed manifest and original/local history reviewed with bounded automated patterns plus manual image/notice review. Zero findings is not a guarantee of zero private data. Alden / MIT attribution preserved. |
| Final archive | Source-only, matching per-file manifest and standalone digest; extracted tests and deterministic archive checks supplied as owner evidence. No EXE, keys or real reports. |
| GitHub | Local clean review copy; no remote repository/push/tag/Release. Workflow checked statically; remote CI and repository settings not executed. |

The development repository retains its original staged foundation, prior changes and rollback references. A separate exact-tree local publication copy is the proposed first public snapshot; the owner's delivery records commit/tree and file digests. Do not bulk-push the development repository's refs or owner evidence.

## Remaining release boundaries

**NOT TESTED:** controlled WinINET dead-proxy injection/repair/API verification/connection-state update/restore, external-drift refusal on a real Windows configuration, UAC cancel/accept and alternate SID/HKCU, privileged WFP/overwrite, clean no-Python Windows 11 GUI/CLI EXE, Defender/SmartScreen, signing, native 100%/200% DPI, OS light/full application dark theme, other Windows/Python versions and remote GitHub Actions. No eligible authorized recoverable Windows VM is available; the daily workstation is not a substitute. No network/security setting was modified to produce acceptance.

Source ZIP acceptance must run outside another Git worktree because the current publication inventory can fail closed on an ignored parent-repository directory. This documented tooling limitation does not remove assertions or weaken the final package checks.

## Decisions reserved for the owner

Choose the GitHub account/repository URL and public Git/no-reply identity; review and approve the supplied exact source tree and its Alpha limits. Public author remains **Alden**, without a legal name/private email or guessed profile. The local review identity intentionally has no email pending that choice.

Choose whether to authorize private staging/remote CI before public visibility. A source-only branch with no tag is the boundary; a CI pass does not authorize EXE or formal Release. See the [About proposal](github-about.md) and [publication steps](source-alpha-publication.md).

If binary distribution is wanted later, authorize a disposable recoverable Windows VM and complete the controlled matrix before any gate decision. Until then `formal_release_ready=false`; do not create/publish a repository, push, tag, Release or EXE without explicit approval. Stop after this closeout; no F8/F9 or other feature expansion.
