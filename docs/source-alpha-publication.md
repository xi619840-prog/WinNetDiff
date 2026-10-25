# Source Alpha publication — 2.2.0a3

**Status: prepared locally; NOT published.** This checklist concerns public source-code review, not a Windows binary release. The owner must explicitly approve the exact Git tree and destination before any remote push. No instructions in this file authorize the assistant or an agent to publish.

## Separate decisions

| Distribution | Current state | Requirement |
|---|---|---|
| Public source tree on a GitHub branch, without a version tag | **Conditionally prepared; pending owner approval** | Reviewed exact tree, license/privacy inspection, local source tests; remote CI still pending |
| Standalone `.py` in the public source tree | **Source review only** | It is code, not a formally validated repair utility; warn users about untested live repair |
| Public unsigned Windows GUI/CLI EXE download | **Blocked** | Controlled real proxy write/restore; clean Windows 11 VM and owner approval |
| Git tag / GitHub Release | **Blocked** | `scripts/check_release_gate.py` requires digest-bound controlled evidence; the current tag workflow intentionally fails while the gate is false |

`release-gate.json` currently says `formal_release_ready=false`; DO NOT change that value based on unit tests, local audits, or documentation work. The source branch can be public as a clearly labelled Alpha review **only after owner approval**, without creating a tag or Release. The reviewed source includes an explicitly confirmed proxy-repair path which has **not** been validated in a controlled Windows VM; reviewers should not test it on production or critical systems.

## Before the owner authorizes the first public push

1. Review every file and the **actual staged tree**, not just an earlier ZIP. Check personal names, hostnames, usernames, project directories, SSIDs, raw network reports, keys, Git history, and third-party licenses. `scripts/publication_audit.py` is limited, not a complete secrets scanner.
2. Confirm public author `Alden`, MIT copyright and third-party notices. Supply the public GitHub repository URL only when the owner selects it; do not guess a username or address.
3. From the reviewed source tree run:

   ```powershell
   py -3 scripts/build_standalone.py --check
   py -3 -m unittest discover -s tests -v
   py -3 windows_net_diffdiag.py --self-test
   py -3 scripts/publication_audit.py
   ```

4. Record platform and results. Read-only evidence and mocks are not equivalent to Windows 11 VM acceptance of UAC, proxy mutation and rollback, WFP export or EXE behavior.
5. Explicitly review README screenshots, public issue templates, `PRIVACY.md`, `SECURITY.md`, license provenance, and false-positive language. Do not publish private keys, raw WFP XML or repair journals.
6. Enable and verify private vulnerability reporting when GitHub offers it for the public repository; configure repository branch rules, required CI, and dependency/security settings appropriate to your account. These are owner-side UI settings, **not** guaranteed by committed workflow YAML. See https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository

The [final local readiness record](source-alpha-readiness.md) lists current evidence. GUI-01/02/03 have now been repaired and revalidated; native DPI and controlled VM limits remain explicit. The owner must approve the exact source tree, identity and destination before public source review. Remote Actions cannot be claimed before an authorized remote exists: an approved private staging repository is an option for obtaining CI evidence before making source public. The current CI push trigger covers `main`; other approved source branch names require an authorized pull request or manual `workflow_dispatch`.

## Owner-approved source-only publication path

**Only after an explicit owner decision on the destination and files**:

- Create or choose the repository under the owner's GitHub account. Keep its visibility private until the final review is complete, if preferred.
- Confirm Git author identity uses an approved public handle / GitHub no-reply email, not a private email.
- Inspect `git status`, `git diff`, `git diff --cached --name-status`, tracked and untracked files. Source only; exclude generated Windows EXEs, local logs and keys.
- Push the reviewed source branch to the chosen remote after owner approval. **Do not tag or create a GitHub Release at this stage.**
- Let Windows CI run, inspect its exact logs, and record this as CI evidence only. Do not declare all 458 Windows tests independently reproduced until the relevant logs are available for review.
- Keep the release gate blocked; an Alpha source branch and a verified distributable binary are distinct milestones.

## Controlled Windows acceptance for a later binary release

- [ ] Real WinINET proxy enable → repair → verify → restore in a disposable, recoverable Windows environment.
- [ ] Confirm spontaneous proxy configuration changes are not overwritten by restore; check alternate-account UAC/HKCU behavior.
- [ ] Test UAC cancellation/acceptance and elevated WFP XML export in a recoverable environment.
- [ ] Clean Windows 11 VM (without Python) launch of the **exact newly built GUI and CLI EXEs**, inspect GUI at multiple DPI scales, review SmartScreen/Defender reaction.
- [ ] Review original Windows test logs, candidate EXE digests, source/build parity, dependencies, code-signing state and publisher identity.
- [ ] Decide whether an unsigned candidate is appropriate even as a prerelease; provenance attestations are not code signatures.
- [ ] Obtain owner sign-off before changing `release-gate.json`; gate fields must describe actual controlled evidence for the exact version and source digest.

Do not move to `git tag v2.2.0a3` or draft/public releases merely because source-alpha CI passes. See [formal release checklist](release-checklist.md) and [validation history](validation.md).
