# Validation archive and current 2.2.0a3 status — 2026-10-25

**Formal release remains blocked.** This document retains historical results by revision; the table immediately below describes historical 2.2.0a1 work, not the current release. The historical maintainer machine was Windows 11 x64 build 26200, Python 3.12.14 and Windows PowerShell 5.1. For current 2.2.0a3 evidence, see the final section and [Source Alpha publication](source-alpha-publication.md).

| Level | Actual evidence |
|---|---|
| Fresh pre-extension baseline | 270 passed; current working source preserved under a separate rollback reference |
| Full final regression | **318 passed**, including unchanged independent 14 and 48 additional extension/build/integration cases |
| Independent original script | **14 passed** separately; bytes match both original test and attachment reference |
| Embedded tests | **19 passed** through modular source, generated source and both candidate EXE entry points |
| Pure module/standalone parity | DNS/Fake-IP, ping semantics, card privacy/length, exact three-language help, existing reports/snapshots/scenarios |
| Native entry points | Three languages through module, standalone and CLI EXE, local-only collectors; per-run source digest and candidate BUILD_INFO checked |
| Native inventories | 18 adapters, 45 routes, 175 bindings; zero core proxy/route/security query errors. Optional NDI metadata has explicitly recorded restricted entries |
| Native GUI | Owned unsigned candidate startup and local audit inspected; new controls visible; preview-first card 238/500. Clipboard not modified; copy callback tested using mocked clipboard |
| Native transport example | One explicitly selected public target; IPv4 HTTP responded, IPv6 DNS unavailable; Fake-IP classification retains uncertainty where ownership/path evidence is missing |
| Native ICMP | Actual Windows DF ping, 1200/1472 payloads, Chinese CP936 output parsed as replies. This is command/pipeline evidence, not a physical path-MTU or black-hole proof |
| Packaging | Explicit source manifest, deterministic standalone/source ZIP, extracted-source regression, matching candidate source SHA-256 and per-file checksum verification |
| GitHub CI/release | Prepared and statically checked; official Action commits verified. **No remote runner, push, release or attestation executed** |

Do not add the separate 14-test run to the 318 unique full-suite cases; it is intentionally overlapping acceptance. The 19 embedded cases are a separate runtime check. Negative tests include expected rejection paths without weakening assertions.

Mock coverage includes healthy Fake-IP, abnormal core exit with target-route/TCP failure, valid private DNS, local listener present/absent/unknown, target-specific routes, explicit fragmentation feedback, ICMP silence, permissions, cancellation, hostile sharing text, real 500-character bounds, GUI confirmation/worker/clipboard flow, and checksum/import/permission failures.

Still unverified: real WinINET mutation/restore, controlled healthy/abnormal proxy exit on Windows, controlled fragmentation/ICMP blocking and TLS cause, actual UAC cancellation/elevated WFP, clean Windows VM EXE, Windows 10, other Python versions, remote CI, code signing and build attestation. No existing working-network/security configuration was changed. Isolated GUI preferences protected the user's actual app settings.

Final machine logs are private under `.local_validation/extensions_20261025/`; the delivery includes full test outputs and aggregate native summaries. Intermediate runs are not final acceptance. See [itemized report](extensions-2.2.0a1.md) for commands, file mapping, behavior and limits.

## Subsequent unreleased source review patch

The historical Windows 318-test results above belong to the original 2.2.0a1 candidate.
An incremental Gemini-based source-only patch was independently run on Linux: **340 collected; 315 passed, 25 platform skips, no failures or errors**. It has **not** been Windows-revalidated, and existing EXEs have not been rebuilt. [Patch notes](audit-gemini-2.2.0a1-reviewfix.md).

## Historical Windows 2.2.0a2 combined review

The 318-case Windows baseline and 387-case external Linux logs preceded this a2 revision. Its Windows suite passed **398/398**, with no skips; independent 14/14 and module/standalone self-tests 19/19 passed separately. These are historical a2 results. See [full integration evidence](combined-review-2.2.0a2.md). Formal release remains blocked.

## Historical 2.2.0a3 F5/F6/F7

The previous 398-case a2 report is historical. The current full Windows regression is 458 cases, including 60 new contracts; immutable independent 14 and 19-case embedded tests remain unchanged. See [exact current evidence and limits](f567-2.2.0a3.md). Reopened Tk and native loopback failures discovered during development are retained as intermediate evidence. No live network/security settings were changed; formal release remains blocked.

## Independent source-alpha documentation preflight (2026-10-25)

The 2.2.0a3 **provided source ZIP**, not a live GitHub checkout, was extracted into a fresh Linux workspace. The independently executed current suite collected **458 cases: 423 passed, 35 skipped (Windows-only), zero failures/errors**, plus **19/19** embedded self-tests. `scripts/build_standalone.py --check` and `scripts/publication_audit.py` passed on the provided baseline source (135 files; zero audit findings). These are **Linux/source checks** and are not Windows native acceptance.

Codex's separately provided delivery statement reports **458/458 Windows tests** and native protocol/GUI checks. Original, complete Windows per-test logs, Git review bundle and controlled repair/clean VM artifacts were not present in the two source/candidate ZIP attachments reviewed here. Thus the maintainer report is **not independently re-executed** by this documentation preflight. Do not add historic tests across versions to the current count. The actual program implementation is unchanged by this documentation-only revision.

No GitHub push, tag, Release, remote Actions execution, controlled WinINET write/restore, UAC or clean VM testing was performed during this preflight. `release-gate.json` remains blocked.

## Historical pre-repair Windows Source Alpha acceptance — 2026-10-25

This is a fresh execution on the authoritative Windows 11 x64 build 26200 worktree, Python 3.12.14, PowerShell 5.1. It is separate from both the preceding F5/F6/F7 execution and the external Linux documentation review. Runtime, tests and build/workflow code were preserved. Standalone SHA-256 remains `a753486ad00b8341ce8a0c37959b03196edbc2cf8f27657d7d812b240b7a38af`.

| Check | This round |
|---|---|
| Full Windows regression | **458/458 passed; no skips** |
| Independent immutable regression | **14/14 passed** separately; overlaps the full suite |
| Modular and generated-source embedded self-tests | **19/19 each** |
| Generated source consistency | Passed, same source digest |
| Local-only entry points | **9/9**: module, standalone and existing matching CLI candidate, each in three languages; zero remote probes and no core inventory errors |
| GUI visual check | Actual matching GUI candidate; isolated preferences; first startup, basic/expert views, three languages, local-only scan/cancel and redacted-export choice/Save As cancellation |
| Native display coverage | Actual **150% (144 DPI)**, OS dark setting with the application's light interface and readable dark native Save As dialog. Native 100%/200% and a full dark application theme **NOT EXECUTED** |
| Controlled repair and clean Windows VM | **NOT EXECUTED**: no eligible authorized recoverable Windows VM available |
| Formal release gate | Expected blocked exit; `formal_release_ready=false` |

The existing unsigned GUI/CLI candidates were reused only after source-digest and checksum verification; this documentation-only round did not rebuild or redistribute EXEs. A daily Windows host is not a clean VM. No live proxy, driver or security setting was changed; no UAC elevation, raw WFP export, public upload, repository creation, push or tag occurred.

The supplied owner evidence directory contains original per-test outputs, commands, environment/source binding, nine-entrypoint summary, public-safe GUI images and the explicit not-executed matrix. Raw local inventories, keys, VM configuration and unrelated desktop screenshots are excluded from the source package. Remaining usability observations and source-publication conditions are in the [readiness record](source-alpha-readiness.md). Zero automated privacy findings do not prove absence of all sensitive information.

## Current final GUI repair acceptance — 2026-10-25

This round changes the authoritative modular GUI/catalog and the cancellation-layer guard, preserves the existing diagnostic/repair architecture, and regenerates the single file. Earlier a3 logs with source `a753…` are historical; existing EXEs no longer match the updated source. Current SHA-256 is `e4b0dee1dfce0129461f258139248758b10915a4f1178a17c1ecbc11237b3db8`.

Fresh Windows full regression passes **476/476, zero skips**, with 18 targeted GUI-01/02/03 contracts. Current module and standalone local-only entry points pass **6/6** in three languages with no remote probes. Independent immutable 14 and embedded self-tests are separate overlapping checks in the final owner evidence. Actual current-source GUI was visually inspected with isolated settings and synthetic reports, including native Return/Escape/window close, default export/cancel, three languages, basic/expert, scan cancel/restart and narrower window. See [full current behavior and limits](gui-final-2.2.0a3.md).

Native 100%/200% DPI, OS light mode, complete app dark theme, controlled WinINET/UAC/WFP, clean Windows VM, new EXEs, signing and remote Actions are **NOT TESTED** this round. Only existing native 150%/144 DPI was visually checked. No real network or security configuration changed; no GitHub publication occurred. Formal Release Gate remains false.

Native screenshots/inputs in this repair round bind to the intermediate `f514…` source, before the final identical-consent extension to raw WFP. Current final Tk automated tests cover that extension, but a last extra native visual attempt failed with `failed to activate captured window` after the permitted retry. That specific final-path native check is **NOT TESTED**; see the precise [GUI evidence scope](gui-final-2.2.0a3.md).
