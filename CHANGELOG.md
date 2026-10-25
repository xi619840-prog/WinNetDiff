# Changelog

## 2.2.0a3 — final Source Alpha GUI repairs (unpublished, 2026-10-25)

- GUI-01: normal report/history/snapshot exports always redact. Full export uses a separate action, an unchecked risk acknowledgement and a disabled-until-acknowledged explicit export button. Enter, Escape, Cancel and window close cannot authorize full output.
- GUI-02: require an existing initial save folder or deliberate folder selection; report cancellation and save failures, retain explicit overwrite consent and atomic publication.
- GUI-03: distinguish Completed, Cancelled, Failed and Partial / Incomplete. Keep partial evidence, prevent overlapping starts, wait for worker exit and allow a fresh scan. Cancellation labels survive language switches.
- Add 18 targeted contracts with actual Windows Tk key/callback integration; full current suite is 476 cases. Regenerate standalone source; earlier unsigned EXEs no longer match this source. No new feature, remote publication or gate change. See [current GUI acceptance](docs/gui-final-2.2.0a3.md).

## 2.2.0a3 — generic hosts, enterprise proxy paths and pinned retries (2026-10-25)

- Add vendor-independent host associations using exact NDIS services, image/install paths, possible signed shared hosts and bounded historical WFP provider/callout/filter keys. Rebuild corroboration from observations and keep unknowns conservative.
- Read structured WinHTTP defaults and interpret static proxy, bypass, PAC and environment scopes. Add explicitly consented, bounded, credential-free HTTP CONNECT/TLS/HEAD diagnostics; distinguish 407, 403 and protocol phases without merging proxy/direct evidence.
- Default to same-IP retries; retain an explicit rotate option, full DNS answers, per-attempt context, settings/UAC propagation and parameter-aware verification.
- Fix reopened Tk resource collection on a background thread; preserve all prior safety repairs. Add 60 regressions and native loopback protocol/negative controls.
- Regenerate standalone and unsigned local candidates. Formal release remains blocked. See docs/f567-2.2.0a3.md.


## 2.2.0a2 — combined review candidate (2026-10-25)


- Strengthen WFP/OEM running-orphan corroboration without requiring NDIS bindings; preserve source completeness and installed-owner checks.
- Repair path redaction, severity order, DNS server shape/routeless association, PowerShell encoded-command batching, and brace-only message handling.
- Restore cross-platform mocked-CLI testability and add 21 synthetic regression cases.

- Start external Windows tools only by absolute path under the OS system directory; refuse other bare program names (search-order planting next to a downloaded EXE, including after UAC relaunch).
- Replace unkeyed SHA-256 pseudonyms with HMAC-SHA256 under a random per-installation key; record the key fingerprint in snapshots and refuse comparisons across keys or with older unkeyed snapshots. Self-tests and the test suite never use the installation key.
- Escape inventory text in Markdown reports and size code fences to their content, so evidence cannot close a block or add links, and redaction markers stay visible.
- Probe host/address-family pairs concurrently (bounded, order-preserving, cancellable); DNS lookups wait for a resolver slot within their budget and report resolution time without that wait.
- Let mocked CLI tests run on non-Windows hosts by relying on the scan engine's platform guard for the terminal path.



Integrated into the existing Windows repository after a 318-test baseline and preserved-index rollback. This candidate has 398 passing Windows tests (including 11 new joint regressions); the unchanged independent 14-test suite and both 19-case embedded self-tests pass.

Additional fixes protect Windows key-file ACLs and atomic publication, reject insecure existing keys, close resolver acquisition/cancellation races, keep DNSBusy out of DNS latency, classify cancellation after a bounded socket wait as cancelled, preserve brace-only messages during translation, and suppress GFM URL/email autolinks. The optional native QA helper uses actual loopback TLS silence and a controlled cmark-gfm renderer. No WAN speed improvement is asserted. Source, binaries and BUILD_INFO are regenerated; formal release remains blocked.

## 2.2.0a1 — optional diagnostics and release engineering (2026-10-25)

- Preserve all prior P0/P1 repairs and immutable 14-test acceptance. Existing work was retained under a separate pre-extension rollback reference.
- Add optional context-aware Fake-IP/DNS audit, target-specific longest-prefix/metric route selection, private/loopback DNS context and explicitly incomplete runtime observations.
- Add opt-in bounded IPv4 DF ICMP auxiliary probes, semantic English/Chinese ping parsing, cancellation boundaries and payload/estimated packet sizes. Fragmentation feedback never becomes a black-hole diagnosis.
- Add a preview-first compact sharing card with a strict field allowlist and measured 500-character cap; no automatic clipboard writes or upload.
- Preserve optional-audit state through language/profile changes and UAC. Extend atomic, confirmed GUI replacement to report/history/diff exports; CLI report saves now refuse existing evidence too.
- Fail closed on unsupported scoped/aliased/wildcard application imports in the explicit standalone manifest; preserve standard import order, validate generated source before source packaging and test entry-point parity.
- Verify every checksum filename/content; isolate release staging from source packaging. Separate readonly CI, build, attestation and explicitly requested draft jobs. Pin official actions/attest v4.

Local candidates are unsigned. Controlled proxy write/restore and a clean Windows VM remain required before formal release; the gate remains blocked. See the extension validation report.


## 2.1.0b2 — audit repair source preview (2026-10-24)

- Separate effective WinINET semantics from archived Connections blobs. Restore through the supported API, detect real endpoint/PAC/policy changes, verify API and registry, and guard failure recovery against external changes.
- Make repair intent, applied/verified state, restore and rollback failures durable; exclude failed/restored entries from recoverable-backup selection.
- Separate overall and stage deadlines, preserve same-connection measurement context and derive retry admission from configured budgets.
- Replace substring translation with exact message templates; preserve language/profile state, localize exports and cancellation, and atomically replace explicitly confirmed GUI evidence files.
- Share field-aware privacy across all export formats and snapshots; mask MAC/user/device/custom paths while retaining semantic versions and useful driver basenames.
- Bound optional NDI metadata enumeration, keep its errors separate from core route completeness, unify E1/E2/E3 around explicit destination/context and independent linked inventory, and distinguish shared SDK branding from installed products.
- Preserve the supplied independent 14-test script byte-for-byte; add modular and generated regressions, source packaging, CI acceptance and a blocking formal-release gate.

Actual proxy mutation/restore and clean VM EXE checks remain unexecuted. No new EXE or public release was produced. See [itemized repair evidence](docs/audit-repair-2.1.0b2.md).


## 2.1.0b1 — 2026-10-24

Prepared WinNetDiff for public review from the prior Windows network differential diagnoser. The public author and MIT copyright are **Alden**. No public repository or release has been created as part of this preparation.

- Split development source into core, collectors, probes, analysis, repairs, reports, GUI, and CLI. Preserve a deterministic generated standalone Python program and legacy CLI options.
- Add English, Simplified Chinese, and Traditional Chinese selection with independent configurable target profiles and custom-domain preservation.
- Add versioned snapshots, structured comparisons, evidence-graded scenarios, and before/after verification for supported reversible repairs.
- Separate basic and expert views, retain background workers and cancellation, and improve table access and language-aware prompts.
- Keep irreversible DNS-cache clearing manual by default. Continue to prohibit generic one-click kernel-driver, WFP, WMI, or adapter-binding cleanup.
- Add English and Chinese README files, privacy/security/contribution policies, synthetic examples, publication preflight, Windows CI, draft prerelease workflow, EXE build scripts, and checksum generation.

See [release notes](docs/release-notes.md) and [validation](docs/validation.md) for executed checks and remaining limits. New capability claims must be checked against the final source and test results before publication.

## 2.0 — prior local delivery

Established strict Windows command decoding, same-socket TCP/TLS/HTTP timings, active-proxy checks, complete route/binding audit, security-inventory completeness and orphan candidates, privacy-conscious exports, explicit UAC, and backed-up proxy repair/restoration. That delivery's private machine evidence is not part of this public source tree.
