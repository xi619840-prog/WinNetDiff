# Roadmap and unfinished work

The first public version is a preview. Stability, truthful evidence, privacy, and recovery are release gates; extra probes must not weaken those gates.

## P0 — public-review foundation

Maintain strict Windows decoding, same-socket stage measurements, complete/unknown inventory semantics, orphan-candidate false-positive controls, three-language UI and README guidance, synthetic regressions, MIT provenance, publication audit, and a Windows CI matrix. Run CI after the owner creates and pushes the reviewed repository; local workflow syntax is not a runner result.

## P1 — practical desktop use

Validate snapshots and comparisons across more real network transitions without distributing those private reports. Exercise reversible proxy repairs and conflicts on a recoverable test account/VM. Verify unsigned GUI/CLI EXEs on a clean Windows 11 x64 VM, including offline startup, language/profile persistence, high-DPI behavior, and normal user-cancelled UAC. Consider code signing only after an owner-controlled release process exists.

## P2 — deeper evidence

Investigate richer WFP provider/filter/callout ownership, relevant Windows network events with time windows, non-destructive MTU checks, captive-portal or campus-authentication observations, resolver-specific comparisons, and explicit HTTP versus HTTPS checks. Each addition needs applicability conditions, counterexamples, bounded work, and a privacy review. Do not infer Windows-update causation merely because an update preceded a failure.

## Explicit current limitations

No universal root-cause proof, automatic driver cleanup, generic WFP editing, or permanent IPv6-disable recommendation is planned. Portable or enterprise software can be absent from uninstall registration. Manufacturer uninstall parameters require version-specific confirmation. A configuration API success alone does not prove network recovery, and stage timing differences across changing CDN IPs need cautious interpretation.

## Implemented in the 2.2.0a3 candidate

F5 generic host associations and bounded historical WFP key input, F6 static proxy-path interpretation/explicit HTTP CONNECT diagnostics, and F7 per-scan same-IP retries with explicit DNS rotation are implemented. Enterprise automatic authentication, PAC execution, HTTPS/SOCKS proxy transports and universal live WFP ownership remain outside this candidate. Controlled VM recovery and clean EXE acceptance are still release gates.
