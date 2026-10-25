# Safety and rollback model

Initial startup and ordinary scans are read-only. They do not silently elevate, reset adapters, disable filters, delete drivers, remove WFP rules, modify antivirus-provider registrations, or upload data. Administrator access is requested through normal Windows UAC only after an explicit user action. Cancelling UAC must preserve the existing window and data.

## Risk classes

| Class | Examples | Program behavior |
|---|---|---|
| Reversible, constrained configuration | Confirmed dead HKCU manual proxy; restoring that exact tool backup | Preview, confirmation, durable backup, reread, execute, verify, journal, then same-parameter diagnostic comparison |
| Transient but not faithfully reversible | Clearing the DNS cache | Manual guidance by default; old cache entries cannot be restored reliably |
| Potential connectivity interruption | One identified adapter binding or temporary network parameter | Expert preview and explicit manual review; no generic automatic execution |
| High impact | Stopping/deleting a security driver, deleting `.sys`, WFP rules, or SecurityCenter WMI records | No universal one-click button or automatic cleanup |

DNS cache flushing used to be an executable low-risk action in the local v2 tool. The public preview tightens this boundary because low operational impact does not make the previous cache contents recoverable.

## Proxy eligibility and transaction

Automatic proxy disable is limited to a complete, unmanaged, current-user manual configuration whose every entry points to an explicitly identified loopback endpoint that persistently refuses connections and has no listener evidence. A timeout, active listener, PAC configuration, remote proxy, policy restriction, incomplete query, or stale scan prevents automatic repair.

Before mutation, save original values, types, existence flags, connection bytes, WinINET flags, and user/machine binding. Persist a prepared journal entry. Only then call the constrained Windows API, reread state, and record the result. Failed or partially applied operations attempt recovery and retain a terminal success/failure/recovery-required record. The backup directory uses a protected local DACL; the files are not encrypted.

Restoration verifies the backup schema and user/machine identity. Already-original state is an idempotent no-op. A current state different from the expected post-change snapshot is a conflict and must not be overwritten. A prepared backup left by an interrupted operation is evidence for manual review, not permission to force a restore.

Configuration verification and network-effect verification are separate. After a supported repair, compare a new scan using the same domains and options. No improvement must be labelled unverified. Restoration may intentionally re-enable a proxy whose client is still stopped, so it requires its own confirmation.

## Expert investigations

For binding isolation, verify the single adapter and ComponentID, save Enabled state and exact identity, retain a local management path, and prepare the corresponding enable command. A wildcard in an adapter name must not expand into multiple targets. VirtualBox, Docker, Npcap, engineering software, and enterprise access clients are not cleanup targets merely because they are third-party components.

The historical `endpointprotection.exe uninstallSdk` command is not a universal repair. The tool may record it as an unverified expert candidate only. A maintainer/user must establish the product, file path, signature, supported version/argument, related services, current protection provider, and risk, then separately authorize any manufacturer uninstall. Record the actual exit code; a nonzero code is not success. This preview does not execute the candidate.

WFP export is read-only but can require elevation and disclose sensitive local rules. Keep the original XML private and stream a bounded summary in a worker. A vendor-name match does not establish fault or ownership.

## 2.1.0b2 restoration boundary

A proxy backup separates effective settings from private raw Connections bytes. Compare-and-swap includes API flags/strings, explicit registry effective values and applicable policy, while excluding raw blob counters. Supported WinINET per-connection options restore flags/server/bypass/PAC; archived blobs are never written. Both API and registry are checked after mutation. Registry/API disagreement blocks automatic repair. Recovery after an attempted mutation also refuses to overwrite external server/PAC/auto-detection/policy changes.

Durable phases are prepared, applied, verified, restore_started, restored and rollback_failed. A prepared/failed/already restored record is not offered as a successful last backup. An interrupted prepared intent remains available only for explicit, ownership-checked recovery if its expected semantic state matches. Atomic sibling files preserve existing journals on write failure. These safeguards have synthetic tests; actual Windows write/restore still requires a recoverable, separately authorized test environment. `release-gate.json` blocks formal release until that evidence and clean-VM EXE validation are reviewed.

## Optional extension boundary

Fake-IP range membership is a clue. Only actual matching TCP failure, completed usable-route checks and a completed known-core inventory can raise stale-mapping suspicion; unknown routes/permissions/budgets remain indeterminate. Configured private DNS alone never becomes a fault. The runtime core search can miss renamed/embedded implementations, and system resolver results do not prove which configured DNS server answered.

PMTU requires explicit consent and repeated same-IP IPv4 TLS evidence; ordinary scans never append it automatically. It sends at most four configured payload sizes and two attempts each, with a bounded overall time and cancellation between individually bounded commands (default two packets, default overall four seconds per target). Header estimates assume 20-byte IPv4 plus 8-byte ICMP headers. Fragmentation Needed demonstrates feedback arrival. Echo silence and TLS failures do not prove PMTUD black holes. There is no automatic MTU, MSS, DNS, driver, WFP or security mutation from these extensions.
