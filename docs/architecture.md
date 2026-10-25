# Architecture

WinNetDiff has modular development source and a generated single-file distribution. Both CLI and GUI call the same diagnostic engine. The generated program is checked for consistency in CI; edits belong in the modules, followed by `scripts/build_standalone.py`.

| Package | Responsibility |
|---|---|
| `core` | Models, configuration, language/profile settings, Windows/process boundaries, scan orchestration, snapshot schema |
| `collectors` | Read-only proxy, route/DNS/binding, service/driver/application/security inventories and WFP export |
| `probes` | Bounded DNS, one-connection TCP/TLS/HTTP stages, retries, cancellation and transport evidence |
| `analysis` | Explainable diagnostic rules, evidence grades, scenarios and before/after verification |
| `repairs` | Explicit eligibility, durable original-state backups, API changes, verification, journals and conflict-safe restore |
| `reports` | Structured evidence, privacy transformations and readable exports |
| `gui` | Tkinter views, translated prompts, background dispatch and main-thread queue updates |
| `cli.py` | Argument compatibility, locale/profile selection, report/snapshot actions and exit codes |

Collectors return both observations and query status. Complete-empty and failed/unknown are different states. Privileged and localized Windows interactions are isolated behind replaceable boundaries; tests replace commands, registry calls, sockets, and mutation APIs with mocks. The core analysis does not import Tkinter.

Each endpoint attempt records the resolved IP and independent connect, handshake, and response durations. DNS is measured before socket creation. Each TCP/TLS/HTTP attempt uses one connection; retrying is a new attempt and its results remain visible. The resolver uses a bounded number of daemon workers because the system `getaddrinfo` operation has no portable cancellation API. Different host/address-family pairs are measured concurrently (at most `PROBE_CONCURRENCY` = 6 pairs; attempts within one pair stay sequential), so the network phase takes about as long as its slowest pair rather than the sum. Results keep the requested host order with IPv4 before IPv6. Probes waiting for one of the four resolver slots do so within their own DNS budget; that wait is excluded from the reported DNS time, and `DNSBusy` means no slot freed in time. Concurrent pairs share the client link, so absolute timings can differ slightly from a strictly sequential run; phase budgets and attribution remain explicit; grades still require the same recorded measurement path.

GUI work that can block runs in a worker. A queue carries progress, results, and errors to the Tk main thread. A cancellation request prevents new work and takes effect at bounded command or socket boundaries; it cannot forcibly terminate a system DNS call. Repair operations are serialized and must complete their durable records before ordinary window closure.

Snapshots are data, never executable instructions. Version/type/size checks precede comparisons. Stable entity identities support joins; privacy mode and schema compatibility constrain whether two files can be compared. Translated display strings do not replace stable rule codes, stage names, IDs, or raw OS evidence.

The audit repair adds `core/messages.py` for exact parameterized messages, `core/privacy.py` for one export classification policy, `core/atomic.py` for complete-file publication and `analysis/evidence.py` for shared context-aware grades. Optional NDI metadata has separate errors and never replaces core route-query status. `release-gate.json` binds controlled evidence to the package/runtime version and deterministic standalone digest; ordinary CI cannot override missing controlled Windows validation.

`collectors/dns_audit.py` supplies optional local DNS/core/listener context and pure destination-route analysis; `analysis/dns_rules.py` creates conservative Findings. `probes/pmtu.py` is a separately consented bounded auxiliary operation. `reports/share_card.py` is a pure allowlist projection with no raw strings/clipboard/network dependency. `core/extension_catalog.py` provides exact three-language messages. The builder refuses unsupported scoped app imports rather than silently removing them and never deduplicates standard imports across intervening code. `scripts/checksums.py` strictly matches each artifact filename/hash and rejects omissions/traversal/duplicates.

External programs are started only through `core/process.py::run_command`. On Windows a bare program name must be on a short allowlist and is resolved to an absolute path under `GetSystemDirectoryW()`; anything else is refused as an incomplete query. This prevents a same-named executable beside a downloaded EXE, or in the working directory, from being run (and run elevated after the UAC relaunch).
