> Historical reviewer record supplied with the combined review. Claims about unkeyed hashes, no Windows retest and old EXEs describe that reviewer stage. Current 2.2.0a2 evidence is in combined-review-2.2.0a2.md.

# WinNetDiff 2.2.0a1 — Gemini incremental review patch (unreleased)

This is an **unreleased source-only review patch**, not a Windows binary release.
The original `2.2.0a1` version identifier and `formal_release_ready=false` gate
are deliberately unchanged. Earlier Windows EXE candidates must not be treated
as built from this modified source tree.

## Changes

1. `analysis/evidence.py`: accept independently observed **running** orphan
   services/drivers without insisting on NDIS binding. Require completed
   uninstall/service inventories and completed runtime enumeration; preserve
   `OwnerApps`, actual registration, and shared-component safeguards. A related
   installed Surfshark/Avira product blocks an automatic shared-OEM orphan
   inference. E3 remains **corroboration, not cause or kernel-deadlock proof**.
2. `core/privacy.py`: separate quoted and unquoted Windows paths; prevent
   free-text path matches from swallowing a later filename; withhold private
   directory leaf names in structured and free-text output. Only recognized,
   unambiguous file basenames remain visible.
3. `core/engine.py` and `analysis/rules.py`: consistently sort by severity,
   then priority; confirmed dead-proxy findings have explicit priority zero.
4. `collectors/dns_audit.py`: normalize PowerShell `ServerAddresses` scalar
   and list shapes. If a Fake-IP destination has no usable target route,
   record *configured* DNS on active interfaces, without claiming these DNS
   servers actually answered the query.
5. `collectors/security.py`: bound PowerShell encoded file-inspection batches
   to 25 entries **and** a conservative encoded payload size; record missing
   responses as unknown, preserve cancellation and partial-error evidence.
6. `core/messages.py`: do not format brace-containing messages without params.
7. `winnetdiff/cli.py`: isolate platform policy behind a mockable function;
   mocked CLI tests no longer tamper with Python's global `os.name`.
8. Existing evidence tests updated to distinguish running-orphan evidence from
   mere labels; 21 new P0/P1/P2/P3 synthetic regression tests added.

## Independent execution in the review container (not Windows)

- Baseline archived 2.2.0a1: 318 collected, **7 failures + 1 error**, 25
  platform-dependent skips on Linux. This chiefly reflected the CLI platform
  guard being reached before mocked scan paths.
- Patched: **340 collected; 315 pass, 25 skip, 0 fail, 0 error**.
- Additional synthetic incremental tests: **21/21 pass**.
- Both modular and generated standalone embedded self-tests: **19/19 pass**.
- Deterministic single-file `scripts/build_standalone.py --check`: pass.
- Local `scripts/publication_audit.py`: pass; manual review still required.

These results are not independent Windows 11 verification. The Codex Windows
318-test report remains historical evidence for the unmodified release, not
acceptance evidence for this patch.

## Deferred decisions / release blockers

- No Windows 11 real driver enumeration or controlled proxy mutation was
  executed by this review. Run the full suite on Windows 11, verify physical
  service/driver inventory, UAC, WFP and GUI, and test proxy restore in a
  disposable VM before distributing EXEs.
- Default privacy `_opaque()` still produces unsalted SHA-256 truncated markers;
  small-domain IP/MAC identifiers can be enumerated and correlated across
  public reports. Design a locally keyed anonymization and threat-model impact
  on snapshot comparisons before promising robust anonymous sharing.
- Directory names are concealed by the added rules, but arbitrary free-form
  command output is difficult to anonymize perfectly; further negative privacy
  tests and independent red-team review remain necessary.
- `release-gate.json` remains blocked, and the original Windows EXEs have not
  been rebuilt from patched sources.
- No service, firewall, registry, driver, Wi-Fi binding, DNS, or MTU setting
  was changed by this review; all collector behavior was synthetic/mocked.

## Verify on Windows 11

```powershell
py -3 scripts/build_standalone.py --check
py -3 -m unittest discover -s tests -v
py -3 -m unittest tests.unit.test_gemini_round_2_2 -v
py -3 windows_net_diffdiag.py --self-test
py -3 -m winnetdiff --self-test
py -3 scripts/publication_audit.py
py -3 windows_net_diffdiag.py --cli --no-network
```

The final command invokes **read-only local collectors** and may take seconds;
it must be run only on a machine whose owner consents to system inventory.
High-risk repairs and driver removals remain manual and are not part of this
validation. Do not advance the release gate without external evidence.
