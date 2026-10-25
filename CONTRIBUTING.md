# Contributing

WinNetDiff is maintained under the public author name **Alden**. A GitHub profile and repository URL will be added after they are confirmed. Do not infer a private contact address from local files.

Start with a concrete failure and the evidence that would distinguish it from another explanation. Add synthetic fixtures and a regression test before changing a diagnostic rule. Include a normal third-party-component case so that a vendor name cannot become the diagnosis. Keep GUI text available in English, Simplified Chinese, and Traditional Chinese; target profiles and custom domains are separate from UI language.

## Local setup

Use Python 3.10 or newer. Source execution needs no pip installation. Keep local reports, snapshots, repair journals, captures, and build environments in ignored directories. Never copy an actual user's report into a fixture, even if a redactor has processed it; create a minimal synthetic example instead.

```powershell
py -3 scripts/build_standalone.py
py -3 scripts/build_standalone.py --check
py -3 -m unittest discover -s tests -v
py -3 windows_net_diffdiag.py --self-test
py -3 scripts/publication_audit.py
```

Edit modular source under `winnetdiff/`. The root `windows_net_diffdiag.py` is generated for users who need a single-file program. Include the regenerated file in the same change. Windows-specific collectors must preserve errors and completeness; an access-denied result is not an empty successful inventory.

## Review expectations

Source Alpha closeout is a feature freeze. Limit changes to reproducible defects and release preparation; do not add new probes, vendor adaptations or broad refactoring. GUI export changes must retain the Enter/Escape/window-close denial tests, default redaction, deliberate save-folder selection, overwrite/failure integrity, and cancellation/restart contracts in `tests/unit/test_source_alpha_gui.py`. Run actual Tk tests on Windows and record native DPI coverage separately from simulated geometry or mocks. Use only synthetic reports for GUI screenshots.

Describe the trigger, changed behavior, and meaningful validation. State whether a test was mocked, run on a Windows CI runner, visually checked on Windows 11, or used an actual system-modification API. Do not turn simulated repairs into a claim of real rollback validation. New mutating operations require explicit targets, an original-state backup, a confirmation preview, conflict checks, post-change validation, and a recovery plan. If reliable rollback is unavailable, default to read-only guidance.

CI changes must avoid privileged fork execution, use minimum token permissions, and pin reviewed Actions to full commit SHAs. A maintainer should re-resolve the official tag and review release notes when updating a pin. Build tools belong in the build environment, not application runtime dependencies.

Contributions are submitted under the repository's MIT License. Do not add proprietary vendor code, redistributable drivers, downloaded cleanup utilities, or trademark artwork without documented permission. See [licensing provenance](docs/licensing-provenance.md) and the [code of conduct](CODE_OF_CONDUCT.md).
