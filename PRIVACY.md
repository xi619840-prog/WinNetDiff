# Privacy and local data

WinNetDiff is offline-first, needs no account, and has no telemetry or report-upload endpoint. The public author name is **Alden**. The source tree does not include a legal name, private email, real device report, or unconfirmed GitHub profile.

## Data flow

An explicitly started scan queries local Windows proxy settings, environment variables, adapters, routes, DNS configuration, bindings, service/driver inventories, installed application registrations, security providers, and available file-signature metadata. It may inspect loopback proxy-listener ports and their owning process. These observations remain in memory until the user exports a report, saves a snapshot, or confirms a repair that requires a journal.

Network mode resolves and connects to the displayed user-selected public domains using native sockets and verified TLS. Those destinations and the user's DNS/network providers can observe ordinary connection traffic, including the client IP and requested host. These probes are functional tests, not telemetry. Local-only mode skips remote probes but still permits loopback listener checks. The tool does not download or execute PAC scripts.

## Saved data

Normal GUI JSON, Markdown, history and snapshot exports are redacted directly. Full output is a separate **Full data…** action: choose a format, acknowledge the risk, then deliberately activate **Export full data**. The action starts disabled and acknowledgement is reset for every export. Enter, Escape, Cancel and window close do not authorize full output. Full mode is never saved as a preference. CLI reports, snapshots and renderer APIs also redact unless explicitly given their full-output option. Redaction covers known credential, token, username, private-path, address, and identifier fields, including opaque raw-byte fields. This is a best-effort transformation, not a promise that a report is safe to publish: software, service, domain, adapter, and rule names may themselves be sensitive. Inspect the exported file before sharing.

Full reports can contain IP/MAC addresses, computer names, installation paths, driver information, network configuration and credentials. They require explicit consent and private local storage. Raw WFP XML is always treated as sensitive; its export uses the same fresh acknowledgement and explicit-action dialog, locked to the WFP XML format. It may contain program paths and large numbers of local network rules. The application keeps parsing bounded summaries and does not automatically upload the XML.

Repair snapshots and journals retain original values so they can be restored. They are private, unencrypted local files protected for the current Windows user and SYSTEM. Do not attach the `repairs` directory to an issue. If other programs have changed the current configuration, restoration refuses to overwrite a conflicting state.

CLI output options and repair storage select their respective local destinations; GUI Save As determines the final export file. The GUI checks that its initial folder exists. If it is unavailable, the user must choose an existing folder before Save As opens; it does not silently use the working directory. Cancelling writes nothing. The selected parent is checked, overwrite requires explicit confirmation with No as the default, and write failures are reported. Atomic file publication still protects an existing file if a write fails. Always review the final path before saving, especially from a source checkout. Application language/profile preferences are local settings. Local development validation is written under ignored `.local_validation/`. The Git source tree excludes results, snapshots, journals, WFP dumps, virtual environments, and build outputs by default. Ignore rules do not remove files that were already committed.

## Deleting and sharing

Close the application before deleting local exports, snapshots, or preferences. Keep any backup needed for a pending restoration until the result has been reviewed; deleting it removes that recovery option. Deleting a report does not change Windows network settings or erase copies someone else already received. Git history can retain accidentally committed data, so prevent publication rather than relying on later deletion.

The publication audit is a local preflight for obvious private files and credential patterns. It never prints matched secret values or sends content out of the machine. It cannot replace manual review of the exact staged diff, archive, and release assets.

## 2.1.0b2 classification policy

`core/privacy.py` is shared by JSON, Markdown, summaries, repair guidance, snapshots, diffs, GUI exports and CLI exception output. Private identity/SSID/profile fields are removed; opaque identifiers support comparisons on the same installation (they are HMAC-SHA256 pseudonyms under a random per-installation key, see below); all three MAC formats and known local user/computer names are masked. Custom absolute paths retain a useful basename. Version fields (`DisplayVersion`, `version`, file/product versions) retain dotted semantic versions, and numeric timings remain numeric. Structured evidence strings and JSON fragments in prefixed errors are parsed before sanitization. Bearer/Basic headers and quoted secret values are masked as complete values.

Local live inventory tables can display the user's actual names for diagnosis. A full private export is a separate explicit choice; the default exported evidence uses the shared policy. Unknown arbitrary third-party text can contain sensitive meaning, so inspect before sharing. Original audit materials and real machine logs stay in ignored local validation storage; the public source package includes only synthetic regressions and reviewed aggregate findings.

## Compact sharing card

The public-card generator does not concatenate arbitrary report/device/Finding/host/error text and then rely on regex. It selects predefined layer/state/hypothesis enums, a validated version and bounded numeric timings. Domains, IP/MAC/SSID, usernames, paths, URLs/tokens and raw diagnostics are excluded by construction. Unknown values fall back to unknown or are omitted. The final compact Markdown length is checked against 500 characters. GUI preview and a separate copy action precede clipboard changes. CLI --share-card prints the minimized preview without uploading or touching the clipboard; file/progress notifications stay out of card stdout. Card creation does not write a separate log.

Optional DNS-core/listener inventories stay local and describe known process names, not proof of all possible proxy software. ICMP auxiliary results include raw command output in private/full evidence; ordinary exports use the shared privacy policy, and cards never use that output.

## Pseudonym key (2.2.0a2 candidate)

IP addresses, MAC addresses, interface GUIDs and snapshot entry IDs in redacted output are keyed HMAC-SHA256 pseudonyms. The 32-byte key is random, created on first use at `%LOCALAPPDATA%\WinNetDiff\pseudonym.key`, never uploaded, and never overwritten; an unreadable or malformed key file is left in place and that run uses a temporary key. Earlier versions used an unkeyed SHA-256, which anyone can reverse for private IPv4 ranges or a MAC address with a known vendor prefix by trying every candidate, and which gave every user with the same address the same token.

Within one installation the same value still maps to the same token, so reports and snapshots from that installation can be correlated with each other. Tokens normally differ across installations; software inventories and other visible fingerprints can still link reports. Anyone holding the key file can reverse tokens by enumeration, so treat it like the other private local files. Deleting it makes earlier snapshots incomparable with new ones; the comparison then refuses instead of reporting every entry as changed. `--self-test` and the test suite use in-memory or temporary keys and never touch the installation key.

The Windows key file is created with a protected DACL granting access only to the process user and SYSTEM. The complete, flushed file is published by an exclusive same-volume rename. Reads check ownership and the DACL on the same handle as the content. Existing keys with inherited/broad permissions, malformed contents or inaccessible storage are left untouched; the process uses an ephemeral key, so snapshots from later sessions may refuse comparison. Administrators with takeover privileges are outside this local-file confidentiality boundary. Tests use temporary paths, including real six-process creation races and insecure-file rejection; actual user key/configuration files are not created during validation.

Markdown dynamic text is escaped and code fences exceed every embedded backtick run. GFM URL autolinks are neutralized; email-like strings contain a zero-width space after @ to prevent GFM auto-linking. JSON remains the lossless export format. This formatting protection is independent of privacy filtering.

## F5/F6/F7 (2.2.0a3)

New ownership graph IDs and WFP keys, structured proxy endpoint DNS names, and new WinHTTP API proxy/bypass strings use the shared HMAC policy. Dynamic names/paths are not translated. Arbitrary legacy command text and software fingerprints can still reveal internal information; review before sharing. The minimized card still excludes all graph/proxy raw data. Proxy testing never sends credentials or downloads PAC. Its target hostname is visible to the explicitly selected proxy; only verified target TLS precedes HEAD. A temporary test certificate is trusted only inside the controlled test process, not the system store.
