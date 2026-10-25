# Frequently asked questions

## Does WinNetDiff need the internet?

The application can start and audit local Windows configuration without remote probes. Select local-only mode or use `--no-network`. Loopback proxy ports may still be checked. Remote reachability and stage timing require a connection to the displayed targets; a genuinely disconnected computer cannot measure a remote TLS handshake.

## Why do a browser and the native probe disagree?

Applications can use different proxy settings, PAC behavior, credentials, certificate stores, or private networking stacks. WinNetDiff's socket probes connect directly with SNI and certificate validation. Compare their results with the proxy and local configuration audit instead of assuming they exactly emulate the browser.

## Must I permanently disable IPv6?

No. An IPv4-only network can be functional. The report separates disabled IPv6, absent route/address information, TCP failure, and TLS failure. Test the actual path and its expected configuration; the tool does not automatically disable IPv6.

## Does a Surfshark, Avira, Wintun, Docker, or VirtualBox name prove a problem?

No. Drivers and filters can be shared or legitimately in use. Installed software, signatures, service registrations, runtime state, file presence, and repeated network behavior provide separate evidence. Even a corroborated orphan candidate is an investigation lead, not proof of malware or a kernel deadlock.

## Why is a query marked incomplete?

Permission restrictions, missing Windows modules, timeouts, parse failures, or cancellation can prevent a query. The tool preserves the error and never turns it into proof that a configuration or product is absent. An explicit UAC restart may help with a restricted read; administrator access is not silently acquired.

## Why is DNS flushing manual now?

The old cache is transient and cannot be faithfully restored. The public preview defaults to guidance for non-reversible operations. This is independent of whether clearing a cache is usually considered low operational risk.

## Can I send the entire report to a public issue?

Inspect a redacted export and share only the evidence necessary to reproduce the problem. Full reports, WFP XML, repair journals, tokens, device identifiers, and personal paths must remain private. Redaction cannot establish that every application or rule name is safe to publish.

## How are language and targets related?

English, Simplified Chinese, and Traditional Chinese suggest global, mainland, and traditional-language target profiles respectively. A profile is independently selectable and custom domains are retained. The list is visible before a scan. A language change is not a command to replace a user's custom configuration.

## Is the EXE signed or proven safe by an attestation?

The preview EXEs are unsigned unless a specific release states otherwise. Check the release source and SHA-256 values. Provenance can bind an artifact to a build workflow; it cannot substitute for review, Windows testing, an antivirus assessment, or a code-signing certificate. Do not disable system protection to run the tool.

## Where is support contact information?

The public author is Alden. No private email or unconfirmed GitHub account is published. Use the eventual repository's issue/security channels after they are established. Do not invent a profile link from a local username.
