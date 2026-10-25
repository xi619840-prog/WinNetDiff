# Security policy

The current preview is under active review. There is no promise of a response deadline or support for older previews. Use the latest reviewed source/release and read its validation limitations.

The current unpublished 2.2.0a3 source includes the final GUI export/cancellation repairs. Normal GUI exports redact; full data requires a separate action and fresh explicit acknowledgement. A redacted report can still reveal sensitive software or network context, so review it before sharing. Earlier EXE candidates are not evidence for this updated source; the binary release gate remains closed.

Report a security issue through GitHub private vulnerability reporting when the maintainer enables it. Before that exists, request a private contact channel with a minimal, non-sensitive description. Do not put exploit credentials, raw WFP XML, private repair journals, personal paths, or a complete device inventory in a public issue. No private email or unconfirmed account address is supplied here.

Useful reports identify the affected version, code path, trigger, potential impact, and a synthetic reproducer. Distinguish a faulty diagnostic hypothesis from an unsafe mutation, injection path, privilege error, or unintended data disclosure. Do not install or delete drivers to create a reproducer on someone else's computer.

The application does not upload reports. A normal scan is read-only; public test domains are contacted only by explicitly started network probes. No universal safety conclusion follows from a successful build, provenance attestation, antivirus scan, or green CI result. Contributor and release controls are described in [safety model](docs/safety-model.md) and [release checklist](docs/release-checklist.md).
