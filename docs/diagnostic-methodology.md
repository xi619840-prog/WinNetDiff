# Diagnostic methodology

The reasoning chain is **observed evidence → differential result → candidate cause → evidence grade → verification → eligible repair**. A finding must say what was measured, where it failed, why the evidence supports a candidate, what else could explain it, and which next check could contradict the candidate. Grades are definitions of evidence strength, not invented probabilities.

## Stage boundaries

DNS success means that an address was returned. It says nothing about whether a route to that address works, whether TCP 443 accepts connections, whether a certificate validates, or whether an HTTP server responds. A cached DNS answer can also outlive a working network path.

TCP connect success means a transport handshake completed with the selected IP. TLS then requires protocol negotiation and certificate validation. A firewall, network filter, MTU problem, TLS inspection device, server policy, or remote failure can interrupt this later stage. A timeout alone does not identify which one caused it.

WinNetDiff therefore wraps the same connected socket with certificate verification and SNI, disables automatic handshake timing, and measures the explicit handshake separately. HTTP is measured only after TLS completes. An HTTP 403 or 503 is still an application response, while an empty or malformed status line is not an HTTP success.

## Compare like with like

Keep the domain set, address family, retry count, network-mode selection, and time budget consistent when comparing before and after. Record the chosen IP for each attempt: a CDN may return different servers between scans. Retain failures even if a later retry succeeds. Different stages or success mixed with failure support an intermittent or target-dependent observation, rather than a claim that every request fails.

IPv4 and IPv6 tests use the same domain. IPv6 absent, disabled, lacking a default route, timing out at TCP, and failing after TCP are different observations. An otherwise functioning IPv4-only network is not a system failure merely because IPv6 did not work. More specific routes can matter even when a default route is absent.

The native probes connect directly and do not emulate every application's proxy decision, PAC script, credential store, or browser behavior. This is why a working direct probe and a broken application can coexist. Proxy settings are assessed separately, and an unused environment variable is not automatically a network fault.

## Correlation is not causation

A third-party filter may be essential for a virtual machine, packet capture, campus access, or an actively used VPN. A vendor keyword locates candidate evidence; it does not prove maliciousness or causation. Missing uninstall registration is weaker than a missing product file plus a still-running service, and portable/enterprise installations can have no normal uninstall entry.

Repeated same-connection TCP success/TLS timeout across several targets, combined with corroborated orphan security-provider or filter evidence, raises the priority of WFP/NDIS investigation. It still does not demonstrate a kernel deadlock. File publisher, product metadata, service registration, installed-software ownership, and active antivirus providers must be checked. Shared components such as Wintun or endpoint SDK drivers may belong to another valid product.

Evidence grades distinguish direct observation, repeated differential behavior, and independent corroboration. The scenario record lists applicability conditions, alternative explanations, a falsifiable verification step, and risk. A Windows update near a configuration change is temporal context; without event/version evidence it is not a proven cause.

## Verify a repair

A successful API call only confirms that a requested configuration operation was accepted. First reread the relevant state. Then run the same diagnostic parameters and compare outcomes and stage timings. If the target configuration changed but connectivity did not improve, report **not verified effective**. If inputs differ, mark the comparison incomparable; if results worsen, report regression.

Change one eligible object at a time and preserve the original. A backup that cannot be matched to the current user, machine, or expected post-change state must not silently overwrite newer settings. For operations without a faithful rollback, provide manual guidance instead of default automation.

## Explicit 2.1.0b2 measurement contract

Stage and overall deadlines remain separate; overall expiration (including ties) is a budget outcome, not TLS evidence. Repetition requires the exact destination IP and explicit port/SNI/request/timeout context. E3 uses complete independent inventory with an exact enabled-binding-to-service link; a vendor word or orphan status alone remains insufficient. See the shared `analysis/evidence.py` and its counterexample tests. Grades and UI priority are independent.
