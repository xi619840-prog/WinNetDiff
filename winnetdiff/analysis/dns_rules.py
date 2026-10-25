"""Conservative Fake-IP findings; no address-only automatic repair."""
import json
from ..core.models import Finding
from .evidence import assess_phase_evidence


def fake_ip_findings(audit):
    findings = []
    for target in audit.get('targets', []):
        status = target['status']
        suspect = status == 'fake_ip_unroutable_suspected'
        title = {'expected_fake_ip_active_proxy': 'Fake-IP mapping works with an active proxy path',
                 'fake_ip_unroutable_suspected': 'Suspected stale Fake-IP mapping without a usable target route',
                 'fake_ip_indeterminate': 'Fake-IP clue needs additional verification'}[status]
        findings.append(Finding('高優先級' if suspect else '資訊', '路由', title,
            json.dumps(target, ensure_ascii=False),
            'The system resolved a benchmarking-range address. Review the recorded target route, core inventory and matching TCP results; no DNS hijacking or culprit is proven.',
            confidence='中' if suspect else '低', priority=1 if suspect else 3,
            code='dns.' + status, evidence_grade=assess_phase_evidence(target.get('matching_attempts', []), {'tcp_timeout', 'tcp_error'})['grade'] if suspect else 'E1',
            alternatives=['Intentional TUN/transparent proxy mapping, incomplete inventory, policy routing or a lab network.'],
            verification=['Verify the owning proxy and target-specific route before changing any DNS setting.']))
    for server in audit.get('dns_servers', []):
        if server['status'] == 'local_listener_missing' and server.get('active_interface') is True:
            findings.append(Finding('資訊', '路由', 'Configured loopback DNS has no observed port 53 listener',
                json.dumps(server, ensure_ascii=False),
                'The endpoint inventory found no matching listener. Resolver caching, interception or another configured DNS server may still work; verify an actual query before changing configuration.',
                confidence='低', code='dns.local_listener_missing'))
    return findings
