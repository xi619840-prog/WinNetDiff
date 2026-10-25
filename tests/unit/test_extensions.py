"""Extension matrix with synthetic data; no real DNS/driver/route changes."""
import copy
import json
import threading
import unittest
from unittest.mock import patch
from winnetdiff.collectors import dns_audit as dns
from winnetdiff.analysis.dns_rules import fake_ip_findings
from winnetdiff.probes import pmtu
from winnetdiff.core.models import Probe, Report, Finding
from winnetdiff.reports.share_card import compact_share_card
from winnetdiff.reports.export import evidence_text, markdown_report


def dns_routes(virtual=True):
    return {'query_status': {'routes':'ok','interfaces':'ok'},
        'adapters':[{'ifIndex':4,'Name':'Synthetic TUN','Classification':'virtual','Status':'Up'},
                    {'ifIndex':5,'Name':'Synthetic LAN','Classification':'physical','Status':'Up'}],
        'interfaces':[{'InterfaceIndex':i,'AddressFamily':2,'ConnectionState':'Connected','InterfaceMetric':10} for i in (4,5)],
        'routes':[{'InterfaceIndex':4 if virtual else 5,'AddressFamily':2,'DestinationPrefix':'198.18.0.0/15','RouteMetric':5},
                  {'InterfaceIndex':5,'AddressFamily':2,'DestinationPrefix':'0.0.0.0/0','RouteMetric':1}],
        'dns_servers':[{'InterfaceIndex':5,'InterfaceAlias':'Synthetic LAN','ServerAddresses':['10.0.0.1']}]}


def dns_probe(stage='http_ok', address='198.18.1.5'):
    return {'host':'synthetic.example','family':'IPv4','ip':address,'resolved_addresses':[address], 'stage':stage,
            'tcp_ms':None if stage.startswith('tcp_') else 5}


def runtime(active=True):
    return {'cores':[{'Name':'mihomo.exe'}] if active else [], 'core_query_complete':True,
            'listeners':[],'listener_query_complete':True,'errors':[]}


class FakeIpTests(unittest.TestCase):
    def test_FIP_01_healthy_tun_is_expected_without_fault_claim(self):
        audit=dns.audit_dns_state(dns_routes(), [dns_probe()], runtime(), network_tested=True)
        self.assertEqual(audit['targets'][0]['status'],'expected_fake_ip_active_proxy')
        self.assertTrue(all(f.severity=='資訊' for f in fake_ip_findings(audit)))

    def test_FIP_02_unroutable_failure_and_absent_core_is_suspected(self):
        routes=dns_routes();routes['routes']=[]
        audit=dns.audit_dns_state(routes, [dns_probe('tcp_timeout')], runtime(False), network_tested=True)
        self.assertEqual(audit['targets'][0]['status'],'fake_ip_unroutable_suspected')
        finding=fake_ip_findings(audit)[0]
        self.assertEqual(finding.severity,'高優先級');self.assertEqual(finding.evidence_grade,'E1')
        self.assertEqual(finding.commands,[])

    def test_FIP_03_private_dns_success_does_not_imply_residue(self):
        audit=dns.audit_dns_state(dns_routes(False), [dns_probe(address='203.0.113.7')],runtime(False),network_tested=True)
        self.assertEqual(audit['dns_servers'][0]['status'],'private_dns_configured')
        self.assertTrue(audit['dns_servers'][0]['resolution_observed'])
        self.assertEqual(fake_ip_findings(audit),[])

    def test_FIP_04_loopback_listener_present_absent_and_unknown(self):
        routes=dns_routes();routes['dns_servers'][0]['ServerAddresses']=['127.0.0.1']
        for complete, listeners, expected in [(True,[{'LocalAddress':'0.0.0.0','LocalPort':53}],'local_listener_present'),
                                             (True,[],'local_listener_missing'),(False,[],'local_listener_unknown')]:
            value=runtime();value.update(listener_query_complete=complete,listeners=listeners)
            audit=dns.audit_dns_state(routes,[dns_probe(address='203.0.113.7')],value,network_tested=True)
            self.assertEqual(audit['dns_servers'][0]['status'],expected)
            self.assertFalse(any(f.severity=='高優先級' for f in fake_ip_findings(audit)))

    def test_FIP_05_specific_target_route_beats_physical_default(self):
        route=dns.select_target_route('198.18.1.5',dns_routes())
        self.assertEqual(route['route']['InterfaceIndex'],4);self.assertTrue(route['virtual'])
        # A completely unrelated TUN default cannot replace a /32 physical path.
        routes=dns_routes();routes['routes'].append({'InterfaceIndex':5,'DestinationPrefix':'198.18.1.5/32','RouteMetric':900})
        self.assertEqual(dns.select_target_route('198.18.1.5',routes)['route']['InterfaceIndex'],5)

    def test_FIP_06_offline_is_indeterminate_not_failed(self):
        routes=dns_routes();routes['routes']=[]
        audit=dns.audit_dns_state(routes,[dns_probe('tcp_timeout')],runtime(False),network_tested=False)
        self.assertEqual(audit['targets'][0]['status'],'fake_ip_indeterminate')
        offline=dns.audit_dns_state(routes,[],runtime(False),network_tested=False)
        self.assertTrue(offline['dns_servers']);self.assertFalse(offline['targets'])

    def test_failed_or_ambiguous_inventory_cannot_claim_unroutable(self):
        routes=dns_routes();routes['query_status']['interfaces']='error';routes['routes']=[]
        audit=dns.audit_dns_state(routes,[dns_probe('tcp_timeout')],runtime(False),network_tested=True)
        self.assertEqual(audit['targets'][0]['status'],'fake_ip_indeterminate')
        routes=dns_routes();routes['routes'].append(dict(routes['routes'][0],InterfaceIndex=5))
        self.assertEqual(dns.select_target_route('198.18.1.5',routes)['status'],'ambiguous')
        routes=dns_routes();routes['interfaces'][0]['InterfaceMetric']=None
        self.assertEqual(dns.select_target_route('198.18.1.5',routes)['status'],'unknown')

    def test_inactive_interface_and_overall_budget_do_not_create_false_claim(self):
        routes=dns_routes();routes['interfaces'][0]['ConnectionState']='Disconnected'
        self.assertEqual(dns.select_target_route('198.18.1.5',routes)['route']['InterfaceIndex'],5)
        routes['routes']=[]
        audit=dns.audit_dns_state(routes,[dns_probe('overall_timeout')],runtime(False),network_tested=True)
        self.assertEqual(audit['targets'][0]['status'],'fake_ip_indeterminate')

    def test_unknown_default_metric_does_not_mask_a_specific_working_route(self):
        routes=dns_routes();routes['interfaces'][1]['InterfaceMetric']=None
        selected=dns.select_target_route('198.18.1.5',routes)
        self.assertEqual(selected['status'],'selected')
        self.assertEqual(selected['route']['InterfaceIndex'],4)

    def test_raw_runtime_failure_is_unknown_and_cancel_stops_queries(self):
        routes=dns_routes();routes['dns_servers'][0]['ServerAddresses']=['127.0.0.1']
        with patch.object(dns,'ps_json',return_value=([],'synthetic access denied')):
            state=dns.collect_dns_runtime(routes)
        self.assertFalse(state['core_query_complete']);self.assertFalse(state['listener_query_complete'])
        event=threading.Event();event.set()
        with patch.object(dns,'ps_json') as query:
            self.assertTrue(dns.collect_dns_runtime(routes,event)['cancelled'])
        query.assert_not_called()

    def test_fake_range_boundaries_and_invalid_input(self):
        for address in ('198.18.0.0','198.19.255.255'):self.assertTrue(dns.is_fake_ip(address))
        for address in ('198.17.255.255','198.20.0.0','::1','not an IP'):self.assertFalse(dns.is_fake_ip(address))


class PmtuTests(unittest.TestCase):
    def run_samples(self, outputs, **kwargs):
        with patch.object(pmtu,'run_command',side_effect=outputs) as command:
            result=pmtu.probe_pmtu('203.0.113.7',confirmed=True,**kwargs)
        return result,command

    def response(self,text,code=0,**kwargs):
        return dict(ok=code==0,returncode=code,stdout=text,stderr='',**kwargs)

    def test_MTU_01_fragment_feedback_is_not_a_black_hole(self):
        result,command=self.run_samples([self.response('Reply from 203.0.113.7: bytes=1200 time=1ms TTL=55'),
                                        self.response('Packet needs to be fragmented but DF set.',1)])
        self.assertEqual(result['status'],'mtu_limited_feedback_present');self.assertFalse(result['blackhole_confirmed'])
        self.assertEqual([s['estimated_ipv4_packet_bytes'] for s in result['samples']],[1228,1500])
        self.assertEqual(command.call_args_list[0].args[0],['ping.exe','-4','-f','-l','1200','-n','1','-w','800','203.0.113.7'])

    def test_MTU_02_small_reply_large_timeout_is_inconclusive(self):
        result,_=self.run_samples([self.response('TTL=55'),self.response('Request timed out.',1)])
        self.assertEqual(result['status'],'size_or_icmp_inconclusive');self.assertFalse(result['blackhole_confirmed'])

    def test_MTU_03_all_silent_is_no_icmp_result(self):
        result,_=self.run_samples([self.response('Request timed out.'),self.response('请求超时。')])
        self.assertEqual(result['status'],'icmp_no_result')

    def test_MTU_04_success_exit_code_without_reply_never_counts_success(self):
        result,_=self.run_samples([self.response('Ping statistics only'),self.response('Destination host unreachable.',0)])
        self.assertEqual(result['status'],'unreachable')
        self.assertNotIn('echo_reply',[s['status'] for s in result['samples']])

    def test_MTU_05_ipv6_invalid_and_fake_ip_send_nothing(self):
        with patch.object(pmtu,'run_command') as command:
            for address,status in [('::1','ipv6_not_supported'),('bad;cmd','invalid_address'),('198.18.1.5','unsuitable_target')]:
                self.assertEqual(pmtu.probe_pmtu(address,confirmed=True)['status'],status)
            self.assertEqual(pmtu.probe_pmtu('203.0.113.7')['status'],'consent_required')
        command.assert_not_called()

    def test_MTU_06_chinese_permissions_and_cancel(self):
        for text,expected in [('来自 203.0.113.7 的回复: 字节=1200 时间<1ms TTL=128','echo_reply'),
                              ('需要拆分数据包，但是设置 DF。','fragmentation_needed'),
                              ('拒绝访问。','permission_denied'),('PING: transmit failed. General failure.','unreachable')]:
            self.assertEqual(pmtu.parse_ping_result(self.response(text)),expected)
        event=threading.Event()
        def stop(*args,**kwargs): event.set();return self.response('Request timed out.',1)
        with patch.object(pmtu,'run_command',side_effect=stop) as command:
            result=pmtu.probe_pmtu('203.0.113.7',confirmed=True,cancel=event)
        self.assertEqual(result['status'],'cancelled');self.assertEqual(command.call_count,1)

    def test_budget_exhaustion_stops_before_next_ping(self):
        clock=[0.0]
        def slow(*args,**kwargs):clock[0]=4.1;return self.response('timeout',1,timed_out=True)
        with patch.object(pmtu.time,'perf_counter',side_effect=lambda:clock[0]),patch.object(pmtu,'run_command',side_effect=slow) as command:
            result=pmtu.probe_pmtu('203.0.113.7',confirmed=True)
        self.assertEqual(result['status'],'overall_timeout');self.assertEqual(command.call_count,1)

    def test_overall_expiration_on_last_payload_is_not_an_icmp_silence_claim(self):
        clock=[0.0]
        def clipped(*args,**kwargs):clock[0]=1.1;return self.response('',1,timed_out=True)
        with patch.object(pmtu.time,'perf_counter',side_effect=lambda:clock[0]),patch.object(pmtu,'run_command',side_effect=clipped):
            result=pmtu.probe_pmtu('203.0.113.7',confirmed=True,payload_sizes=(1200,),overall_timeout=1)
        self.assertEqual(result['status'],'overall_timeout')
        self.assertEqual(len(result['samples']),1)

    def test_budget_and_sizes_validation(self):
        for options in ({'retries':0},{'payload_sizes':[True]},{'overall_timeout':float('nan')},{'timeout_ms':100000}):
            with self.assertRaises(ValueError):pmtu.probe_pmtu('203.0.113.7',confirmed=True,**options)


def private_card_report():
    secret='PrivateAlice 张三 PrivateDevice-99 aa:bb:cc:dd:ee:ff 10.22.33.44 2001:db8::77 PrivateSSID D:\\SecretLab\\app.exe https://private.example/?token=SecretToken user:PrivatePassword@'
    probes=[Probe(secret,'IPv4',ip='10.22.33.44',stage='tls_timeout',dns_ms=1,tcp_ms=2,tls_ms=6000,error=secret,http_line=secret)]*20
    findings=[Finding('高優先級','路由',secret,secret,secret,code='dns.fake_ip_unroutable_suspected',priority=1,evidence_grade='E2')]*20
    report=Report('4.5.5.0','private-time',secret,True,[secret],{'secret':secret},{'secret':secret},probes,{'secret':secret},findings,[secret])
    report.layers={key:{'status':'待核對','raw_evidence':secret} for key in ('代理','路由','IPv4/IPv6','TCP/TLS','安全/驅動')}
    return report,secret


class CardTests(unittest.TestCase):
    def test_CARD_01_02_03_allowlist_three_locales_and_real_length(self):
        report,secret=private_card_report()
        for locale in ('en','zh-CN','zh-TW'):
            card=compact_share_card(report,locale)
            self.assertLessEqual(len(card),500)
            for token in ('PrivateAlice','张三','PrivateDevice','aa:bb','10.22','2001:db8','PrivateSSID','SecretLab','private.example','SecretToken','PrivatePassword'):
                self.assertNotIn(token,card)
            self.assertIn('4.5.5.0',card)
            self.assertIn('E2',card)
            self.assertTrue(card.startswith('### WinNetDiff'))
            self.assertNotIn('```',card)

    def test_malicious_dynamic_values_are_rejected_not_escaped_into_card(self):
        report,_=private_card_report();bad='SECRET\n```\n[click](https://SecretUrl)\x00\x1b'
        report.version=bad;report.layers={'代理':{'status':bad}}
        for probe in report.probes:probe.stage=bad;probe.family=bad;probe.tcp_ms=bad
        for finding in report.findings:finding.code=bad
        card=compact_share_card(report)
        self.assertNotIn('SECRET',card);self.assertNotIn('SecretUrl',card)
        self.assertNotIn('\x00',card);self.assertNotIn('\x1b',card);self.assertLessEqual(len(card),500)

    def test_CARD_05_offline_no_findings_produces_no_invented_probe(self):
        report,_=private_card_report();report.probes=[];report.findings=[]
        card=compact_share_card(report,'en')
        self.assertIn('not run',card);self.assertNotIn('D/T/L/H=',card)

    def test_extension_reports_still_redact_paths_and_preserve_versions(self):
        report,_=private_card_report();report.version='2.2.0a1'
        report.dns_audit={'targets':[{'address':'198.18.1.5','host':'example.com','raw_columns':[r'D:\SecretLab\driver.sys']}], 'DisplayVersion':'4.5.5.0'}
        for render in (evidence_text,markdown_report):
            text=render(report);self.assertNotIn('SecretLab',text);self.assertNotIn('198.18.1.5',text);self.assertIn('4.5.5.0',text)
