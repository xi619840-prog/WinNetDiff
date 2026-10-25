"""F5/F6/F7 independent synthetic contracts; no system configuration writes."""
import contextlib
import copy
import io
import json
from pathlib import Path
import socket
import ssl
import sys
import subprocess
import time
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

import windows_net_diffdiag as standalone
from winnetdiff.analysis.ownership import associate_hosts
from winnetdiff.analysis.evidence import corroborating_orphans, assess_phase_evidence
from winnetdiff.collectors.security import summarize_wfp_xml
from winnetdiff.probes import proxy_path, transport
from winnetdiff.core import config, engine, privacy
from winnetdiff.core.models import Probe
from winnetdiff.core.i18n import tr, set_language
from winnetdiff import cli
from tests.unit.test_gemini_round_2_2 import fixture
from tests.unit.test_i18n_safety_gui import empty_report

KEYS = ['11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222','33333333-3333-3333-3333-333333333333']


def generic_inventory():
    sec={'installed_apps': [],'service_registry': [], 'drivers_wmi':[
        {'Name':'通用Filter','State':'Running','PathName':r'C:\Windows\System32\drivers\generic.sys'}],
        'services_wmi':[], 'driverquery':[], 'files':[], 'evidence':[],
        'completeness':{'installed_apps':True,'service_registry':True,'drivers_wmi':True,'services_wmi':True}}
    routes={'query_status':{'bindings':'ok'},'bindings':[{'ComponentID':'arbitrary_component','Enabled':True,
        'OwnerEvidence':{'Service':'通用Filter'}}]}
    return sec,routes


def graph_security(sec,routes):
    sec['ownership']=associate_hosts(sec,routes)
    return sec


class GenericHostTests(unittest.TestCase):
    def test_vendor_free_running_binding_and_missing_registration_corroborate(self):
        sec,routes=generic_inventory(); graph_security(sec,routes)
        self.assertEqual('orphan_evidence',sec['ownership']['components'][0]['Status'])
        refs=corroborating_orphans(sec,routes)
        self.assertEqual(['通用Filter'],[row['Name'] for row in refs])
        self.assertEqual('E3',assess_phase_evidence(fixture()['probes'],{'tls_timeout'},corroboration=refs)['grade'])

    def test_registered_unknown_owner_is_not_orphan_just_because_uninstall_is_empty(self):
        sec,routes=generic_inventory();sec['service_registry']=copy.deepcopy(sec['drivers_wmi'])
        graph_security(sec,routes)
        self.assertEqual('owner_unknown',sec['ownership']['components'][0]['Status'])
        self.assertFalse(corroborating_orphans(sec,routes))

    def test_installed_path_host_wins_without_vendor_names(self):
        sec,routes=generic_inventory();sec['drivers_wmi'][0]['PathName']=r'D:\Aster Product\bin\generic.sys'
        sec['installed_apps']=[{'DisplayName':'星河產品','InstallLocation':r'D:\Aster Product'}]
        graph_security(sec,routes);row=sec['ownership']['components'][0]
        self.assertEqual('owner_installed',row['Status']);self.assertEqual(['星河產品'],row['OwnerApps'])
        self.assertFalse(corroborating_orphans(sec,routes))

    def test_path_prefix_lookalike_is_not_an_owner(self):
        sec,routes=generic_inventory();sec['drivers_wmi'][0]['PathName']=r'D:\Aster Product Other\generic.sys'
        sec['installed_apps']=[{'DisplayName':'Aster','InstallLocation':r'D:\Aster Product'}]
        graph_security(sec,routes);self.assertFalse(sec['ownership']['components'][0]['OwnerApps'])

    def test_shared_root_is_never_an_application_owner(self):
        sec,routes=generic_inventory();sec['installed_apps']=[{'DisplayName':'Unknown','InstallLocation':r'C:\Windows'}]
        graph_security(sec,routes);self.assertFalse(sec['ownership']['components'][0]['OwnerApps'])

    def test_valid_signer_only_is_possible_host_and_blocks_orphan(self):
        sec,routes=generic_inventory();sec['installed_apps']=[{'DisplayName':'Aster Agent','Publisher':'Aster Corp'}]
        sec['files']=[{'Path':sec['drivers_wmi'][0]['PathName'],'Exists':True,'SignatureStatus':'Valid','Publisher':'CN=Signing Cert, O=Aster Corp, C=US'}]
        graph_security(sec,routes);row=sec['ownership']['components'][0]
        self.assertEqual('owner_possible',row['Status']);self.assertFalse(row['OwnerApps'])
        self.assertFalse(corroborating_orphans(sec,routes))

    def test_generic_possible_host_protects_legacy_wfp_candidates_without_ndis(self):
        from tests.unit.test_gemini_round_2_2 import realistic_security
        from winnetdiff.collectors.security import classify_security
        sec=realistic_security()
        sec['installed_apps']=[{'DisplayName':'星河企業端點','Publisher':'Aster Corp'}]
        for row in sec['files']:
            if row.get('Exists') is True:row.update(SignatureStatus='Valid',Publisher='CN=Signing, O=Aster Corp')
        sec['evidence']=classify_security(sec)
        graph_security(sec,{'bindings':[]})
        self.assertFalse(corroborating_orphans(sec,{'bindings':[]}))
        self.assertTrue(any(row['PossibleHosts'] for row in sec['ownership']['components']))

    def test_unsigned_company_name_does_not_claim_a_host(self):
        sec,routes=generic_inventory();sec['installed_apps']=[{'DisplayName':'Aster','Publisher':'Aster Corp'}]
        sec['files']=[{'Path':sec['drivers_wmi'][0]['PathName'],'CompanyName':'Aster Corp','SignatureStatus':'NotSigned'}]
        graph_security(sec,routes);self.assertFalse(sec['ownership']['components'][0]['PossibleHosts'])

    def test_incomplete_inventory_never_supplies_absence(self):
        for key in ('installed_apps','service_registry','drivers_wmi'):
            sec,routes=generic_inventory();sec['completeness'][key]=False;graph_security(sec,routes)
            self.assertFalse(corroborating_orphans(sec,routes),key)

    def test_inactive_or_unknown_binding_cannot_corrobate(self):
        for state in ('disabled','incomplete'):
            sec,routes=generic_inventory()
            if state=='disabled':routes['bindings'][0]['Enabled']=False
            else:routes['query_status']['bindings']='error'
            graph_security(sec,routes);self.assertFalse(corroborating_orphans(sec,routes))

    def test_renamed_registration_with_exact_binary_blocks_missing_registration(self):
        sec,routes=generic_inventory();sec['service_registry']=[{'Name':'Alias','PathName':sec['drivers_wmi'][0]['PathName']}]
        graph_security(sec,routes);self.assertFalse(corroborating_orphans(sec,routes))

    def test_fake_serialized_graph_is_rebuilt_from_observations(self):
        sec,routes=generic_inventory();graph_security(sec,routes);sec['drivers_wmi']=[]
        self.assertFalse(corroborating_orphans(sec,routes))

    def test_no_image_or_stopped_component_cannot_corrobate(self):
        for change in ({'PathName':''},{'State':'Stopped'}):
            sec,routes=generic_inventory();sec['drivers_wmi'][0].update(change);graph_security(sec,routes)
            self.assertFalse(corroborating_orphans(sec,routes))

    def test_missing_binary_is_concrete_but_keeps_manual_review(self):
        sec,routes=generic_inventory();sec['service_registry']=copy.deepcopy(sec['drivers_wmi'])
        sec['files']=[{'Path':sec['drivers_wmi'][0]['PathName'],'Exists':False}]
        graph_security(sec,routes);self.assertEqual('running_binary_missing',sec['ownership']['components'][0]['Inconsistency'])
        self.assertTrue(corroborating_orphans(sec,routes))

    def test_coservices_are_exact_not_substring_matches(self):
        sec,routes=generic_inventory();routes['bindings'][0]['OwnerEvidence']={'Service':'Unrelated','CoServices':['通用Filter']}
        graph_security(sec,routes);self.assertTrue(corroborating_orphans(sec,routes))
        routes['bindings'][0]['OwnerEvidence']['CoServices']=['通用FilterExtra'];graph_security(sec,routes)
        self.assertFalse(corroborating_orphans(sec,routes))


class WfpKeyTests(unittest.TestCase):
    def xml(self,extra=''):
        return f'<state><providers><item><providerKey>{{{KEYS[0]}}}</providerKey><serviceName>通用Filter</serviceName></item></providers><callouts><item><calloutKey>{{{KEYS[1]}}}</calloutKey><providerKey>{{{KEYS[0]}}}</providerKey></item></callouts><filters><item><filterKey>{{{KEYS[2]}}}</filterKey><action><calloutKey>{{{KEYS[1]}}}</calloutKey></action></item></filters>{extra}</state>'

    def parse(self,text):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'synthetic.xml';path.write_text(text,encoding='utf-8');return summarize_wfp_xml(path)

    def test_exact_provider_callout_filter_chain_and_service(self):
        summary=self.parse(self.xml());self.assertEqual(3,len(summary['ownership_records']))
        sec,_=generic_inventory();graph=associate_hosts(sec,{},summary)
        links=[e for e in graph['edges'] if e['relation']=='wfp_explicit_key_reference']
        self.assertEqual(2,len(links));self.assertEqual('imported_snapshot',graph['wfp_scope'])
        self.assertFalse(graph['components'][0]['EligibleCorroboration'])

    def test_display_text_cannot_spoof_a_service_key(self):
        summary=self.parse(self.xml().replace('<serviceName>通用Filter</serviceName>','<description><serviceName>通用Filter</serviceName></description>'))
        sec,_=generic_inventory();self.assertFalse(associate_hosts(sec,{},summary)['components'])

    def test_duplicate_provider_keys_do_not_establish_ownership(self):
        summary=self.parse(self.xml());summary['ownership_records'].append(copy.deepcopy(summary['ownership_records'][0]))
        sec,_=generic_inventory();self.assertFalse(associate_hosts(sec,{},summary)['components'])

    def test_dtd_is_rejected(self):
        with self.assertRaises(ValueError):self.parse('<!DOCTYPE x [<!ENTITY e "spoof">]>'+self.xml())

    def test_utf16_dtd_after_long_comment_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'input.xml';path.write_bytes(('<?xml version="1.0" encoding="utf-16"?>'+'<!--'+('x'*70000)+'-->'+'<!DOCTYPE state>'+self.xml()).encode('utf-16'))
            with self.assertRaises(ValueError):summarize_wfp_xml(path)

    def test_key_privacy_preserves_graph_connectivity(self):
        sec,routes=generic_inventory();graph=associate_hosts(sec,routes,self.parse(self.xml()))
        redacted=privacy.redacted_data(graph);serialized=json.dumps(redacted)
        self.assertNotIn(KEYS[0],serialized)
        ids={n['node_id'] for n in redacted['nodes']}
        self.assertTrue(all(e['source_id'] in ids and e['target_id'] in ids for e in redacted['edges']))


class ProxyPlanningTests(unittest.TestCase):
    def plan(self,value='http://proxy.corp.invalid:8080',**extra):
        return proxy_path.proxy_path_plan({'environ_process':{'HTTPS_PROXY':value,**extra}},'www.example.com')

    def test_remote_http_proxy_is_eligible_without_looking_for_local_listener(self):
        row=next(r for r in self.plan()['paths'] if r['source']=='env:process')
        self.assertTrue(row['eligible']);self.assertEqual('proxy.corp.invalid',row['host'])

    def test_credentials_are_neither_returned_nor_sent(self):
        plan=self.plan('http://PrivateUser:PrivatePassword@proxy.corp.invalid:8080')
        self.assertNotIn('PrivatePassword',json.dumps(plan));self.assertNotIn('PrivateUser',json.dumps(plan))
        row=next(r for r in plan['paths'] if r['source']=='env:process')
        self.assertEqual('credentials_not_sent',row['status']);self.assertFalse(row['eligible'])

    def test_proxy_dns_identity_is_masked_in_default_export(self):
        text=json.dumps(privacy.redacted_data(self.plan()))
        self.assertNotIn('proxy.corp.invalid',text);self.assertIn('<id-',text)

    def test_new_winhttp_configuration_strings_are_pseudonymized(self):
        result=privacy.redacted_data({'winhttp_config':{'ok':True,'access_type':3,'proxy':'proxy.corp.invalid:8080','bypass':'*.internal.corp.invalid'}})
        self.assertEqual(3,result['winhttp_config']['access_type'])
        self.assertNotIn('corp.invalid',json.dumps(result))

    def test_target_bypass_domain_suffix_has_boundary(self):
        self.assertTrue(proxy_path.proxy_bypass('www.example.com','.example.com'))
        self.assertFalse(proxy_path.proxy_bypass('badexample.com','.example.com'))
        self.assertFalse(next(r for r in self.plan(NO_PROXY='.example.com')['paths'] if r['source']=='env:process')['eligible'])

    def test_windows_bypass_local_wildcards_and_ports(self):
        self.assertTrue(proxy_path.proxy_bypass('intranet','<local>',windows=True))
        self.assertTrue(proxy_path.proxy_bypass('app.corp.invalid','*.corp.invalid',windows=True))
        self.assertFalse(proxy_path.proxy_bypass('app.corp.invalid','*.corp.invalid:80',windows=True))

    def test_https_proxy_is_not_silently_downgraded(self):
        row=next(r for r in self.plan('https://proxy.corp.invalid:443')['paths'] if r['source']=='env:process')
        self.assertEqual('unsupported_proxy_scheme',row['status'])

    def test_pac_is_recorded_not_downloaded(self):
        plan=proxy_path.proxy_path_plan({'wininet':{'AutoConfigURL':'http://pac.corp.invalid/a.pac','ProxyEnable':1,'ProxyServer':'old.corp.invalid:80'},'wininet_api':{'flags':6}},'www.example.com')
        self.assertTrue(any(r['status']=='auto_proxy_unresolved' for r in plan['paths']))
        self.assertFalse(any(r['eligible'] for r in plan['paths']))

    def test_https_mapping_uses_http_connect_not_http_target_entry(self):
        plan=proxy_path.proxy_path_plan({'winhttp_config':{'ok':True,'access_type':3,'proxy':'http=wrong.corp.invalid:80;https=correct.corp.invalid:8080'}},'www.example.com')
        row=next(r for r in plan['paths'] if r['source']=='WinHTTP-default');self.assertEqual('correct.corp.invalid',row['host'])

    def test_stored_user_environment_is_not_assumed_active(self):
        plan=proxy_path.proxy_path_plan({'environ_user':{'HTTPS_PROXY':'proxy.corp.invalid:80'}},'www.example.com')
        self.assertEqual('stored_or_inactive',next(r for r in plan['paths'] if r['source']=='env:user')['status'])

    def test_unconfirmed_and_invalid_requests_do_not_create_sockets(self):
        with patch.object(proxy_path.socket,'socket') as factory:
            result=proxy_path.probe_proxy_path('www.example.com',{'scheme':'http','host':'proxy','port':80})
            self.assertEqual('not_confirmed',result['status'])
            result=proxy_path.probe_proxy_path('www.example.com',{'scheme':'http','host':'proxy\r\nInjected','port':80},confirmed=True)
            self.assertEqual('unsupported_or_invalid_proxy',result['status'])
        factory.assert_not_called()

    def test_target_cannot_smuggle_multiple_authorities(self):
        with patch.object(proxy_path,'timeout_dns') as dns:
            with self.assertRaises(ValueError):proxy_path.probe_proxy_path('first.example,second.example',{},confirmed=True)
        dns.assert_not_called()

    def test_probe_limit_and_duplicate_endpoints_are_enforced(self):
        proxy={'environ_process':{'HTTPS_PROXY':'proxy1.example:80 proxy2.example:80 proxy3.example:80'},
               'winhttp_config':{'ok':True,'access_type':3,'proxy':'proxy1.example:80'}}
        with patch.object(proxy_path,'probe_proxy_path',return_value={'status':'proxy_auth_required'}) as probe:
            context=proxy_path.diagnose_proxy_paths(proxy,[],'www.example.com',confirmed=True)
        self.assertEqual(2,probe.call_count);self.assertEqual('authentication_required',context['comparison'])

    def test_pre_cancelled_diagnostics_never_probe(self):
        cancel=threading.Event();cancel.set()
        with patch.object(proxy_path,'probe_proxy_path') as probe:
            context=proxy_path.diagnose_proxy_paths({'environ_process':{'HTTPS_PROXY':'proxy.example:80'}},[],'www.example.com',confirmed=True,cancel=cancel)
        probe.assert_not_called();self.assertTrue(context['cancelled']);self.assertEqual('not_compared',context['comparison'])


class ProxyProtocolTests(unittest.TestCase):
    def exercise(self,response,secure=None,cancel=None):
        raw=MagicMock();raw.recv.side_effect=response if isinstance(response,Exception) else [bytes([b]) for b in response]+[b'']
        tls=secure or MagicMock();tls.version.return_value='TLSv1.3'
        tls.recv.side_effect=[bytes([b]) for b in b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n']
        context=MagicMock();context.wrap_socket.return_value=tls
        info=(socket.AF_INET,socket.SOCK_STREAM,6,'',('192.0.2.10',443))
        with patch.object(proxy_path,'timeout_dns',return_value=([info],'',1)),patch.object(proxy_path.socket,'socket',return_value=raw),patch.object(proxy_path,'_proxy_tls_context',return_value=context):
            result=proxy_path.probe_proxy_path('www.example.com',{'scheme':'http','host':'proxy.corp.invalid','port':8080},confirmed=True,cancel=cancel)
        return result,raw,tls

    def test_auth_407_is_not_a_dead_proxy_or_tls_failure(self):
        result,raw,tls=self.exercise(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate PrivateChallenge\r\n\r\n')
        self.assertEqual('proxy_auth_required',result['status']);self.assertEqual(['negotiate'],result['auth_schemes'])
        self.assertNotIn('PrivateChallenge',json.dumps(result));self.assertFalse(result['tls_verified']);tls.do_handshake.assert_not_called()
        self.assertNotIn(b'Proxy-Authorization',raw.sendall.call_args.args[0])

    def test_policy_denial_stays_separate(self):
        result,_,tls=self.exercise(b'HTTP/1.1 403 Forbidden\r\n\r\n')
        self.assertEqual('proxy_policy_denied',result['status']);tls.do_handshake.assert_not_called()

    def test_connect_verified_tls_and_head_success(self):
        result,raw,tls=self.exercise(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        self.assertEqual('proxy_http_observed',result['status']);self.assertTrue(result['tls_verified'])
        self.assertFalse(result['target_ip_observed']);self.assertEqual(204,result['http_status'])
        self.assertTrue(raw.sendall.call_args.args[0].startswith(b'CONNECT www.example.com:443 HTTP/1.1'))
        self.assertTrue(tls.sendall.call_args.args[0].startswith(b'HEAD / HTTP/1.1'))

    def test_certificate_error_is_never_retried_unverified(self):
        tls=MagicMock();tls.do_handshake.side_effect=ssl.SSLCertVerificationError('untrusted')
        result,_,tls=self.exercise(b'HTTP/1.1 200 OK\r\n\r\n',secure=tls)
        self.assertEqual('proxy_tls_cert_error',result['status']);self.assertFalse(result['tls_verified']);tls.sendall.assert_not_called()

    def test_empty_connect_response_is_not_tls_timeout(self):
        result,_,tls=self.exercise(b'')
        self.assertEqual('proxy_connect_error',result['status']);tls.do_handshake.assert_not_called()

    def test_connect_timeout_is_not_tls_timeout(self):
        result,_,tls=self.exercise(TimeoutError('bounded connect wait'))
        self.assertEqual('proxy_connect_timeout',result['status']);tls.do_handshake.assert_not_called()

    def test_interim_connect_response_is_bounded_and_supported(self):
        result,_,_=self.exercise(b'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n')
        self.assertEqual('proxy_http_observed',result['status'])

    def test_precancelled_protocol_has_no_dns_or_socket(self):
        cancel=threading.Event();cancel.set()
        with patch.object(proxy_path,'timeout_dns') as dns:
            result=proxy_path.probe_proxy_path('www.example.com',{'scheme':'http','host':'proxy','port':80},confirmed=True,cancel=cancel)
        dns.assert_not_called();self.assertEqual('cancelled',result['status'])

    def test_auth_explanation_is_translated_without_claiming_fault(self):
        finding=proxy_path.proxy_path_findings({'comparison':'authentication_required'})[0]
        text=[tr(finding.interpretation,locale) for locale in ('en','zh-CN','zh-TW')]
        self.assertEqual(3,len(set(text)));self.assertIn('不能证明代理失效',text[1])
        self.assertEqual('資訊',finding.severity);self.assertEqual('E1',finding.evidence_grade)


class PinnedRetryTests(unittest.TestCase):
    def run_mode(self,module,family,mode='same-ip'):
        addresses=[(family,socket.SOCK_STREAM,6,'',(ip,443,0,0) if family==socket.AF_INET6 else (ip,443)) for ip in
                   (('2001:db8::1','2001:db8::2') if family==socket.AF_INET6 else ('203.0.113.1','203.0.113.2'))]
        def endpoint(host,family,info,dns_ms,**kwargs):
            return module.Probe(host,'IPv6' if family==socket.AF_INET6 else 'IPv4',ip=info[4][0],stage='tls_timeout',tcp_ms=1,
                context={'port':443,'sni':host,'method':'HEAD','path':'/','connect_timeout':5,'tls_timeout':6,'http_timeout':5})
        with patch.object(module,'timeout_dns',return_value=(addresses,'',1)),patch.object(module,'probe_endpoint',side_effect=endpoint) as probe:
            result=module.probe_host_family('www.example.com',family,retries=2,retry_mode=mode)
        return result,probe

    def test_pinned_ipv4_and_ipv6_reuse_the_exact_dns_sockaddr(self):
        for module in (transport,standalone):
            for family in (socket.AF_INET,socket.AF_INET6):
                result,probe=self.run_mode(module,family)
                self.assertEqual(probe.call_args_list[0].args[2],probe.call_args_list[1].args[2])
                self.assertEqual(2,len(result.resolved_addresses));self.assertEqual('same-ip',result.context['retry_mode'])
                self.assertEqual('E2',assess_phase_evidence([result],{'tls_timeout'})['grade'])

    def test_rotating_addresses_are_not_counted_as_repeated_same_ip(self):
        result,probe=self.run_mode(transport,socket.AF_INET,'rotate')
        self.assertNotEqual(probe.call_args_list[0].args[2],probe.call_args_list[1].args[2])
        self.assertEqual('E1',assess_phase_evidence([result],{'tls_timeout'})['grade'])

    def test_invalid_retry_mode_is_rejected_before_dns(self):
        with patch.object(transport,'timeout_dns') as dns,self.assertRaises(ValueError):
            transport.probe_host_family('www.example.com',socket.AF_INET,retry_mode='guess')
        dns.assert_not_called()

    def test_retry_modes_are_not_cross_compared_as_identical_evidence(self):
        pinned,_=self.run_mode(transport,socket.AF_INET)
        rotated,_=self.run_mode(transport,socket.AF_INET,'rotate')
        # One pinned pair and one rotated visit to the same IP cannot be joined.
        rotated.host=pinned.host
        for attempt in rotated.attempts:attempt['attempt']+=2
        result=assess_phase_evidence([pinned,rotated],{'tls_timeout'})
        self.assertEqual(1,len(result['repeated_paths']))
        self.assertEqual('same-ip',result['repeated_paths'][0]['context']['retry_mode'])


class FeatureCliTests(unittest.TestCase):
    def tearDown(self):set_language('en')

    def test_proxy_test_requires_explicit_consent_and_online_cli(self):
        with patch.object(cli,'load_settings',return_value={}),patch.object(cli,'scan') as scan,contextlib.redirect_stderr(io.StringIO()):
            for args in (['--cli','--proxy-paths'],['--cli','--proxy-paths','--confirm-proxy-paths','--no-network'],['--proxy-paths','--confirm-proxy-paths']):
                with self.assertRaises(SystemExit):cli.main(args)
        scan.assert_not_called()

    def test_retry_option_and_wfp_context_reach_scan(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'input.xml';path.write_text('<state/>')
            with patch.object(cli,'load_settings',return_value={}),patch.object(cli,'scan',return_value=empty_report('en')) as scan,contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0,cli.main(['--cli','--no-network','--retry-mode','rotate','--wfp-input',str(path)]))
            self.assertEqual('rotate',scan.call_args.kwargs['retry_mode']);self.assertEqual([],scan.call_args.kwargs['wfp_context']['ownership_records'])

    def test_explicit_proxy_diagnostics_are_separate_from_direct_probes(self):
        report=empty_report('en')
        with patch.object(cli,'load_settings',return_value={}),patch.object(cli,'scan',return_value=report),patch.object(cli,'with_proxy_path_evidence',return_value=report) as probe,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0,cli.main(['--cli','--proxy-paths','--confirm-proxy-paths']))
        self.assertTrue(probe.call_args.kwargs['confirmed'])


class FeatureParityTests(unittest.TestCase):
    def test_imported_raw_wfp_samples_never_enter_default_report(self):
        context={'ownership_records':[{'kind':'providers','object_key':KEYS[0],
            'provider_key':KEYS[0],'callout_key':'','service_name':'SyntheticSvc'}],
            'samples':[{'detail':'PrivateImportMarker '+KEYS[0]}],
            'matches':[{'detail':'PrivateImportMarker'}],'ownership_truncated':False,'counts':{'providers':1}}
        from winnetdiff.reports.export import evidence_text,markdown_report
        report=engine.with_wfp_context(empty_report('en'),context)
        for text in (evidence_text(report),markdown_report(report)):
            self.assertNotIn('PrivateImportMarker',text);self.assertNotIn(KEYS[0],text)
        self.assertNotIn('samples',report.security['wfp_context'])
    def test_generic_ownership_matches_generated_source(self):
        sec,routes=generic_inventory()
        self.assertEqual(associate_hosts(sec,routes),standalone.associate_hosts(sec,routes))

    def test_proxy_plan_matches_generated_source(self):
        proxy={'environ_process':{'HTTPS_PROXY':'proxy.example:80','NO_PROXY':'.bypass.example'}}
        self.assertEqual(proxy_path.proxy_path_plan(proxy,'www.example.com'),standalone.proxy_path_plan(proxy,'www.example.com'))

    def test_generic_corrobation_uses_real_rules_and_scenarios(self):
        sec,routes=generic_inventory();data=fixture()
        routes={**data['route'],**routes}
        graph_security(sec,routes)
        from winnetdiff.analysis.rules import analyze
        from winnetdiff.analysis.scenarios import evaluate_scenarios
        probes=[Probe(**row) for row in data['probes']]
        findings=analyze(data['proxy'],routes,probes,sec)
        self.assertTrue(any(f.evidence_grade=='E3' for f in findings))
        data['security']=sec;data['route']=routes
        scenario=next(s for s in evaluate_scenarios(data) if s['code']=='tcp_ok_tls_failure')
        self.assertEqual('E3',scenario['grade'])


@unittest.skipUnless(sys.platform=='win32','Withdrawn native Tk feature callbacks')
class FeatureGuiTests(unittest.TestCase):
    def tearDown(self):set_language('en')

    def exercise(self,callback,**options):
        from winnetdiff.gui import app
        import tkinter as tk
        from tkinter import messagebox
        def loop(root):
            root.withdraw()
            try:callback(root,root.winnetdiff_widgets,root.winnetdiff_state)
            finally:root.winnetdiff_close()
        with tempfile.TemporaryDirectory() as folder,patch.object(app,'default_output_dir',return_value=Path(folder)),patch.object(app,'load_settings',return_value={}),patch.object(app,'save_settings') as save,patch.object(tk.Tk,'mainloop',loop),patch.object(messagebox,'showerror') as errors:
            app.gui(**options)
        errors.assert_not_called();return save

    def wait(self,root,state):
        deadline=time.monotonic()+4
        while state['busy'] and time.monotonic()<deadline:root.update();time.sleep(.01)
        self.assertFalse(state['busy'])

    def test_rotating_choice_survives_language_change_scan_and_settings(self):
        from winnetdiff.gui import app
        def callback(root,widgets,state):
            widgets['retry_same_ip_var'].set(False)
            widgets['language_var'].set('繁體中文');widgets['change_language']()
            self.assertFalse(widgets['retry_same_ip_var'].get());widgets['run'].invoke();self.wait(root,state)
        with patch.object(app,'scan',return_value=empty_report('zh-TW')) as scan:
            save=self.exercise(callback,no_network=True)
        self.assertEqual('rotate',scan.call_args.kwargs['retry_mode']);self.assertEqual('rotate',save.call_args.args[0]['retry_mode'])

    def test_offline_and_declined_proxy_actions_send_nothing(self):
        from winnetdiff.gui import app
        from tkinter import messagebox
        report=empty_report('en');report.scan_options={'do_network':False}
        report.proxy_paths={'paths':[{'eligible':True,'source':'synthetic','host':'proxy.example','port':80}]}
        def callback(root,widgets,state):
            widgets['display_report'](report);widgets['request_proxy_paths']()
            report.scan_options['do_network']=True;widgets['passive_var'].set(False);widgets['request_proxy_paths']()
        with patch.object(app,'with_proxy_path_evidence') as probe,patch.object(messagebox,'showinfo'),patch.object(messagebox,'askyesno',return_value=False):
            self.exercise(callback,no_network=True)
        probe.assert_not_called()

    def test_proxy_worker_is_cancellable_and_preserves_scan_results(self):
        from winnetdiff.gui import app
        from tkinter import messagebox
        report=empty_report('en');report.scan_options={'do_network':True}
        report.proxy_paths={'paths':[{'eligible':True,'source':'synthetic','host':'proxy.example','port':80}]}
        threads=[]
        def measure(value,confirmed,cancel):
            threads.append(threading.get_ident());cancel.wait(1);return value
        def callback(root,widgets,state):
            widgets['display_report'](report);widgets['request_proxy_paths']()
            self.assertEqual('normal',str(widgets['cancel'].cget('state')))
            widgets['cancel'].invoke();self.wait(root,state);self.assertIs(report,state['report'])
        with patch.object(app,'with_proxy_path_evidence',side_effect=measure),patch.object(messagebox,'askyesno',return_value=True):
            self.exercise(callback)
        self.assertTrue(threads);self.assertNotEqual(threading.get_ident(),threads[0])

    def test_wfp_import_updates_context_without_os_commands(self):
        from winnetdiff.gui import app
        from tkinter import filedialog
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'synthetic.xml';path.write_text('<state/>')
            def callback(root,widgets,state):
                widgets['display_report'](empty_report('en'));widgets['request_wfp_input']();self.wait(root,state)
                self.assertEqual([],state['wfp_context']['ownership_records'])
                self.assertEqual('imported_snapshot',state['report'].security['ownership']['wfp_scope'])
            with patch.object(filedialog,'askopenfilename',return_value=str(path)),patch('subprocess.run',side_effect=AssertionError('No native commands for imported XML')):
                self.exercise(callback,no_network=True)

    def test_reopened_gui_resources_are_not_collected_on_worker_thread(self):
        code=r'''
import gc,tempfile,time
from pathlib import Path
from unittest.mock import patch
import tkinter as tk
from winnetdiff.gui import app
from tests.unit.test_i18n_safety_gui import empty_report
from tkinter import messagebox
def scan(**kwargs):
    gc.collect()
    return empty_report(kwargs['locale'])
def loop(root):
    root.withdraw();state=root.winnetdiff_state
    root.winnetdiff_widgets['run'].invoke();deadline=time.monotonic()+5
    while state['busy'] and time.monotonic()<deadline:
        root.update();time.sleep(.005)
    assert not state['busy'] and state['report'] is not None
    root.winnetdiff_close()
with tempfile.TemporaryDirectory() as folder,patch.object(app,'default_output_dir',return_value=Path(folder)),patch.object(app,'load_settings',return_value={}),patch.object(app,'save_settings'),patch.object(app,'scan',side_effect=scan),patch.object(tk.Tk,'mainloop',loop),patch.object(messagebox,'showerror') as error:
    for language in ('en','zh-CN','zh-TW'):app.gui(no_network=True,locale=language)
    assert not error.called
gc.collect()
print('reopened-gui-gc-ok')
'''
        run=subprocess.run([sys.executable,'-c',code],cwd=Path(__file__).resolve().parents[2],capture_output=True,timeout=35)
        self.assertEqual(0,run.returncode,run.stderr.decode('utf-8',errors='replace'))
        self.assertIn(b'reopened-gui-gc-ok',run.stdout)
        self.assertNotIn(b'Exception ignored',run.stderr)
        self.assertNotIn(b'Tcl_AsyncDelete',run.stderr)
