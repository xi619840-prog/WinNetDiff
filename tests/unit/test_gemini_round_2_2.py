"""Gemini 2.2.0a1 incremental review regressions.

Synthetic inventories and mocked OS commands only: no network, registry, service
or firewall writes. A stronger E3 grade is corroboration, not culprit proof.
"""
import copy
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch
from winnetdiff.analysis.evidence import corroborating_orphans, assess_phase_evidence
from winnetdiff.collectors.security import classify_security, inspect_security_files
from winnetdiff.collectors.dns_audit import audit_dns_state, collect_dns_runtime
from winnetdiff.core.privacy import redact, redacted_data
from winnetdiff.core.messages import msg
from winnetdiff.core.models import Finding, Probe, SEVERITIES
from winnetdiff.core import engine
from winnetdiff import cli

ROOT = Path(__file__).resolve().parents[2]


def fixture():
    return json.loads((ROOT / 'tests/fixtures/orphaned_endpoint_security_filter.json').read_text(encoding='utf-8'))


def realistic_security():
    """A synthetically invented Surfshark/Avira inventory, not an actual user log."""
    data = {
        'installed_apps': [], 'service_registry': [
            {'Name': 'EndpointProtectionService', 'PathName': r'C:\Program Files\Surfshark\Endpoint Protection SDK\endpointprotection.exe'}],
        'services_wmi': [
            {'Name': 'EndpointProtectionService', 'State': 'Running', 'PathName': r'C:\Program Files\Surfshark\Endpoint Protection SDK\endpointprotection.exe'}],
        'drivers_wmi': [
            {'Name': 'BdNet', 'DisplayName': 'Avira Network Filter', 'State': 'Running', 'PathName': r'C:\Windows\System32\drivers\BdNet.sys'}],
        'driverquery': [],
        'antivirus_products': [{'displayName':'Surfshark', 'pathToSignedProductExe':r'C:\Program Files\Surfshark\Surfshark.exe'}],
        'files': [
            {'Path':r'C:\Program Files\Surfshark\Endpoint Protection SDK\endpointprotection.exe','Exists':True},
            {'Path':r'C:\Windows\System32\drivers\BdNet.sys','Exists':True},
            {'Path':r'C:\Program Files\Surfshark\Surfshark.exe','Exists':False},
        ],
        'completeness': {'installed_apps':True, 'service_registry':True, 'services_wmi':True,
                         'drivers_wmi':True, 'driverquery':True, 'antivirus_products':True},
    }
    data['evidence'] = classify_security(data)
    return data


class RunningOrphanEvidenceTests(unittest.TestCase):
    def test_P0_non_ndis_running_driver_and_present_file_support_e3(self):
        inventory=realistic_security()
        refs=corroborating_orphans(inventory, {'bindings': [{'Enabled':True, 'OwnerEvidence':{'Service':'Tcpip'}}]})
        names={e['Name'] for e in refs}
        self.assertIn('BdNet', names)
        self.assertIn('EndpointProtectionService', names)
        self.assertTrue(all(e['Running'] is True for e in refs))
        report=fixture()
        assessment=assess_phase_evidence(report['probes'], {'tls_timeout'}, corroboration=refs)
        self.assertEqual(assessment['grade'],'E3')
        self.assertTrue(assessment['persistent_multitarget'])

    def test_P0_installed_owner_cannot_be_reclassified_as_orphan(self):
        data=realistic_security()
        data['installed_apps']=[{'DisplayName':'Surfshark', 'Publisher':'Surfshark', 'InstallLocation':r'C:\Program Files\Surfshark'}]
        data['evidence']=classify_security(data)
        self.assertFalse(corroborating_orphans(data, {'bindings':[]}))

    def test_P0_shared_endpoint_requires_independent_related_orphan_clue(self):
        data=realistic_security()
        data['service_registry'].append({'Name':'BdNet','PathName':r'C:\Windows\System32\drivers\BdNet.sys'})
        data['evidence']=classify_security(data)
        bdnet=next(e for e in data['evidence'] if e['Name']=='BdNet')
        self.assertEqual(bdnet['Status'],'owner_unknown')
        self.assertEqual(bdnet['Group'],'SharedEndpoint')
        self.assertIn('BdNet',{e['Name'] for e in corroborating_orphans(data, {})})
        data['services_wmi']=[];data['service_registry']=[x for x in data['service_registry'] if x['Name']=='BdNet']
        data['antivirus_products']=[]
        data['evidence']=classify_security(data)
        self.assertFalse(corroborating_orphans(data, {}))

    def test_P0_incomplete_installed_inventory_cannot_prove_absence(self):
        data=realistic_security()
        data['completeness']['installed_apps']=False
        data['evidence']=classify_security(data)
        self.assertFalse(corroborating_orphans(data, {}))

    def test_P0_missing_independent_runtime_is_not_a_corrobating_record(self):
        data=realistic_security()
        data['services_wmi']=[];data['drivers_wmi']=[]
        data['evidence']=classify_security(data)
        self.assertFalse(corroborating_orphans(data, {}))

    def test_P0_nonrunning_driver_or_registration_status_alone_is_not_enough(self):
        data=realistic_security()
        for row in data['drivers_wmi']:
            row['State']='Stopped'
        for row in data['services_wmi']:
            row['State']='Stopped'
        data['evidence']=classify_security(data)
        self.assertFalse(corroborating_orphans(data, {}))

    def test_P0_unknown_shared_component_without_related_provider_is_not_enough(self):
        data=realistic_security()
        data['services_wmi']=[];data['service_registry']=[];data['antivirus_products']=[]
        # A registered, owner-unknown shared driver without a related orphan
        # provider does not qualify merely because a vendor-like name matches.
        data['service_registry']=[{'Name':'BdNet','PathName':r'C:\Program Files\SharedVendor\BdNet.sys'}]
        data['drivers_wmi'][0]['PathName']=r'C:\Program Files\SharedVendor\BdNet.sys'
        data['files']=[{'Path':r'C:\Program Files\SharedVendor\BdNet.sys','Exists':True}]
        data['evidence']=classify_security(data)
        # Without a registered orphan provider, a shared product group alone
        # cannot be treated as an associated orphaned installation.
        self.assertFalse(corroborating_orphans(data, {}))


class PrivacyBoundaryTests(unittest.TestCase):
    def test_P1_path_cannot_consume_next_field(self):
        s=r'InstallDir=D:\SecretCompany\TopSecretFolder cmd=test.exe'
        output=redact(s)
        self.assertNotIn('TopSecretFolder',output)
        self.assertIn('cmd=test.exe',output)
        self.assertIn('<local-path>',output)

    def test_P1_quoted_path_with_spaces_removes_private_directories(self):
        s=r'Path="D:\Internal Company\TopSecret\service.exe" command=run'
        self.assertNotIn('Internal Company',redact(s))
        self.assertNotIn('TopSecret',redact(s))
        self.assertIn('service.exe',redact(s))

    def test_P1_ambiguous_unquoted_path_with_spaces_does_not_leak_tail(self):
        s=r'D:\Sensitive Company\PrivateProject\tool.exe'
        output=redact(s)
        self.assertNotIn('Sensitive',output)
        self.assertNotIn('PrivateProject',output)

    def test_P1_install_location_directory_keeps_no_leaf(self):
        content=redacted_data({'InstallLocation':r'D:\SecretCompany\TopSecretProject'})
        self.assertEqual(content['InstallLocation'],'<local-path>')

    def test_P1_driver_file_can_retain_safe_file_name(self):
        content=redacted_data({'PathName':r'D:\Private\Subfolder\driver.sys'})
        self.assertEqual(content['PathName'],'<local-path>/driver.sys')

    def test_P1_directory_like_file_without_extension_is_hidden(self):
        content=redacted_data({'Path':r'D:\Confidential\SensitiveFolder'})
        self.assertEqual(content['Path'],'<local-path>')


class SeverityAndDnsTests(unittest.TestCase):
    def test_P1_engine_sort_matches_rules_confirmed_before_suspicious(self):
        import types
        confirmed=Finding('已確認設定異常','代理','Synthetic dead local proxy','sample','configured',priority=3)
        suspicious=Finding('可疑','TCP/TLS','Synthetic TLS timeout','sample','not proven',priority=1)
        # Execute the real engine post-processing path. The collectors and
        # network are mocked, but engine.scan must preserve severity ordering.
        with patch.object(engine,'os',types.SimpleNamespace(name='nt')),\
             patch.object(engine,'is_admin',return_value=False),\
             patch.object(engine,'collect_proxy',return_value={}),\
             patch.object(engine,'collect_routes',return_value={'errors':[]}),\
             patch.object(engine,'collect_security',return_value={'errors':[]}),\
             patch.object(engine,'analyze',return_value=[suspicious,confirmed]):
            report=engine.scan(['synthetic.example'],do_network=False,fake_ip_audit=False)
        self.assertEqual([f.severity for f in report.findings[:2]], ['已確認設定異常','可疑'])
        self.assertIs(report.findings[0],confirmed)

    def test_P1_empty_target_route_falls_back_to_active_dns(self):
        routes={'query_status':{'routes':'ok','interfaces':'ok'},'interfaces':[
            {'InterfaceIndex':2,'AddressFamily':2,'ConnectionState':'Connected'},
            {'InterfaceIndex':3,'AddressFamily':2,'ConnectionState':'Disconnected'}],
            'adapters':[], 'routes':[],
            'dns_servers':[{'InterfaceIndex':2,'ServerAddresses':['198.18.0.2']},
                           {'InterfaceIndex':3,'ServerAddresses':['192.168.1.1']}]}
        probes=[{'host':'synthetic.example','ip':'198.18.1.2','resolved_addresses':['198.18.1.2'],
            'attempts':[{'ip':'198.18.1.2','stage':'tcp_timeout'}]}]
        runtime={'cores':[],'core_query_complete':True,'listeners':[],'listener_query_complete':True}
        result=audit_dns_state(routes,probes,runtime,network_tested=True)
        target=result['targets'][0]
        self.assertEqual(target['route_context']['status'],'no_usable_route')
        self.assertEqual(target['status'],'fake_ip_unroutable_suspected')
        self.assertEqual([d['address'] for d in target['configured_dns']],['198.18.0.2'])

    def test_P1_scalar_ServerAddresses_does_not_split_into_chars(self):
        routes={'query_status':{'routes':'ok','interfaces':'ok'},'interfaces':[],
                'routes':[], 'dns_servers':[{'InterfaceIndex':2,'ServerAddresses':'127.0.0.1'}]}
        with patch('winnetdiff.collectors.dns_audit.ps_json',return_value=([],'')) as cmd:
            runtime=collect_dns_runtime(routes)
        self.assertEqual(cmd.call_count,2)   # core and loopback-listener inventory
        result=audit_dns_state(routes,[],runtime,network_tested=False)
        self.assertEqual(len(result['dns_servers']),1)
        self.assertEqual(result['dns_servers'][0]['address'],'127.0.0.1')

    def test_P1_selected_target_route_uses_exact_interface_dns(self):
        routes={'query_status':{'routes':'ok','interfaces':'ok'},'interfaces':[
            {'InterfaceIndex':2,'AddressFamily':2,'ConnectionState':'Connected','InterfaceMetric':10}],
            'adapters':[{'ifIndex':2,'Status':'Up','Classification':'physical'}],
            'routes':[{'InterfaceIndex':2,'DestinationPrefix':'198.18.0.0/15','RouteMetric':1}],
            'dns_servers':[{'InterfaceIndex':2,'ServerAddresses':'10.0.0.53'}]}
        probe={'host':'synthetic.example','ip':'198.18.1.2','resolved_addresses':['198.18.1.2'],
               'attempts':[{'ip':'198.18.1.2','stage':'tcp_timeout'}]}
        result=audit_dns_state(routes,[probe],{'core_query_complete':False,'cores':[]},network_tested=True)
        target=result['targets'][0]
        self.assertEqual(target['status'],'fake_ip_indeterminate')
        self.assertEqual(target['configured_dns'][0]['address'],'10.0.0.53')


class CommandBoundariesAndMessagesTests(unittest.TestCase):
    def test_P2_long_security_paths_split_batches_under_encoded_command_budget(self):
        import winnetdiff.collectors.security as sec
        captured=[]
        paths=['C:\\VeryLongCompany\\'+('NestedFolder'*6)+f'\\component_{i:03d}.sys' for i in range(120)]
        def fake_ps(script, timeout):
            captured.append(script)
            match=re.search(r"\$paths = ConvertFrom-Json '(.+?)'",script)
            self.assertIsNotNone(match)
            selected=json.loads(match.group(1).replace("''", "'"))
            self.assertLessEqual(len(selected),25)
            return ([{'Path':item,'Exists':False} for item in selected], '')
        with patch.object(sec,'ps_json',side_effect=fake_ps):
            rows,errors=inspect_security_files(paths)
        self.assertFalse(errors)
        self.assertEqual(len(rows),len(paths))
        self.assertGreater(len(captured),1)
        self.assertTrue(all(len(sec.base64.b64encode(script.encode('utf-16le')))<21000 for script in captured))

    def test_P2_single_huge_path_is_unknown_not_called_as_invalid_command(self):
        import winnetdiff.collectors.security as sec
        huge='C:\\VeryLongCompany\\'+('LongDirectory'*900)+r'\component.sys'
        with patch.object(sec,'ps_json') as call:
            rows,errors=inspect_security_files([huge])
        self.assertEqual(len(rows),1)
        self.assertIsNone(rows[0]['Exists'])
        self.assertTrue(errors)
        call.assert_not_called()

    def test_P3_Message_braces_without_parameters_are_literal(self):
        token='{4d36e972-e325-11ce-bfc1-08002be10318}'
        self.assertEqual(msg('Network adapter '+token),'Network adapter '+token)
        self.assertEqual(msg('Sample: {name}',name=token),'Sample: '+token)

    def test_crossplatform_CLI_seam_can_be_mocked_without_changing_global_os_name(self):
        self.assertTrue(callable(cli._live_audit_supported))
        with patch.object(cli,'_live_audit_supported',return_value=True):
            self.assertTrue(cli._live_audit_supported())
        # We do NOT patch os.name globally; pathlib remains POSIX on Linux.
        self.assertIn(cli._live_audit_supported(), (True,False))


if __name__=='__main__':
    unittest.main()
