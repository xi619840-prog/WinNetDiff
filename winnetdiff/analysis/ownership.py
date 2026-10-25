"""Vendor-independent, evidence-labelled host associations; never removal advice."""
from __future__ import annotations
import ntpath
import re
from typing import Any
from winnetdiff.core.models import Finding
from winnetdiff.core.messages import msg
from winnetdiff.collectors.security import normalize_binary_path


def ownership_path(value: Any) -> str:
    text = str(value or '').strip().strip('"').replace('/', '\\')
    if not re.match(r'^[A-Za-z]:\\', text) or any(part == '..' for part in text.split('\\')):
        return ''
    return ntpath.normpath(text).casefold()


def _host_location(value: Any) -> str:
    path = ownership_path(value).rstrip('\\')
    # A root/shared container is not an application's ownership boundary.
    if not ntpath.splitdrive(path)[1].strip('\\') or ntpath.basename(path) in ('windows', 'system32', 'syswow64', 'drivers', 'program files', 'program files (x86)', 'programdata', 'users', 'common files'):
        return ''
    return path


def _owner_publisher(value: Any) -> str:
    text = str(value or '').strip().casefold()
    match = re.search(r'(?:^|,)\s*o\s*=\s*("[^"]+"|[^,]+)', text)
    return (match.group(1).strip('" ') if match else text).strip()


def associate_hosts(security: dict, routes: dict | None = None, wfp: dict | None = None) -> dict:
    """Keep exact links separate from possible publisher matches and unknowns.

    Missing uninstall registration alone is never generic orphan evidence.
    Imported WFP XML is historical configuration context, not a live filter test.
    """
    routes, wfp = routes or {}, wfp or {}
    completeness = security.get('completeness') or {}
    limits = {'apps': 2048, 'services': 4096, 'network_links': 4096, 'edges': 8192}
    apps = security.get('installed_apps') or []
    registry = security.get('service_registry') or []
    sources = ('services_wmi', 'drivers_wmi', 'driverquery')
    runtime = [(source, row) for source in sources if completeness.get(source) is True
               for row in security.get(source, [])]
    names = sorted({str(row.get('Name') or '').casefold() for _, row in runtime} |
                   {str(row.get('Name') or '').casefold() for row in registry})
    bounded = len(apps) <= limits['apps'] and len(names) <= limits['services']
    apps = apps[:limits['apps']]
    files = {ownership_path(row.get('Path')): row for row in security.get('files', [])}
    nodes, edges, components = [], [], []
    edge_truncated = [False]
    def edge(row):
        if len(edges) < limits['edges']: edges.append(row)
        else: edge_truncated[0] = True
    for index, app in enumerate(apps):
        nodes.append({'node_id': f'app:{index}', 'kind': 'installed_application',
                      'name': app.get('DisplayName'), 'path': app.get('InstallLocation')})
    links: dict[str, list[dict]] = {}
    legacy_names = {str(row.get('Name') or '').casefold() for row in security.get('evidence', [])}
    for binding in routes.get('bindings', []):
        owner = binding.get('OwnerEvidence') or {}
        services = [owner.get('Service')]
        co = owner.get('CoServices') or []
        services += [co] if isinstance(co, str) else co if isinstance(co, list) else []
        for name in services:
            if isinstance(name, str) and name.strip():
                links.setdefault(name.casefold(), []).append({'kind': 'ndis_service',
                    'component_id': binding.get('ComponentID'), 'enabled': binding.get('Enabled'),
                    'live': routes.get('query_status', {}).get('bindings') == 'ok'})
    providers: dict[str, list[dict]] = {}
    for row in wfp.get('ownership_records', []):
        if row.get('kind') == 'providers' and row.get('object_key') and row.get('service_name'):
            providers.setdefault(row['object_key'].casefold(), []).append(row)
    object_rows: dict[str, list] = {}
    for row in wfp.get('ownership_records', []):
        if row.get('object_key'):
            object_rows.setdefault(row['object_key'].casefold(), []).append(row)
    for key, objects in object_rows.items():
        if len(objects) != 1: continue
        row = objects[0]
        nodes.append({'node_id': 'wfp:' + key, 'kind': row.get('kind'), 'object_key': key})
        parent = row.get('callout_key') if row.get('kind') == 'filters' and row.get('callout_key') else row.get('provider_key')
        if parent and parent != key and len(object_rows.get(parent.casefold(), [])) == 1:
            edge({'source_id': 'wfp:' + key, 'target_id': 'wfp:' + parent.casefold(), 'relation': 'wfp_explicit_key_reference'})
    for key, records in providers.items():
        if len(records) != 1:
            continue  # Conflicting duplicate keys cannot establish a host.
        row = records[0]
        edge({'source_id':'wfp:' + key, 'target_id':'service:' + row['service_name'].casefold(), 'relation':'wfp_provider_service'})
        links.setdefault(row['service_name'].casefold(), []).append({
            'kind': 'wfp_provider_service', 'provider_key': key, 'live': False,
            'linked_objects': sum(item.get('provider_key', '').casefold() == key
                                  for item in wfp.get('ownership_records', []) if item.get('kind') != 'providers')})
    link_count = sum(map(len, links.values()))
    bounded = bounded and link_count <= limits['network_links'] and not wfp.get('ownership_truncated')
    for name in sorted((set(links) | legacy_names) - set(names))[:limits['services']]:
        nodes.append({'node_id': 'service:' + name, 'kind': 'service_or_driver', 'name': name, 'state': 'not_observed'})
        components.append({'Name':name, 'Status':'host_not_observed', 'Running':False,
            'Path':'', 'OwnerApps':[], 'PossibleHosts':[], 'NetworkLinks':links.get(name,[])[:32],
            'RuntimeSources':[], 'RegistrationPresent':False, 'Inconsistency':'',
            'File':{}, 'EligibleCorroboration':False})
    for name in names[:limits['services']]:
        if not name or name not in links and name not in legacy_names:
            continue
        peers = [(source, row) for source, row in runtime if str(row.get('Name') or '').casefold() == name]
        registered = [row for row in registry if str(row.get('Name') or '').casefold() == name]
        images = {ownership_path(normalize_binary_path(row.get('PathName', ''))) for _, row in peers} | {ownership_path(normalize_binary_path(row.get('PathName', ''))) for row in registered}
        images.discard('')
        image = next(iter(images)) if len(images) == 1 else ''
        # Alias registration at the exact same binary is explicit counterevidence.
        alias_registered = bool(image) and any(ownership_path(normalize_binary_path(row.get('PathName', ''))) == image for row in registry)
        metadata = files.get(image, {})
        running = any(row.get('Started') is True or str(row.get('State') or '').casefold() in
                      ('running', '运行中', '正在运行', '執行中') for _, row in peers)
        owners, possible = [], []
        for index, app in enumerate(apps):
            location = _host_location(app.get('InstallLocation'))
            if image and location and image.startswith(location + '\\'):
                owners.append(app.get('DisplayName') or f'app:{index}')
                edge({'source_id': 'service:' + name, 'target_id': f'app:{index}', 'relation': 'binary_within_install_location'})
            elif (metadata.get('SignatureStatus') == 'Valid' and metadata.get('Publisher')
                  and _owner_publisher(metadata['Publisher']) == _owner_publisher(app.get('Publisher'))):
                possible.append(app.get('DisplayName') or f'app:{index}')
                edge({'source_id': 'service:' + name, 'target_id': f'app:{index}', 'relation': 'possible_shared_signer_only'})
        network = links.get(name, [])[:32]
        concrete_network = any(link['kind'] == 'ndis_service' and link['live'] and link['enabled'] is True for link in network)
        complete_absence = bounded and completeness.get('installed_apps') is True and completeness.get('service_registry') is True
        inconsistency = ('registration_missing' if not registered and not alias_registered else
                         'running_binary_missing' if metadata.get('Exists') is False else '')
        status = ('owner_installed' if owners else 'owner_possible' if possible else
                  'inventory_incomplete' if not complete_absence else
                  'orphan_evidence' if running and concrete_network and inconsistency and bool(image) else 'owner_unknown')
        row = {'Name': next((str(p.get('Name')) for _, p in peers), name), 'Status': status,
               'Running': running, 'Path': image, 'OwnerApps': owners, 'PossibleHosts': possible,
               'NetworkLinks': network, 'RuntimeSources': sorted({source for source, _ in peers}),
               'RegistrationPresent': bool(registered or alias_registered), 'Inconsistency': inconsistency,
               'File': metadata, 'EligibleCorroboration': status == 'orphan_evidence'}
        if network or name in legacy_names: components.append(row)
        nodes.append({'node_id': 'service:' + name, 'kind': 'service_or_driver', 'name': row['Name'], 'path': image})
        for index, link in enumerate(network):
            target = f'network:{name}:{index}'
            nodes.append({'node_id': target, **link})
            edge({'source_id': target, 'target_id': 'service:' + name, 'relation': link['kind']})
    node_ids = {row['node_id'] for row in nodes}
    valid_edges = [row for row in edges if row['source_id'] in node_ids and row['target_id'] in node_ids]
    return {'schema_version': 1, 'nodes': nodes, 'edges': valid_edges, 'components': components,
            'bounded_complete': bounded and not edge_truncated[0] and len(valid_edges) == len(edges), 'limits': limits, 'wfp_scope': 'imported_snapshot' if wfp else 'not_supplied',
            'limitations': ['Exact service keys and binary paths describe association, not causation.',
                'Signed publisher-only matches remain possible shared hosts.',
                'Imported WFP state is historical and does not prove a currently active filter.']}


def ownership_findings(ownership: dict, existing: list | None = None) -> list[Finding]:
    known = {str(row.get('Name') or '').casefold() for row in existing or []}
    findings = []
    for row in ownership.get('components', []):
        if str(row['Name']).casefold() in known:
            continue
        status = row['Status']
        findings.append(Finding('可疑' if status == 'orphan_evidence' else '資訊', '安全/驅動',
            msg('Network component host association: {name}', name=row['Name']),
            __import__('json').dumps(row, ensure_ascii=False),
            msg('Host association is configuration evidence. Unknown or absent ownership does not prove a faulty driver.'),
            code='ownership.' + status, confidence='中', risk='read_only'))
    return findings
