"""Structured service inventory parsed from managed nmap XML. It drives the methodology playbooks.

Facts come only from registered tool output, never from model text.
"""
import ipaddress
import xml.etree.ElementTree as ET
from .storage import atomic_json, read_json


def nmap_hosts(path):
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return []
    hosts = []
    for host in root.findall('host'):
        addr = host.find("address[@addrtype='ipv4']")  # Elements are falsy, so no "or" here
        if addr is None:
            addr = host.find('address')
        if addr is None:
            continue
        status = host.find('status')
        ports = {}
        for port in host.findall('ports/port'):
            state = port.find('state')
            if state is None or state.get('state') not in ('open', 'open|filtered'):
                continue
            svc = port.find('service')
            svc = svc.attrib if svc is not None else {}
            ports[f"{port.get('portid')}/{port.get('protocol')}"] = {
                'state': state.get('state'), 'service': svc.get('name', ''), 'product': svc.get('product', ''),
                'version': svc.get('version', ''), 'extrainfo': svc.get('extrainfo', ''),
                'tunnel': svc.get('tunnel', ''), 'probed': svc.get('method') == 'probed'}
        hosts.append({'address': addr.get('addr'), 'up': status is not None and status.get('state') == 'up',
                      'hostnames': sorted({h.get('name') for h in host.findall('hostnames/hostname') if h.get('name')}),
                      'ports': ports})
    return hosts


def address_key(address):
    try:
        ip = ipaddress.ip_address(address)
        return (0, ip.version, int(ip), '')
    except ValueError:
        return (1, 0, 0, address)


def port_key(key):
    number, _, proto = key.partition('/')
    return (proto, int(number) if number.isdigit() else 0)


class Facts:
    def __init__(self, workspace):
        self.ws = workspace
        self.path = workspace.root / 'facts.json'

    def load(self):
        data = read_json(self.path, {'hosts': {}})
        if not isinstance(data, dict) or not isinstance(data.get('hosts'), dict):
            raise ValueError('Invalid facts store')
        return data

    def ingest_nmap(self, xml_path, source):
        """Merge a scan. Version-probed values win; a later port-table guess never erases a probed banner."""
        with self.ws.lock:
            data = self.load()
            for found in nmap_hosts(xml_path):
                host = data['hosts'].setdefault(found['address'], {'up': False, 'hostnames': [], 'ports': {}})
                host['up'] = host['up'] or found['up']
                host['hostnames'] = sorted(set(host['hostnames']) | set(found['hostnames']))
                for key, new in found['ports'].items():
                    old = host['ports'].get(key)
                    if old is None or (new['probed'] and not old.get('probed')):
                        merged = dict(new)
                    else:
                        merged = dict(old)
                        for field, value in new.items():
                            if value and not merged.get(field):
                                merged[field] = value
                    merged['sources'] = sorted(set((old or {}).get('sources', [])) | {source})
                    host['ports'][key] = merged
            atomic_json(self.path, data)

    def services(self):
        """(address, 'port/proto', info) in a fixed order: address, protocol, port number."""
        hosts = self.load()['hosts']
        return [(addr, key, hosts[addr]['ports'][key])
                for addr in sorted(hosts, key=address_key)
                for key in sorted(hosts[addr]['ports'], key=port_key)]

    def describe(self, info):
        return ' '.join(x for x in (info.get('service'), info.get('product'), info.get('version'),
                                    info.get('extrainfo')) if x) or 'unknown service'

    def summary(self, limit=80):
        return [f"{addr} {key} {self.describe(info)}" + ('' if info.get('probed') else ' (not version-probed)')
                for addr, key, info in self.services()[:limit]]
