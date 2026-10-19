"""Conservative TCP reconnaissance of pinned lab or authorized deployed IP; no NSE scripts."""
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from app.network.scope import LAB_IP, LAB_PORT, check_ssrf
from app.scanners.controlled import ControlledAdapter, ToolFailure, run_process, RULES_DIR


class NmapScanner(ControlledAdapter):
    tool, display_name = 'nmap', 'Nmap'

    def __init__(self, profile='SAFE', check=None, port=None):
        if profile not in {'SAFE', 'STANDARD'}:
            raise ValueError('Invalid Nmap profile.')
        self.profile = profile
        self.check = check
        self.target_port = port or LAB_PORT

    def build_command(self, target):
        ip_str = str(target)
        if ip_str == LAB_IP:
            port = LAB_PORT
        else:
            check_ssrf(ip_str, allow_lab=False)
            port = self.target_port

        args = [
            self.validate_environment(),
            '-sT', '-Pn', '-n', '-T2',
            '--max-retries', '1',
            '--host-timeout', '45s',
            '-p', str(port)
        ]
        if self.profile == 'STANDARD':
            args += ['-sV', '--version-light']
        return args + ['-oX', '-', ip_str]

    def execute(self, target):
        result = run_process(self.build_command(target), cwd=RULES_DIR, seconds=60, check=self.check)
        if result.returncode != 0:
            raise ToolFailure('NMAP_EXIT_ERROR', 'Nmap failed to complete reconnaissance.')
        return result.stdout

    def scan(self, target):
        return self.parse(self.execute(target), target=str(target))

    def parse(self, output, target=LAB_IP):
        try:
            if b'<!ENTITY' in output.upper():
                raise ValueError('Entity declaration')
            root = ET.fromstring(output)
            if root.tag != 'nmaprun':
                raise ValueError('Wrong XML root')
            finished = root.find('./runstats/finished')
            if finished is None or finished.get('exit') != 'success':
                raise ValueError('Incomplete Nmap result')
            ports = []
            for host in root.findall('host'):
                if host.get('timedout') == 'true':
                    raise ToolFailure('TOOL_TIMEOUT', 'Nmap reached its host timeout.')
                for address in host.findall('address'):
                    if address.get('addrtype') in {'ipv4', 'ipv6'} and address.get('addr') != target:
                        raise ValueError('Unexpected host')
                for port in host.findall('./ports/port'):
                    number = int(port.get('portid', '0'))
                    if port.get('protocol') != 'tcp':
                        raise ValueError('Unexpected protocol')
                    state, service = port.find('state'), port.find('service')
                    if state is None:
                        raise ValueError('No port state')
                    ports.append({
                        'ip': target,
                        'port': number,
                        'protocol': 'tcp',
                        'state': state.get('state'),
                        'service': service.get('name', 'unknown')[:80] if service is not None else 'unknown',
                        'product': service.get('product', '')[:120] if service is not None else '',
                        'version': service.get('version', '')[:80] if service is not None else ''
                    })
            if not ports:
                raise ValueError('No port results')
            return {'ports': ports}
        except ToolFailure:
            raise
        except (ET.ParseError, ValueError, TypeError):
            raise ToolFailure('MALFORMED_OUTPUT', 'Nmap returned incomplete or invalid XML.') from None

    def normalize(self, raw_data, project_id):
        # An open port alone is reconnaissance, not a fabricated vulnerability.
        return []
