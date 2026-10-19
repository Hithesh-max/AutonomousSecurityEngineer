"""Read-only authorization checks with explicit personas and pinned destinations."""
from datetime import datetime, timezone
import hashlib
import http.client
import socket
import ssl
import re
from urllib.parse import urlsplit, quote
from app.network.scope import resolve_and_verify_destination


def redact_auth_header(value):
    if not value: return ''
    if value.lower().startswith('bearer '): return 'Bearer [REDACTED_TOKEN]'
    if value.lower().startswith('basic '): return 'Basic [REDACTED_CREDENTIALS]'
    return '[REDACTED]'


class PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, hostname, port, ip, timeout):
        super().__init__(hostname, port, timeout=timeout)
        self.verified_ip = ip
    def connect(self):
        self.sock = socket.create_connection((self.verified_ip, self.port), self.timeout)


class PinnedHTTPS(PinnedHTTP):
    def connect(self):
        super().connect()
        self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)


def execute_auth_probe(url, method, headers, timeout_seconds=3, explicit_scope=None):
    if method not in {'GET', 'HEAD'}:
        raise PermissionError('Only GET/HEAD authorization probes are permitted.')
    ip = resolve_and_verify_destination(url, explicit_scope)
    parsed = urlsplit(url)
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    cls = PinnedHTTPS if parsed.scheme == 'https' else PinnedHTTP
    connection = cls(parsed.hostname, port, ip, timeout_seconds)
    try:
        # http.client sends to the verified IP with the original HTTP Host/TLS SNI.
        # No proxies, cookie jar, redirects or a second DNS lookup are used.
        path = parsed.path or '/'
        if parsed.query: path += '?' + parsed.query
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        body = response.read(65537)
        return {'status_code': response.status, 'error': None,
                'body_sha256': hashlib.sha256(body).hexdigest() if len(body) <= 65536 and body else None,
                'content_type': response.getheader('Content-Type', '').split(';')[0],
                'body_sample': '', 'headers': {k: redact_auth_header(v) if k.lower() == 'authorization' else v for k,v in headers.items()}}
    except (OSError, http.client.HTTPException):
        return {'status_code': None, 'error': 'Connection failed, timed out, or returned invalid HTTP.', 'body_sample': '', 'body_sha256': None}
    finally:
        connection.close()


def run_authorization_tests(base_url, endpoints, synthetic_users, explicit_scope=None):
    resolve_and_verify_destination(base_url, explicit_scope)
    tokens = {name: (synthetic_users.get(name) or {}).get('token') for name in ['USER_A','USER_B','ADMIN']}
    if not all(tokens.values()) or tokens['USER_A'] == tokens['USER_B']:
        raise ValueError('Provide distinct User A/User B tokens and an administrator token for controlled test accounts.')
    resource = (synthetic_users.get('USER_A') or {}).get('resource_id')
    if not resource or len(resource) > 200:
        raise ValueError("Provide the ID of an existing resource owned by User A.")
    results = []
    origin = urlsplit(base_url)
    def probe(path, persona, method):
        url = base_url.rstrip('/') + '/' + path.lstrip('/')
        parsed = urlsplit(url)
        if (parsed.scheme, parsed.hostname, parsed.port) != (origin.scheme, origin.hostname, origin.port):
            raise PermissionError('Probe must remain on the exact approved origin.')
        return execute_auth_probe(url, method, {'User-Agent':'ASE-AuthAudit/1.1','Authorization': 'Bearer '+tokens[persona]}, explicit_scope=explicit_scope)
    candidates = [ep for ep in endpoints if ep.get('bola_candidate') or ep.get('bfla_candidate')]
    for ep in candidates[:10]:
        path, method = ep['path'], ep['method']
        if not path.startswith('/') or path.startswith('//') or '?' in path or '#' in path or '\\' in path or '..' in path.split('/'):
            raise ValueError('OpenAPI probe paths must be relative paths without traversal or query fragments.')
        for category in ['BOLA', 'BFLA']:
            if not ep.get('bola_candidate' if category=='BOLA' else 'bfla_candidate'): continue
            result = {'test_type':category,'endpoint':path,'method':method,'status':'INCONCLUSIVE','observed_status_code':None,'finding_title':None}
            if method not in {'GET','HEAD'}:
                result['evidence']='Skipped: state-changing methods are not permitted.'
            elif not ep.get('security_required'):
                result['evidence']='Skipped: the specification does not declare authentication for this endpoint.'
            else:
                target_path = re.sub(r'\{[^{}]*id[^{}]*\}', quote(resource, safe=''), path, flags=re.IGNORECASE)
                if '{' in target_path or '}' in target_path:
                    result['evidence']='Skipped: additional path parameters require scenario configuration.'
                else:
                    control = probe(target_path, 'USER_A' if category=='BOLA' else 'ADMIN', method)
                    if control['status_code'] != 200:
                        result['evidence']='Authorized control request did not succeed; denial or resource absence cannot establish correct authorization.'
                    else:
                        other = probe(target_path, 'USER_B' if category=='BOLA' else 'USER_A', method)
                        result['observed_status_code']=other['status_code']
                        if other['status_code'] in {403,404}:
                            result['status']='SECURE';result['evidence']='Authorized control succeeded and the lower-privilege request was denied for this case.'
                        elif other['status_code']==200:
                            result['status']='ACCESS_GRANTED_REVIEW_REQUIRED'
                            same=bool(control.get('body_sha256')) and control.get('body_sha256')==other.get('body_sha256')
                            result['evidence']=f'Both control and lower-privilege requests returned 200. Response hashes match: {same}. Confirm object ownership, distinct roles and expected policy before declaring a vulnerability.'
                        else:
                            result['evidence']='Lower-privilege probe failed, redirected, or returned an inconclusive status.'
            results.append(result)
    return {'target_base_url':base_url,'tested_endpoints_count':len(results),
            'vulnerable_count':sum(r['status']=='ACCESS_GRANTED_REVIEW_REQUIRED' for r in results),
            'secure_count':sum(r['status']=='SECURE' for r in results),
            'inconclusive_count':sum(r['status']=='INCONCLUSIVE' for r in results),
            'results':results,'timestamp':datetime.now(timezone.utc).isoformat(),
            'limitations':['Only the first ten candidate endpoints are considered; GET/HEAD only.',
                'Access-granted alerts require human confirmation of resource ownership and roles; not verified vulnerabilities.',
                'Tokens are not stored; response bodies are not returned. Redirects are not followed.',
                'Expected authorization semantics, cookies, custom headers and multi-step workflows require dedicated scenarios.']}
