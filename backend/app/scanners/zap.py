"""Authenticated, bounded ZAP API orchestration for the isolated lab and authorized deployed targets."""
import hashlib
import json
import re
import time
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
from urllib.error import URLError, HTTPError
from app.network.scope import (
    LAB_URL, ZAP_API, validate_lab_target, is_lab_target,
    resolve_and_verify_destination, sanitize_endpoint, sanitized_endpoint
)
from app.scanners.controlled import ToolFailure
from app.utils.redaction import redact_evidence

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class ZAPScanner:
    tool, display_name = 'zap', 'OWASP ZAP'

    def __init__(self, api_key, check=None, progress=None):
        if not isinstance(api_key, str) or len(api_key) < 32:
            raise ToolFailure('ZAP_CONFIGURATION_ERROR', 'A separate ZAP_API_KEY of at least 32 characters is required.')
        self.api_key, self.check = api_key, check
        self.progress = progress or (lambda stage, percent=None: None)
        self.opener = build_opener(ProxyHandler({}), NoRedirect())
        self.spider_id, self.active_id = None, None

    def validate_environment(self):
        return self.health_check()

    def request(self, component, kind, operation, params=None, *, check=True):
        if check and self.check:
            self.check()
        url = f'{ZAP_API}/JSON/{component}/{kind}/{operation}/?' + urlencode(params or {})
        try:
            request = Request(url, headers={'X-ZAP-API-Key': self.api_key, 'Accept': 'application/json'})
            with self.opener.open(request, timeout=8) as response:
                payload = response.read(2 * 1024 * 1024 + 1)
            if len(payload) > 2 * 1024 * 1024:
                raise ToolFailure('OUTPUT_LIMIT', 'ZAP response exceeded its limit.')
            data = json.loads(payload)
            if not isinstance(data, dict) or 'code' in data:
                raise ToolFailure('ZAP_API_ERROR', 'ZAP rejected an API operation. Check its version and installed add-ons.')
            return data
        except ToolFailure:
            raise
        except (URLError, HTTPError, TimeoutError, OSError, ValueError):
            raise ToolFailure('ZAP_UNAVAILABLE', 'ZAP is unreachable, not ready, unauthorized, or returned invalid JSON.') from None

    def action(self, component, operation, params=None):
        result = self.request(component, 'action', operation, params)
        if result.get('Result') != 'OK':
            raise ToolFailure('ZAP_API_ERROR', 'ZAP did not acknowledge a configuration change.')

    def health_check(self):
        version = self.request('core', 'view', 'version').get('version')
        if not isinstance(version, str) or not re.fullmatch(r'[0-9][0-9A-Za-z.+_-]{0,40}', version):
            raise ToolFailure('MALFORMED_OUTPUT', 'ZAP version is invalid.')
        return {'tool': 'zap', 'version': version, 'policy_version': 'ase-web-1'}

    def poll(self, component, scan_id, stage, seconds):
        deadline = time.monotonic() + seconds
        last = None
        while time.monotonic() < deadline:
            data = self.request(component, 'view', 'status', {'scanId': scan_id})
            try:
                percentage = int(data['status'])
            except (KeyError, ValueError, TypeError):
                raise ToolFailure('MALFORMED_OUTPUT', 'ZAP progress is invalid.') from None
            if not 0 <= percentage <= 100:
                raise ToolFailure('MALFORMED_OUTPUT', 'ZAP progress is invalid.')
            if percentage != last:
                self.progress(stage, percentage)
                last = percentage
            if percentage == 100:
                return
            time.sleep(1)
        raise ToolFailure('TOOL_TIMEOUT', 'ZAP did not complete within the phase time limit.')

    def drain_passive(self):
        self.progress('PASSIVE_ANALYSIS')
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                count = int(self.request('pscan', 'view', 'recordsToScan')['recordsToScan'])
            except (KeyError, ValueError, TypeError):
                raise ToolFailure('MALFORMED_OUTPUT', 'ZAP passive queue is invalid.') from None
            if count == 0:
                return
            time.sleep(1)
        raise ToolFailure('TOOL_TIMEOUT', 'ZAP passive analysis did not drain in time.')

    def execute(self, target=LAB_URL, *, active=False, explicit_scope=None):
        is_lab = is_lab_target(target) or target in (LAB_URL, LAB_URL + '/')
        if is_lab:
            validate_lab_target(target)
            target_url = LAB_URL
            scope_regex = r'^http://ase-lab:8080(?:/.*)?$'
            context_name = 'ASE-LAB'
        else:
            # Validate deployed application destination with SSRF check
            resolve_and_verify_destination(target, explicit_scope)
            target_url = target.rstrip('/')
            parsed = urlsplit(target_url)
            escaped_host = re.escape(parsed.netloc)
            scope_regex = rf'^{parsed.scheme}://{escaped_host}(?:/.*)?$'
            context_name = f'ASE-{re.sub(r"[^A-Za-z0-9]", "-", parsed.hostname)[:20]}'

        self.health_check()
        # Caller holds global lease: reset sessions to prevent cross-scan contamination
        self.action('spider', 'stopAllScans')
        self.action('ascan', 'stopAllScans')
        self.action('core', 'newSession', {'name': '', 'overwrite': 'true'})
        self.action('core', 'setMode', {'mode': 'protect'})

        context = self.request('context', 'action', 'newContext', {'contextName': context_name})
        context_id = context.get('contextId')
        if not str(context_id).isdigit():
            raise ToolFailure('MALFORMED_OUTPUT', 'ZAP context ID is invalid.')

        self.action('context', 'includeInContext', {'contextName': context_name, 'regex': scope_regex})
        self.action('context', 'setContextInScope', {'contextName': context_name, 'booleanInScope': 'true'})
        self.action('spider', 'setOptionMaxDuration', {'Integer': 1})
        self.action('spider', 'setOptionThreadCount', {'Integer': 2})
        self.action('spider', 'setOptionMaxDepth', {'Integer': 3})
        self.action('pscan', 'setScanOnlyInScope', {'onlyInScope': 'true'})

        started = self.request('spider', 'action', 'scan', {
            'url': target_url + '/',
            'maxChildren': 10,
            'recurse': 'true',
            'contextName': context_name,
            'subtreeOnly': 'true'
        })
        self.spider_id = started.get('scan')
        if not str(self.spider_id).isdigit():
            raise ToolFailure('MALFORMED_OUTPUT', 'ZAP spider ID is invalid.')

        crawl_began = time.monotonic()
        self.poll('spider', self.spider_id, 'CRAWLING', 90)
        if time.monotonic() - crawl_began >= 55:
            raise ToolFailure('INCOMPLETE_COVERAGE', 'Crawling reached its configured duration; coverage is unconfirmed.')

        self.drain_passive()

        urls = self.request('core', 'view', 'urls', {'baseurl': target_url}).get('urls', [])
        if not isinstance(urls, list) or not urls:
            raise ToolFailure('ZAP_DISCOVERY_EMPTY', 'ZAP did not discover target application endpoints.')
        if len(urls) > 500:
            raise ToolFailure('OUTPUT_LIMIT', 'ZAP discovery exceeded the endpoint limit.')

        endpoints = sorted({sanitize_endpoint(u, target_url, explicit_scope) for u in urls})

        if active:
            self.action('ascan', 'setOptionMaxScanDurationInMins', {'Integer': 4})
            self.action('ascan', 'setOptionMaxRuleDurationInMins', {'Integer': 4})
            self.action('ascan', 'setOptionThreadPerHost', {'Integer': 2})
            self.action('ascan', 'setOptionDelayInMs', {'Integer': 100})
            self.action('ascan', 'disableAllScanners')
            self.action('ascan', 'enableScanners', {'ids': '40012,40018'})
            self.action('ascan', 'setScannerAttackStrength', {'id': 40012, 'attackStrength': 'LOW'})
            self.action('ascan', 'setScannerAttackStrength', {'id': 40018, 'attackStrength': 'LOW'})

            started = self.request('ascan', 'action', 'scan', {
                'url': target_url + '/',
                'recurse': 'true',
                'inScopeOnly': 'true',
                'contextId': context_id
            })
            self.active_id = started.get('scan')
            if not str(self.active_id).isdigit():
                raise ToolFailure('MALFORMED_OUTPUT', 'ZAP active scan ID is invalid.')

            began = time.monotonic()
            self.poll('ascan', self.active_id, 'ACTIVE_TESTING', 270)
            if time.monotonic() - began >= 235:
                raise ToolFailure('INCOMPLETE_COVERAGE', 'Active testing reached its configured duration; coverage is unconfirmed.')
            self.drain_passive()

        alerts = []
        for start in range(0, 1001, 100):
            page = self.request('core', 'view', 'alerts', {'baseurl': target_url, 'start': start, 'count': 100}).get('alerts')
            if not isinstance(page, list):
                raise ToolFailure('MALFORMED_OUTPUT', 'ZAP alerts are invalid.')
            alerts.extend(page)
            if len(alerts) > 1000:
                raise ToolFailure('FINDING_LIMIT', 'ZAP exceeded the alert limit.')
            if len(page) < 100:
                break

        return {
            'alerts': alerts,
            'endpoints': endpoints,
            'active_testing': active,
            'spider_id': str(self.spider_id),
            'active_scan_id': str(self.active_id) if active else None,
            'target_url': target_url
        }

    def parse(self, raw):
        if not isinstance(raw, dict) or not isinstance(raw.get('alerts'), list):
            raise ToolFailure('MALFORMED_OUTPUT', 'ZAP result is invalid.')
        return raw

    def scan(self, target=LAB_URL, *, active=False, explicit_scope=None):
        return self.parse(self.execute(target, active=active, explicit_scope=explicit_scope))

    def stop(self):
        failures = []
        for component, scan_id in [('spider', self.spider_id), ('ascan', self.active_id)]:
            if scan_id is None:
                continue
            try:
                data = self.request(component, 'action', 'stop', {'scanId': scan_id}, check=False)
                if data.get('Result') != 'OK':
                    failures.append(component)
            except ToolFailure:
                failures.append(component)
        if failures:
            raise ToolFailure('ZAP_STOP_UNCONFIRMED', 'Unable to confirm ZAP stopped; restart the ZAP container before another scan.')

    def normalize(self, raw, project_id, explicit_scope=None):
        target_url = raw.get('target_url', LAB_URL)
        findings, seen = [], set()
        try:
            for alert in raw['alerts']:
                rule = str(alert['pluginId'])
                if not rule.isdigit():
                    raise ValueError('Bad rule')
                endpoint = sanitize_endpoint(alert['url'], target_url, explicit_scope)
                method = str(alert.get('method', 'GET')).upper()
                if method not in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'}:
                    raise ValueError('Bad method')
                parameter = str(alert.get('param', ''))[:120]
                evidence = redact_evidence({
                    'tool': 'zap',
                    'rule': rule,
                    'endpoint': endpoint,
                    'method': method,
                    'parameter': parameter,
                    'scanner_evidence': str(alert.get('evidence', ''))[:500],
                    'http_message_id': str(alert.get('messageId', ''))[:40],
                    'raw_http_stored': False,
                    'active_testing_enabled': raw['active_testing']
                })
                fingerprint = hashlib.sha256(
                    json.dumps([rule, endpoint, method, parameter, evidence['scanner_evidence']], sort_keys=True).encode()
                ).hexdigest()
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                severity = {
                    '0': 'INFO', '1': 'LOW', '2': 'MEDIUM', '3': 'HIGH',
                    'INFORMATIONAL': 'INFO', 'LOW': 'LOW', 'MEDIUM': 'MEDIUM', 'HIGH': 'HIGH'
                }[str(alert['risk']).upper()]
                confidence = {
                    '0': 'LOW', '1': 'LOW', '2': 'MEDIUM', '3': 'HIGH', '4': 'HIGH',
                    'FALSE POSITIVE': 'LOW', 'LOW': 'LOW', 'MEDIUM': 'MEDIUM', 'HIGH': 'HIGH',
                    'CONFIRMED': 'HIGH', 'USER CONFIRMED': 'HIGH'
                }[str(alert['confidence']).upper()]
                cwe = str(alert.get('cweid', ''))
                findings.append({
                    'project_id': project_id,
                    'title': str(alert.get('name') or alert.get('alert') or 'ZAP finding')[:255],
                    'description': str(alert.get('description', 'Review scanner evidence.'))[:2000],
                    'source': 'DAST',
                    'category': 'WEB_APPLICATION',
                    'severity': severity,
                    'confidence': confidence,
                    'status': 'OPEN',
                    'source_tools': ['zap'],
                    'tool_rule_id': rule,
                    'fingerprint': fingerprint,
                    'endpoint': {'method': method, 'path': endpoint},
                    'parameter': parameter,
                    'evidence': evidence,
                    'cwe': 'CWE-' + cwe if cwe.isdigit() and cwe != '0' else None
                })
            return findings
        except (KeyError, ValueError, TypeError):
            raise ToolFailure('MALFORMED_OUTPUT', 'ZAP finding normalization failed.') from None
