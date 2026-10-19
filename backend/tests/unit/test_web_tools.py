import json
import socket
import unittest
from unittest.mock import patch
from app.network.scope import LAB_URL, LAB_IP, validate_lab_target, resolve_lab, sanitized_endpoint
from app.scanners.nmap import NmapScanner
from app.scanners.zap import ZAPScanner
from app.scanners.controlled import ToolFailure

class WebToolTests(unittest.TestCase):
    def test_only_exact_lab_target_allowed(self):
        self.assertEqual(validate_lab_target(LAB_URL+'/'), LAB_URL)
        for url in ['http://example.com','http://localhost:8080','http://127.0.0.1:8080','http://169.254.169.254',
                    'http://ase-lab:8080@evil.test','http://ase-lab:8080/evil','http://ase-lab:8080?url=evil','http://ase-lab:8080#x','https://ase-lab:8080']:
            with self.subTest(url=url), self.assertRaises(PermissionError): validate_lab_target(url)
    def test_dns_must_match_exact_lab_address(self):
        def answer(address): return (socket.AF_INET,socket.SOCK_STREAM,6,'',(address,8080))
        with patch('app.network.scope.socket.getaddrinfo',return_value=[answer(LAB_IP)]): self.assertEqual(resolve_lab(),LAB_IP)
        for addresses in [[],[answer('127.0.0.1')],[answer(LAB_IP),answer('1.1.1.1')]]:
            with patch('app.network.scope.socket.getaddrinfo',return_value=addresses),self.assertRaises(PermissionError): resolve_lab()
    def test_nmap_safe_arguments_are_fixed(self):
        with patch.object(NmapScanner,'validate_environment',return_value='/usr/bin/nmap'):
            safe = NmapScanner().build_command(LAB_IP)
            self.assertIn('-sT',safe); self.assertIn('-n',safe); self.assertNotIn('-sV',safe)
            self.assertEqual(safe[safe.index('-p')+1],'8080')
            self.assertIn('-sV',NmapScanner('STANDARD').build_command(LAB_IP))
            for value in ['--script=vuln','127.0.0.1',LAB_IP+'; echo x']:
                with self.assertRaises(PermissionError): NmapScanner().build_command(value)
    def test_nmap_real_xml_shape_and_no_invented_vulnerabilities(self):
        # Parser fixture only, never used by production scans.
        xml = b'<nmaprun><host><address addr="172.30.250.3" addrtype="ipv4"/><ports><port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="ASE lab" version="1"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'
        adapter = NmapScanner()
        result = adapter.parse(xml)
        self.assertEqual(result['ports'][0]['state'],'open')
        self.assertEqual(adapter.normalize(result,'project'),[])
        for bad in [b'not xml',xml.replace(b'172.30.250.3',b'127.0.0.1'),xml.replace(b'exit="success"',b'exit="error"'),b'<!ENTITY x "secret">'+xml]:
            with self.assertRaises(ToolFailure): adapter.parse(bad)
    def test_endpoint_scope_and_query_redaction(self):
        self.assertEqual(sanitized_endpoint(LAB_URL+'/search?q=PRIVATE#fragment'),LAB_URL+'/search')
        for url in ['http://evil.test/','http://user:password@ase-lab:8080/','http://ase-lab:9090/']:
            with self.assertRaises(PermissionError): sanitized_endpoint(url)
    def test_zap_named_risk_evidence_and_deduplication(self):
        adapter = ZAPScanner('x'*32)
        alert={'pluginId':'40012','url':LAB_URL+'/echo?text=PRIVATE','method':'GET','param':'text',
               'risk':'High','confidence':'Medium','name':'Reflected XSS','description':'Review input handling.',
               'evidence':'api_key=UNIT_PRIVATE_KEY','cweid':'79'}
        findings = adapter.normalize({'alerts':[alert,alert],'active_testing':True},'project')
        self.assertEqual(len(findings),1)
        self.assertEqual(findings[0]['severity'],'HIGH')
        self.assertEqual(findings[0]['confidence'],'MEDIUM')
        self.assertNotIn('PRIVATE',json.dumps(findings))
        self.assertEqual(findings[0]['cwe'],'CWE-79')
        with self.assertRaises(PermissionError): adapter.normalize({'alerts':[{**alert,'url':'http://outside.test/'}],'active_testing':True},'project')
        with self.assertRaises(ToolFailure): adapter.normalize({'alerts':[{**alert,'risk':'unknown'}],'active_testing':True},'project')
    def test_zap_rejects_missing_key_and_bad_output(self):
        with self.assertRaises(ToolFailure): ZAPScanner('')
        with self.assertRaises(ToolFailure): ZAPScanner('x'*32).parse({'alerts':'not a list'})
    def test_zap_revocation_stops_before_network_request(self):
        def reject(): raise PermissionError('Revoked')
        adapter = ZAPScanner('x'*32,check=reject)
        with patch.object(adapter.opener,'open') as send:
            with self.assertRaises(PermissionError): adapter.health_check()
            send.assert_not_called()
    def test_zap_timeout_is_not_success(self):
        adapter = ZAPScanner('x'*32)
        with self.assertRaises(ToolFailure): adapter.poll('spider','0','CRAWLING',0)
    def test_passive_workflow_never_starts_active_scanner(self):
        adapter = ZAPScanner('x'*32)
        calls=[]
        # API-control fixture only: it tests scope and active-opt-in, not scanner accuracy.
        def request(component,kind,operation,params=None,**kwargs):
            calls.append((component,kind,operation,params))
            if operation=='version':return {'version':'2.16.1'}
            if operation=='newContext':return {'contextId':'1'}
            if operation=='scan':return {'scan':'0'}
            if operation=='status':return {'status':'100'}
            if operation=='recordsToScan':return {'recordsToScan':'0'}
            if operation=='urls':return {'urls':[LAB_URL+'/']}
            if operation=='alerts':return {'alerts':[]}
            return {'Result':'OK'}
        with patch.object(adapter,'request',side_effect=request): adapter.scan(LAB_URL,active=False)
        self.assertFalse(any(c[0]=='ascan' and c[2]=='scan' for c in calls))
        inclusion=next(c for c in calls if c[2]=='includeInContext')
        self.assertEqual(inclusion[3]['regex'],r'^http://ase-lab:8080(?:/.*)?$')
        self.assertTrue(any(c[2]=='setMode' and c[3]['mode']=='protect' for c in calls))

if __name__ == '__main__': unittest.main()
