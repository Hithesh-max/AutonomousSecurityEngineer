"""Tests send requests only to a temporary loopback lab server."""
import threading
import unittest
from urllib.request import urlopen
from urllib.parse import urlencode
from http.server import ThreadingHTTPServer
from app import Handler

class LabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = 'http://127.0.0.1:'+str(cls.server.server_port)
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()
    def get(self, path):
        with urlopen(self.base+path, timeout=3) as response: return response.read().decode()
    def test_health_and_discovery(self):
        self.assertEqual(self.get('/health'),'ASE_LAB_READY')
        self.assertIn('/echo?text=hello',self.get('/'))
    def test_seeded_reflection(self):
        payload='<script>alert(1)</script>'
        self.assertIn(payload,self.get('/echo?'+urlencode({'text':payload})))
    def test_seeded_sql_injection_and_ephemeral_data(self):
        self.assertNotIn('bob',self.get('/search?q=alice'))
        self.assertIn('bob',self.get('/search?'+urlencode({'q':"alice' OR '1'='1"})))
        self.assertNotIn('bob',self.get('/search?q=alice'))

if __name__ == '__main__': unittest.main()
