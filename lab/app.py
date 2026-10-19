"""Deliberately vulnerable, synthetic-data lab. Never deploy outside isolated ASE lab network."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import sqlite3
from urllib.parse import parse_qs, urlsplit

class Handler(BaseHTTPRequestHandler):
    server_version = 'ASETrainingLab/1.0'
    def log_message(self, format, *args):
        pass  # Do not log attack payloads, query strings, or request bodies.
    def do_GET(self):
        if len(self.path) > 8192:
            self.send_error(414); return
        parsed = urlsplit(self.path)
        try: query = parse_qs(parsed.query, max_num_fields=20)
        except ValueError:
            self.send_error(400); return
        status = 200
        if parsed.path == '/health':
            body = 'ASE_LAB_READY'
        elif parsed.path == '/':
            body = '''<html><head><title>ASE isolated training lab</title></head><body>
<h1>Intentionally vulnerable ASE lab</h1><p>Synthetic records only.</p>
<a href="/search?q=alice">Search</a><a href="/echo?text=hello">Echo</a>
<form action="/search" method="get"><input name="q" value="alice"><button>Search</button></form>
<form action="/echo" method="get"><input name="text" value="hello"><button>Echo</button></form>
</body></html>'''
        elif parsed.path == '/echo':
            # Intentional reflected XSS for the authorized scanner demonstration.
            body = '<html><body><h1>Echo</h1><div>' + query.get('text', ['hello'])[0] + '</div></body></html>'
        elif parsed.path == '/search':
            database = sqlite3.connect(':memory:')
            try:
                database.execute('CREATE TABLE invoices (owner TEXT, amount INTEGER)')
                database.executemany('INSERT INTO invoices VALUES (?, ?)', [('alice', 10), ('bob', 20)])
                # Intentional SQL injection; the database is recreated for each request.
                rows = database.execute("SELECT owner, amount FROM invoices WHERE owner = '" + query.get('q', ['alice'])[0] + "'").fetchall()
                body = '<html><body><h1>Invoices</h1><pre>' + html.escape(str(rows)) + '</pre></body></html>'
            except sqlite3.Error as error:
                status, body = 500, '<html><body>SQLite error: '+html.escape(str(error))+'</body></html>'
            finally: database.close()
        else:
            status, body = 404, 'Not found'
        raw = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        # Intentional missing security headers/cookie attributes for passive detection.
        self.send_header('Set-Cookie', 'lab_session=synthetic; Path=/')
        self.end_headers()
        self.wfile.write(raw)
    def do_POST(self):
        self.send_error(405)

if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
