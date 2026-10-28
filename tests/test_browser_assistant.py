import json, functools, http.server, threading, unittest, os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FX = json.loads((ROOT / 'tests' / 'fixtures' / 'models.json').read_text())

class TestBrowserAssistant(unittest.TestCase):
    def test_assistant_page_with_mocked_providers(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest('playwright not installed')
        if not (ROOT / '_site' / 'assistant.html').exists():
            self.skipTest('site not built (python scripts/build_site.py)')
        fx = FX
        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(type('Q', (http.server.SimpleHTTPRequestHandler,), {'log_message': lambda *a: None}), directory=str(ROOT / '_site')))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f'http://127.0.0.1:{srv.server_address[1]}'
        KEY = 'gsk_' + 'A' * 52
        GK = 'AIza' + 'B' * 35
        seen = []
        def route_groq(r):
            req = r.request; seen.append((req.method, req.url, req.headers))
            cors = {'access-control-allow-origin': '*'}
            if req.url.endswith('/models'): return r.fulfill(json={'data': fx['groq']}, headers=cors)
            if len([s for s in seen if s[0] == 'POST']) == 1: return r.fulfill(status=429, json={}, headers=cors)
            return r.fulfill(json={'choices': [{'message': {'content': 'Signed with Ed25519 <img src=x onerror=alert(1)> and ' + GK}}]}, headers=cors)
        with sync_playwright() as p:
            b = p.chromium.launch(); pg = b.new_page()
            self.addCleanup(srv.shutdown)
            pg.route('https://api.groq.com/**', route_groq)
            pg.goto(base + '/assistant.html')
            self.assertTrue(pg.is_disabled('#as-q'))
            pg.fill('#as-key', 'sk-notakey'); pg.click('#as-connect'); self.assertIn('Unrecognised', pg.inner_text('#as-status'))
            pg.fill('#as-key', KEY); pg.click('#as-connect'); pg.wait_for_function("!document.getElementById('as-q').disabled")
            st = pg.inner_text('#as-status'); self.assertIn('Groq', st); self.assertIn('llama-3.3-70b-versatile', st)
            self.assertEqual(pg.input_value('#as-key'), '')
            pg.fill('#as-q', 'How is the ledger signed?'); pg.click('#as-send'); pg.wait_for_selector('.msg.bot')
            bot = pg.inner_text('.msg.bot')
            self.assertIn('onerror', bot); self.assertEqual(pg.locator('.msg.bot img').count(), 0)
            self.assertNotIn(GK, bot); self.assertIn('[REDACTED]', bot)
            posts = [s for s in seen if s[0] == 'POST']; self.assertEqual(len(posts), 2)
            self.assertEqual(posts[1][2]['authorization'], 'Bearer ' + KEY); self.assertNotIn(KEY, posts[1][1])
            pg.fill('#as-q', 'my key ' + KEY); pg.click('#as-send'); self.assertIn('credential', pg.inner_text('#as-status'))
            self.assertEqual(len([s for s in seen if s[0] == 'POST']), 2)
            pg.fill('#as-q', 'again'); pg.click('#as-send'); self.assertIn('Slow down', pg.inner_text('#as-status'))
            pg.click('#as-forget'); self.assertTrue(pg.is_disabled('#as-q'))
            self.assertEqual(pg.evaluate("fetch('https://example.com/x').then(()=>'ok',()=>'blocked')"), 'blocked')
            pg.set_viewport_size({'width': 375, 'height': 700}); self.assertTrue(pg.evaluate('document.documentElement.scrollWidth<=window.innerWidth'))
            b.close()


if __name__ == '__main__':
    unittest.main()
