import http.client
from http.cookies import SimpleCookie
import json
import tempfile
import threading
import unittest
from pathlib import Path
import server

class Flows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        server.DB = Path(cls.temp.name) / 'test.db'
        server.initialize()
        cls.http = server.ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        threading.Thread(target=cls.http.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()
        cls.http.server_close()
        cls.temp.cleanup()

    def request(self, path, data=None, cookie='', app=None, device='a'*64, extra_headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.http.server_port)
        headers = {'Content-Type': 'application/json', 'Cookie': cookie, 'User-Agent': 'OuthMan-test', 'X-OuthMan-Device': device}
        headers.update(extra_headers or {})
        if app:
            headers.update({'X-OuthMan-App': app['app_id'], 'Authorization': 'Bearer ' + app['app_secret']})
        conn.request('POST' if data is not None else 'GET', path, json.dumps(data) if data is not None else None, headers)
        response = conn.getresponse()
        jar = SimpleCookie(); jar.load(cookie)
        for name, value in response.getheaders():
            if name.lower() == 'set-cookie': jar.load(value)
        result = response.status, json.loads(response.read()), '; '.join(k+'='+v.value for k,v in jar.items())
        conn.close()
        return result

    def test_full_lifecycle(self):
        status, body, admin = self.request('/api/login', {'username': 'admin@admin.com', 'password': 'pass123'})
        self.assertEqual(status, 200)
        self.assertTrue(body['user']['must_change'])
        self.assertEqual(self.request('/api/invitations', {'duration': 60}, admin)[0], 403)
        self.assertEqual(self.request('/api/code', {}, admin)[0], 403)
        status, _, admin = self.request('/api/change-credentials', {'username': 'owner@example.com', 'password': 'BetterPassword123!'}, admin)
        self.assertEqual(status, 200)
        self.assertEqual(self.request('/api/login', {'username': 'admin@admin.com', 'password': 'pass123'})[0], 401)
        self.assertEqual(self.request('/api/v1/enroll', {})[0], 403)
        self.assertEqual(self.request('/api/acl', {'networks': ['invalid']}, admin)[0], 400)
        self.assertEqual(self.request('/api/acl', {'networks': ['192.0.2.1']}, admin)[0], 200)
        self.assertEqual(self.request('/api/v1/enroll', {})[0], 403)
        self.assertEqual(self.request('/api/acl', {'networks': ['127.0.0.0/8', '::1']}, admin)[0], 200)
        self.assertEqual(self.request('/api/v1/enroll', {})[0], 401)
        status, invite, _ = self.request('/api/invitations', {'duration': 60}, admin)
        self.assertEqual(status, 200)
        self.assertEqual(len(invite['key']), 16)
        self.assertEqual(self.request('/api/check-invite', {'key': invite['key']})[0], 200)
        registration = {'key': invite['key'], 'username': 'cosine-user', 'password': 'StrongPassword123'}
        status, _, user = self.request('/api/register', registration)
        self.assertEqual(status, 202)
        self.assertEqual(user, '')
        _, accounts, _ = self.request('/api/admin', cookie=admin)
        pending_id = next(u['id'] for u in accounts['users'] if u['username']=='cosine-user')
        self.assertEqual(self.request('/api/users/approve', {'user_id': pending_id}, admin)[0], 200)
        status, _, user = self.request('/api/login', {'username': 'cosine-user', 'password': 'StrongPassword123'})
        self.assertEqual(status, 200)
        self.assertEqual(self.request('/api/register', dict(registration, username='second-user'))[0], 400)
        status, code, _ = self.request('/api/code', {}, user)
        self.assertEqual(status, 200)
        self.assertRegex(code['value'], r'^\d{6}$')
        self.assertLessEqual(code['expires_at'] - server.time.time(), 60)
        self.assertEqual(self.request('/api/admin', cookie=user)[0], 403)
        self.assertEqual(self.request('/api/acl', {'networks': []}, user)[0], 403)
        self.assertEqual(self.request('/api/invitations', {'duration': 60}, user)[0], 403)
        _, audit, _ = self.request('/api/admin', cookie=admin)
        self.assertEqual(audit['invitations'][0]['used_by'], 'cosine-user')
        self.assertTrue(any(e['ip'] == '127.0.0.1' and e['browser'] == 'OuthMan-test' for e in audit['events']))
        _, expired, _ = self.request('/api/invitations', {'duration': 30}, admin)
        with server.connect() as db:
            db.execute('UPDATE invitations SET expires_at=0 WHERE token=?', (server.digest(expired['key']),))
            db.execute('UPDATE codes SET expires_at=0')
        self.assertEqual(self.request('/api/check-invite', {'key': expired['key']})[0], 400)
        self.assertIsNone(self.request('/api/me', cookie=user)[1]['code'])
        # Integration secrets are provisioned only by an initialized admin.
        self.assertEqual(self.request('/api/apps', {'name': 'Unauthorized'}, user)[0], 403)
        status, app, _ = self.request('/api/apps', {'name': 'XYZ'}, admin)
        self.assertEqual(status, 201)
        self.assertEqual(len(app['app_secret']), 32)
        _, other_app, _ = self.request('/api/apps', {'name': 'Other'}, admin)
        uid = self.request('/api/me', cookie=user)[1]['user']['id']
        self.assertEqual(self.request('/api/groups', {'name': 'Allowed', 'user_ids': [uid], 'app_ids': [app['app_id']]}, user)[0], 403)
        self.assertEqual(self.request('/api/groups', {'name': 'Allowed', 'user_ids': [uid], 'app_ids': [app['app_id']]}, admin)[0], 200)
        def fresh_code():
            return self.request('/api/code', {}, user)[1]['value']
        enrollment = {'username': 'cosine-user', 'password': 'StrongPassword123', 'code': fresh_code()}
        self.assertEqual(self.request('/api/v1/enroll', enrollment)[0], 401)
        status, link, _ = self.request('/api/v1/enroll', enrollment, app=app)
        self.assertEqual(status, 201)
        self.assertEqual(len(link['user_key']), 32)
        self.assertIsNone(self.request('/api/me', cookie=user)[1]['code'])
        login = dict(enrollment, user_key=link['user_key'], request_id='unique-login-attempt-123', code=fresh_code())
        self.assertEqual(self.request('/api/v1/enroll', login, app=app)[0], 409)
        self.assertEqual(self.request('/api/v1/verify', dict(login, password='wrong'), app=app)[0], 401)
        self.assertEqual(self.request('/api/v1/verify', dict(login, user_key='wrong'), app=app)[0], 401)
        self.assertEqual(self.request('/api/v1/verify', login, app=other_app)[0], 403)
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.request('/api/v1/verify', login, app=app), range(2)))
        self.assertEqual(sorted(r[0] for r in results), [200, 401])
        receipt = next(r[1] for r in results if r[0] == 200)
        confirmation = {'username': 'cosine-user', 'auth_pin': receipt['auth_pin'], 'request_id': login['request_id']}
        self.assertEqual(self.request('/api/v1/confirm', dict(confirmation, request_id='wrong-session'), app=app)[0], 401)
        self.assertEqual(self.request('/api/v1/confirm', confirmation, app=other_app)[0], 403)
        status, confirmed, _ = self.request('/api/v1/confirm', confirmation, app=app)
        self.assertEqual(status, 200)
        self.assertTrue(confirmed['verified'])
        self.assertEqual(confirmed['user_id'], link['user_id'])
        self.assertEqual(self.request('/api/v1/confirm', confirmation, app=app)[0], 401)
        # Failed requests do not consume valid codes; expired codes never authenticate.
        login['code'] = fresh_code()
        with server.connect() as db:
            db.execute('UPDATE codes SET expires_at=0')
            db.execute('DELETE FROM attempts')
        self.assertEqual(self.request('/api/v1/verify', login, app=app)[0], 401)
        login['code'] = fresh_code()
        _, receipt, _ = self.request('/api/v1/verify', login, app=app)
        with server.connect() as db:
            db.execute('UPDATE auth_pins SET expires_at=0')
        self.assertEqual(self.request('/api/v1/confirm', dict(confirmation, auth_pin=receipt['auth_pin']), app=app)[0], 401)
        # Group changes immediately remove access and invalidate pending PINs.
        _, policies, _ = self.request('/api/admin', cookie=admin)
        group = next(g for g in policies['groups'] if g['name'] == 'Allowed')
        self.assertEqual(self.request('/api/groups', {'id': group['id'], 'name': 'Allowed', 'user_ids': [uid], 'app_ids': []}, admin)[0], 200)
        self.assertEqual(self.request('/api/v1/confirm', confirmation, app=app)[0], 403)
        self.request('/api/groups', {'id': group['id'], 'name': 'Allowed', 'user_ids': [uid], 'app_ids': [app['app_id']]}, admin)
        # Limits persist across sessions; five-minute block becomes suspension.
        self.assertEqual(self.request('/api/users/policy', {'user_id': uid, 'code_limit': 1, 'release': True}, user)[0], 403)
        self.assertEqual(self.request('/api/users/policy', {'user_id': uid, 'code_limit': 1, 'release': True}, admin)[0], 200)
        self.assertEqual(self.request('/api/code', {}, user)[0], 200)
        self.assertEqual(self.request('/api/code', {}, user)[0], 423)
        self.assertIsNone(self.request('/api/me', cookie=user)[1]['code'])
        self.assertEqual(self.request('/api/login', {'username': 'cosine-user', 'password': 'StrongPassword123'}, user)[0], 423)
        self.assertEqual(self.request('/api/v1/verify', login, app=app)[0], 423)
        with server.connect() as db:
            db.execute('UPDATE users SET blocked_at=? WHERE id=?', (server.time.time()-301, uid))
        self.assertIn('suspended', self.request('/api/code', {}, user)[1]['error'])
        self.request('/api/users/policy', {'user_id': uid, 'code_limit': None, 'release': True}, admin)
        self.assertEqual(self.request('/api/code', {}, user)[0], 200)
        # Request logging includes ACL denials and successful calls, without payloads.
        self.request('/api/acl', {'networks': []}, admin)
        self.assertEqual(self.request('/api/v1/enroll', {'password': 'never-log-this'}, app=app)[0], 403)
        # Wait for request completion: the HTTP reply can arrive before log commit.
        import time
        for _ in range(100):
            _, logged, _ = self.request('/api/admin', cookie=admin)
            if logged['api_requests'] and logged['api_requests'][0]['status'] == 403:
                break
            time.sleep(.01)
        self.assertTrue(any(r['status'] == 201 for r in logged['api_requests']))
        self.assertTrue(any(r['status'] == 401 for r in logged['api_requests']))
        self.assertEqual(logged['api_requests'][0]['ip'], '127.0.0.1')
        self.assertNotIn('never-log-this', json.dumps(logged))
        self.assertEqual(set(logged['api_requests'][0]), {'created_at', 'method', 'endpoint', 'ip', 'client', 'status'})
        self.request('/api/acl', {'networks': ['127.0.0.1']}, admin)
        # No secret appears in admin list responses; revocation disables every API call.
        _, admin_data, _ = self.request('/api/admin', cookie=admin)
        self.assertNotIn('app_secret', admin_data['apps'][0])
        self.assertNotIn('key_hash', admin_data['apps'][0])
        self.request('/api/apps/revoke', {'app_id': app['app_id']}, admin)
        self.assertEqual(self.request('/api/v1/verify', login, app=app)[0], 401)
        for _ in range(10):
            self.request('/api/v1/verify', login, app=app)
        self.assertEqual(self.request('/api/v1/verify', login, app=app)[0], 429)
        self.request('/api/logout', {}, user)
        self.assertIsNone(self.request('/api/me', cookie=user)[1]['user'])
        self.assertEqual(self.request('/api/login', {'username': 'cosine-user', 'password': 'StrongPassword123'}, user)[0], 200)

if __name__ == '__main__':
    unittest.main()
