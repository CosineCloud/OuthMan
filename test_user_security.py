from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

import backups
import server
import test_server


class UserSecurity(unittest.TestCase):
    request = test_server.Flows.request

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous_db = server.DB
        server.DB = Path(self.temp.name) / 'test.db'
        server.initialize()
        self.http = server.ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        _, _, self.admin = self.request('/api/login', {'username': 'admin@admin.com', 'password': 'pass123'})
        _, _, self.admin = self.request('/api/change-credentials', {'username': 'security-admin', 'password': 'StrongAdmin123!'}, self.admin)
        _, invite, _ = self.request('/api/invitations', {'duration': 600}, self.admin)
        self.registration = {'username': 'invited-user', 'password': 'StrongUser123!', 'key': invite['key']}
        self.credentials = {k: self.registration[k] for k in ('username', 'password')}
        status, result, cookie = self.request('/api/register', self.registration)
        self.assertEqual((status, result, cookie), (202, {'pending_approval': True}, ''))
        _, admin_data, _ = self.request('/api/admin', cookie=self.admin)
        self.uid = next(u['id'] for u in admin_data['users'] if u['username'] == 'invited-user')

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.temp.cleanup()
        server.DB = self.previous_db

    def approve(self):
        self.assertEqual(self.request('/api/users/approve', {'user_id': self.uid}, self.admin)[0], 200)

    def test_pending_approval_first_binding_and_generic_errors(self):
        pending = self.request('/api/login', self.credentials)
        wrong = self.request('/api/login', dict(self.credentials, password='wrong'))
        self.assertEqual(pending[0], wrong[0])
        self.assertTrue(pending[1]['error'].startswith('Incorrect username or password.'))
        self.assertTrue(wrong[1]['error'].startswith('Incorrect username or password.'))
        self.assertEqual(self.request('/api/code', {})[0], 401)
        self.request('/api/acl', {'networks': ['127.0.0.1']}, self.admin)
        _, app, _ = self.request('/api/apps', {'name': 'Security test'}, self.admin)
        self.assertEqual(self.request('/api/v1/enroll', dict(self.credentials, code='123456'), app=app)[0], 401)
        self.assertEqual(self.request('/api/users/approve', {'user_id': self.uid})[0], 401)
        self.approve()
        self.assertEqual(self.request('/api/login', self.credentials, device='')[0], 401)
        status, user, browser_a = self.request('/api/login', self.credentials)
        self.assertEqual(status, 200)
        self.assertTrue(user['user']['device_bound'])
        self.assertNotIn('bound_hash', user['user'])
        self.assertIn('outhman_device=', browser_a)
        self.assertEqual(self.request('/api/code', {}, browser_a)[0], 200)
        self.assertEqual(self.request('/api/login', self.credentials, browser_a)[0], 200)
        different_browser = self.request('/api/login', self.credentials, device='b'*64)
        self.assertEqual(different_browser[0], 401)
        self.assertTrue(different_browser[1]['error'].startswith('Incorrect username or password.'))
        self.assertNotIn('device', different_browser[1]['error'])
        self.assertEqual(self.request('/api/login', self.credentials, browser_a, device='b'*64)[0], 401)
        # A copied session cookie alone or a changed fingerprint cannot use an existing session.
        self.assertIsNone(self.request('/api/me', cookie=browser_a, device='b'*64)[1]['user'])
        session_only = '; '.join(c for c in browser_a.split('; ') if c.startswith('outhman='))
        self.assertIsNone(self.request('/api/me', cookie=session_only)[1]['user'])
        self.assertEqual(self.request('/api/code', {}, browser_a, device='b'*64)[0], 401)
        self.assertEqual(self.request('/api/users/release-device', {'user_id': self.uid}, browser_a)[0], 403)
        self.assertEqual(self.request('/api/users/approve', {'user_id': self.uid}, browser_a)[0], 403)
        self.assertEqual(self.request('/api/users/release-device', {'user_id': 1}, self.admin)[0], 400)

    def test_release_invalidates_and_rebinds_exactly_one_browser(self):
        self.approve()
        _, _, old_cookie = self.request('/api/login', self.credentials)
        self.request('/api/code', {}, old_cookie)
        with server.connect() as db:
            db.execute('INSERT INTO apps VALUES(?,?,?,?,NULL)', ('security-app', 'test', 'hash', 0))
            db.execute('INSERT INTO auth_pins VALUES(?,?,?,?,?)', ('pin', 'security-app', self.uid, 'request', 9999999999))
        self.assertEqual(self.request('/api/users/release-device', {'user_id': self.uid}, self.admin)[0], 200)
        self.assertIsNone(self.request('/api/me', cookie=old_cookie)[1]['user'])
        with server.connect() as db:
            for table in ('sessions', 'codes', 'auth_pins'):
                self.assertEqual(db.execute(f'SELECT COUNT(*) FROM {table} WHERE user_id=?', (self.uid,)).fetchone()[0], 0)
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda fp: self.request('/api/login', self.credentials, device=fp), ['b'*64, 'c'*64]))
        self.assertEqual(sorted(r[0] for r in outcomes), [200, 401])
        self.assertEqual(self.request('/api/login', self.credentials, old_cookie)[0], 401)

    def test_three_failures_admin_release_and_reset(self):
        self.approve()
        _, _, cookie = self.request('/api/login', self.credentials)
        self.assertEqual(self.request('/api/users/release-login', {'user_id': self.uid}, cookie)[0], 403)
        first = self.request('/api/login', dict(self.credentials, password='wrong'))
        self.assertEqual(first[0], 401)
        self.assertEqual(first[1]['attempts_remaining'], 2)
        self.assertEqual(self.request('/api/login', self.credentials, cookie)[0], 200)
        # Success resets the counter; device failures count without disclosing binding.
        self.assertEqual(self.request('/api/login', self.credentials, device='b'*64)[1]['attempts_remaining'], 2)
        second = self.request('/api/login', dict(self.credentials, username='INVITED-USER', password='wrong'))
        self.assertEqual(second[1]['attempts_remaining'], 1)
        third = self.request('/api/login', self.credentials, device='')
        self.assertEqual(third[0], 423)
        self.assertEqual(third[1]['attempts_remaining'], 0)
        self.assertEqual(self.request('/api/login', self.credentials, cookie)[0], 423)
        self.assertIsNone(self.request('/api/me', cookie=cookie)[1]['user'])
        with server.connect() as db:
            row = db.execute('SELECT * FROM users WHERE id=?', (self.uid,)).fetchone()
            self.assertEqual((row['login_failures'], row['login_locked']), (3, 1))
            self.assertIsNotNone(row['bound_hash'])
            for table in ('sessions', 'codes', 'auth_pins'):
                self.assertEqual(db.execute(f'SELECT COUNT(*) FROM {table} WHERE user_id=?', (self.uid,)).fetchone()[0], 0)
        self.assertEqual(self.request('/api/users/release-login', {'user_id': self.uid})[0], 401)
        self.assertEqual(self.request('/api/users/release-login', {'user_id': self.uid}, self.admin)[0], 200)
        self.assertEqual(self.request('/api/login', self.credentials, cookie)[0], 200)
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT login_failures,login_locked FROM users WHERE id=?', (self.uid,)).fetchone()[:], (0, 0))

    def test_suspend_resume_and_delete_user(self):
        self.approve()
        _, _, cookie = self.request('/api/login', self.credentials)
        for action in ('suspend', 'resume', 'delete'):
            self.assertEqual(self.request('/api/users/'+action, {'user_id': self.uid, 'confirm': True}, cookie)[0], 403)
            self.assertEqual(self.request('/api/users/'+action, {'user_id': 1, 'confirm': True}, self.admin)[0], 400)
        self.request('/api/code', {}, cookie)
        self.assertEqual(self.request('/api/users/suspend', {'user_id': self.uid}, self.admin)[0], 200)
        self.assertEqual(self.request('/api/login', self.credentials, cookie)[0], 423)
        self.assertIsNone(self.request('/api/me', cookie=cookie)[1]['user'])
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM codes WHERE user_id=?', (self.uid,)).fetchone()[0], 0)
        self.request('/api/users/release-login', {'user_id': self.uid}, self.admin)
        self.assertEqual(self.request('/api/login', self.credentials, cookie)[0], 423)
        self.assertEqual(self.request('/api/users/resume', {'user_id': self.uid}, self.admin)[0], 200)
        _, _, cookie = self.request('/api/login', self.credentials, cookie)
        self.assertEqual(self.request('/api/code', {}, cookie)[0], 200)
        with server.connect() as db:
            db.execute('INSERT INTO apps VALUES(?,?,?,?,NULL)', ('delete-app', 'test', 'hash', 0))
            db.execute('INSERT INTO app_users VALUES(?,?,?,?)', ('delete-app', self.uid, 'key-hash', 0))
            gid = db.execute("INSERT INTO access_groups(name) VALUES('Delete test')").lastrowid
            db.execute('INSERT INTO group_users VALUES(?,?)', (gid, self.uid))
        self.assertEqual(self.request('/api/users/delete', {'user_id': self.uid}, self.admin)[0], 400)
        self.assertEqual(self.request('/api/users/delete', {'user_id': self.uid, 'confirm': True}, self.admin)[0], 200)
        self.assertEqual(self.request('/api/login', self.credentials, cookie)[0], 401)
        self.assertIsNone(self.request('/api/me', cookie=cookie)[1]['user'])
        self.assertEqual(self.request('/api/users/approve', {'user_id': self.uid}, self.admin)[0], 400)
        admin_data = self.request('/api/admin', cookie=self.admin)[1]
        self.assertNotIn(self.uid, [u['id'] for u in admin_data['users']])
        self.assertTrue(any('Deleted account' in e['action'] for e in admin_data['events']))
        with server.connect() as db:
            for table in ('sessions', 'codes', 'auth_pins', 'app_users', 'group_users'):
                self.assertEqual(db.execute(f'SELECT COUNT(*) FROM {table} WHERE user_id=?', (self.uid,)).fetchone()[0], 0)
            tombstone = db.execute('SELECT * FROM users WHERE id=?', (self.uid,)).fetchone()
            self.assertNotEqual(tombstone['username'], self.credentials['username'])
            self.assertIsNotNone(tombstone['deleted_at'])
        _, invite, _ = self.request('/api/invitations', {'duration': 600}, self.admin)
        self.assertEqual(self.request('/api/register', dict(self.credentials, key=invite['key']))[0], 202)
        admin_data = self.request('/api/admin', cookie=self.admin)[1]
        new_id = next(u['id'] for u in admin_data['users'] if u['username']==self.credentials['username'])
        self.assertNotEqual(new_id, self.uid)

    def test_older_backup_requires_approval_and_migration_keeps_current_users(self):
        self.approve()
        _, _, cookie = self.request('/api/login', self.credentials)
        server.initialize()
        self.assertIsNotNone(self.request('/api/me', cookie=cookie)[1]['user'])
        legacy_path = Path(self.temp.name) / 'legacy.db'
        source = sqlite3.connect(server.DB)
        legacy = sqlite3.connect(legacy_path)
        source.backup(legacy)
        source.close()
        legacy.execute('DROP TABLE log_meta')
        for table in ('events', 'api_requests'):
            legacy.execute(f'DROP INDEX IF EXISTS {table}_app_id_idx')
            legacy.execute(f'ALTER TABLE {table} DROP COLUMN app_id')
        for name in ('approved', 'bound_hash', 'bound_at', 'bound_browser'):
            legacy.execute(f'ALTER TABLE users DROP COLUMN {name}')
        legacy.commit()
        legacy.close()
        phrase = 'legacy backup private passphrase'
        result = backups.create(legacy_path, phrase)
        encrypted = backups.path_for(legacy_path, result['id']).read_bytes()
        backups.restore(server.DB, encrypted, phrase)
        with server.connect() as db:
            account = db.execute('SELECT * FROM users WHERE id=?', (self.uid,)).fetchone()
            self.assertEqual(account['approved'], 0)
            self.assertIsNone(account['bound_hash'])
            self.assertEqual(db.execute('SELECT approved FROM users WHERE is_admin=1').fetchone()[0], 1)


if __name__ == '__main__':
    unittest.main()
