import base64
import http.client
import json
from pathlib import Path
import tempfile
import subprocess
from unittest.mock import patch
import threading
import unittest

import backups
import backup_service
import server


class BackupFlows(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = server.DB
        server.DB = Path(self.temp.name) / 'test.db'
        server.initialize()
        self.http = server.ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.cookie = ''
        self.request('/api/login', {'username': 'admin@admin.com', 'password': 'pass123'})
        self.request('/api/change-credentials', {'username': 'backup-owner', 'password': 'BetterPassword123!'})

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.temp.cleanup()
        server.DB = self.old_db

    def request(self, path, data=None, cookie=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.http.server_port)
        connection.request('GET' if data is None else 'POST', path,
                           None if data is None else json.dumps(data),
                           {'Content-Type': 'application/json', 'Cookie': self.cookie if cookie is None else cookie, **(headers or {})})
        response = connection.getresponse()
        raw = response.read()
        if cookie is None and response.getheader('Set-Cookie'):
            self.cookie = response.getheader('Set-Cookie').split(';')[0]
        body = json.loads(raw) if response.getheader('Content-Type') == 'application/json' else raw
        status = response.status
        connection.close()
        return status, body

    def test_encrypted_round_trip_and_access_controls(self):
        secret = 'a long private backup passphrase'
        self.assertEqual(self.request('/api/backups', {'passphrase': secret})[0], 403)
        self.request('/api/acl', {'networks': ['127.0.0.1']})
        self.assertEqual(self.request('/api/backups', cookie='')[0], 403)
        self.assertEqual(self.request('/api/backups', {'passphrase': 'short'})[0], 400)
        self.request('/api/apps', {'name': 'Before restore'})
        self.request('/api/code', {})
        status, created = self.request('/api/backups', {'passphrase': secret})
        self.assertEqual(status, 201)
        self.assertEqual(self.request('/api/backups')[1]['backups'][0]['id'], created['id'])
        status, encrypted = self.request('/api/backups/' + created['id'])
        self.assertEqual(status, 200)
        self.assertTrue(encrypted.startswith(backups.MAGIC))
        self.assertNotIn(b'backup-owner', encrypted)
        self.assertNotIn(b'SQLite format', encrypted)
        self.assertEqual(self.request('/api/backups/' + created['id'], cookie='')[0], 403)
        self.assertEqual(self.request('/api/backups/../server.py')[0], 400)
        self.assertEqual(self.request('/api/backups/' + 'a'*32)[0], 404)
        self.request('/api/apps', {'name': 'After snapshot'})
        payload = {'backup': base64.b64encode(encrypted).decode(), 'passphrase': secret, 'confirm': True}
        self.assertEqual(self.request('/api/backups/restore', dict(payload, confirm=False))[0], 400)
        self.assertEqual(self.request('/api/backups/restore', dict(payload, passphrase='wrong long passphrase'))[0], 400)
        damaged = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
        self.assertEqual(self.request('/api/backups/restore', dict(payload, backup=base64.b64encode(damaged).decode()))[0], 400)
        self.assertEqual(len(self.request('/api/admin')[1]['apps']), 2)
        old_cookie = self.cookie
        status, restored = self.request('/api/backups/restore', payload)
        self.assertEqual(status, 200)
        self.assertTrue(restored['ok'])
        self.assertEqual(self.request('/api/admin', cookie=old_cookie)[0], 403)
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT name FROM apps').fetchall()[0][0], 'Before restore')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM apps').fetchone()[0], 1)
            for table in backups.TRANSIENT:
                self.assertEqual(db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0], 0)
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])
        self.request('/api/login', {'username': 'backup-owner', 'password': 'BetterPassword123!'})
        recovery = self.request('/api/backups/' + restored['recovery_backup_id'])[1]
        self.assertTrue(recovery.startswith(backups.MAGIC))
        # The pre-restore recovery file really contains the later data.
        backups.restore(server.DB, recovery, secret)
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM apps').fetchone()[0], 2)

    def test_schedule_and_read_only_keys(self):
        self.request('/api/acl', {'networks': ['127.0.0.1']})
        phrase = 'scheduled private passphrase'
        self.assertEqual(self.request('/api/backups/schedule', {'enabled': True, 'interval_minutes': 5})[0], 410)
        saved = backup_service.configure(server.DB, {'enabled': True, 'interval_minutes': 5, 'passphrase': phrase})
        self.assertTrue(saved['schedule']['has_passphrase'])
        self.assertEqual(saved['mode'], 'external')
        self.assertFalse(saved['host_scheduler_enabled'])
        self.assertNotIn(phrase, json.dumps(saved))
        state = backup_service.configure(server.DB, {'enabled': True, 'interval_minutes': 5}, now=100)
        self.assertEqual(state['schedule']['next_run'], 400)
        self.assertIsNone(backup_service.tick(server.DB, now=399))
        created = backup_service.tick(server.DB, now=400)
        self.assertTrue(created['id'])
        state = backup_service.status(server.DB)
        self.assertEqual(state['schedule']['last_run'], 400)
        self.assertEqual(state['schedule']['next_run'], 700)
        self.assertIsNone(backup_service.tick(server.DB, now=401))
        with patch('backup_service.backups.create', side_effect=OSError('sensitive private path')):
            self.assertIsNone(backup_service.tick(server.DB, now=700))
        failed = backup_service.status(server.DB)['schedule']
        self.assertEqual(failed['next_run'], 1000)
        self.assertNotIn('sensitive private path', failed['last_error'])
        key_path, config_path = backup_service.paths(server.DB)
        self.assertNotIn(phrase.encode(), config_path.read_bytes())
        self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
        status, issued = self.request('/api/backups/keys', {'name': 'Collector'})
        self.assertEqual(status, 201)
        headers = {'Authorization': 'Bearer ' + issued['api_key']}
        self.assertEqual(self.request('/api/backups', cookie='', headers=headers)[0], 200)
        self.assertEqual(self.request('/api/backups/latest', cookie='', headers=headers)[1], backups.path_for(server.DB, created['id']).read_bytes())
        # Exercise the exact curl header-from-stdin pattern in the user guide.
        downloaded = subprocess.run(['curl', '--fail', '--silent', '-H', '@-', f'http://127.0.0.1:{self.http.server_port}/api/backups/latest'], input=('Authorization: Bearer ' + issued['api_key'] + '\n').encode(), capture_output=True, check=True)
        self.assertTrue(downloaded.stdout.startswith(backups.MAGIC))
        self.assertEqual(self.request('/api/backups/' + created['id'], cookie='', headers=headers)[0], 200)
        self.assertEqual(self.request('/api/backups/status', cookie='', headers=headers)[0], 403)
        self.assertEqual(self.request('/api/backups', {'passphrase': phrase}, cookie='', headers=headers)[0], 403)
        self.assertEqual(self.request('/api/backups/restore', {'confirm': True}, cookie='', headers=headers)[0], 403)
        self.assertEqual(self.request('/api/backups/keys', {'name': 'Escalate'}, cookie='', headers=headers)[0], 403)
        state = self.request('/api/backups/status')[1]
        self.assertNotIn(issued['api_key'], json.dumps(state))
        self.assertNotIn('hash', state['keys'][0])
        self.assertNotIn(issued['api_key'].encode(), config_path.read_bytes())
        self.request('/api/acl', {'networks': []})
        self.assertEqual(self.request('/api/backups/latest', cookie='', headers=headers)[0], 403)
        self.request('/api/acl', {'networks': ['127.0.0.1']})
        self.request('/api/backups/keys/revoke', {'id': issued['id']})
        self.assertEqual(self.request('/api/backups/latest', cookie='', headers=headers)[0], 401)
        backup_service.configure(server.DB, {'enabled': False, 'interval_minutes': 5})
        self.assertIsNone(backup_service.tick(server.DB, now=99999))
        self.assertFalse(backup_service.status(server.DB)['schedule']['enabled'])

    def test_schema_rejected_before_modification(self):
        secret = 'another private backup passphrase'
        self.request('/api/acl', {'networks': ['127.0.0.1']})
        with server.connect() as db:
            db.execute('CREATE TABLE unexpected(value TEXT)')
        created = backups.create(server.DB, secret)
        encrypted = backups.path_for(server.DB, created['id']).read_bytes()
        with server.connect() as db:
            db.execute('DROP TABLE unexpected')
        with self.assertRaisesRegex(ValueError, 'schema'):
            backups.restore(server.DB, encrypted, secret)
        self.assertEqual(self.request('/api/admin')[0], 200)
        self.assertEqual(len(backups.listing(server.DB)), 1)


if __name__ == '__main__':
    unittest.main()
