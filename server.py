"""OuthMan local authentication server with encrypted backup support."""
import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import os
import re
from pathlib import Path
import secrets
import sqlite3
import time
import threading
import backups
import backup_service
import log_export
from urllib.parse import urlsplit
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).parent
DB = Path(os.environ.get('OUTHMAN_DB', str(ROOT / 'data' / 'outhman.sqlite3')))
SESSION_AGE = 8 * 3600
DATA_LOCK = threading.RLock()

def connect():
    db = sqlite3.connect(DB, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    return db

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

def password_hash(password):
    salt = secrets.token_hex(16)
    return salt + ':' + hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()

def password_ok(password, stored):
    salt, expected = stored.split(':')
    actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
    return hmac.compare_digest(actual, expected)

def initialize():
    DB.parent.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE, password TEXT NOT NULL, is_admin INTEGER DEFAULT 0, must_change INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id), expires_at REAL);
        CREATE TABLE IF NOT EXISTS invitations(id INTEGER PRIMARY KEY, token TEXT UNIQUE, created_at REAL, expires_at REAL, used_at REAL, used_by TEXT);
        CREATE TABLE IF NOT EXISTS codes(user_id INTEGER PRIMARY KEY REFERENCES users(id), value TEXT, expires_at REAL);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, action TEXT, username TEXT, ip TEXT, browser TEXT, created_at REAL);
        CREATE TABLE IF NOT EXISTS apps(id TEXT PRIMARY KEY, name TEXT NOT NULL, secret_hash TEXT NOT NULL, created_at REAL, revoked_at REAL);
        CREATE TABLE IF NOT EXISTS app_users(app_id TEXT REFERENCES apps(id), user_id INTEGER REFERENCES users(id), key_hash TEXT NOT NULL, created_at REAL, PRIMARY KEY(app_id,user_id));
        CREATE TABLE IF NOT EXISTS auth_pins(token_hash TEXT PRIMARY KEY, app_id TEXT REFERENCES apps(id), user_id INTEGER REFERENCES users(id), request_id TEXT NOT NULL, expires_at REAL);
        CREATE TABLE IF NOT EXISTS api_requests(id INTEGER PRIMARY KEY, created_at REAL NOT NULL, method TEXT, endpoint TEXT, ip TEXT, client TEXT, status INTEGER);
        CREATE TABLE IF NOT EXISTS log_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS api_acl(network TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS attempts(ip TEXT PRIMARY KEY, failures INTEGER, reset_at REAL);
        ''')
        for table in ('events', 'api_requests'):
            if 'app_id' not in {r['name'] for r in db.execute(f'PRAGMA table_info({table})')}:
                db.execute(f'ALTER TABLE {table} ADD COLUMN app_id TEXT')
            db.execute(f'CREATE INDEX IF NOT EXISTS {table}_app_id_idx ON {table}(app_id,id)')
        db.execute("INSERT OR IGNORE INTO log_meta VALUES('epoch',?)", (secrets.token_hex(16),))
        columns = {r['name'] for r in db.execute('PRAGMA table_info(users)')}
        for name, definition in [('code_limit', 'INTEGER'), ('code_count', 'INTEGER NOT NULL DEFAULT 0'), ('blocked_at', 'REAL'), ('approved', 'INTEGER NOT NULL DEFAULT 1'), ('bound_hash', 'TEXT'), ('bound_at', 'REAL'), ('bound_browser', 'TEXT'), ('login_failures', 'INTEGER NOT NULL DEFAULT 0'), ('login_locked', 'INTEGER NOT NULL DEFAULT 0'), ('suspended', 'INTEGER NOT NULL DEFAULT 0'), ('deleted_at', 'REAL')]:
            if name not in columns:
                db.execute(f'ALTER TABLE users ADD COLUMN {name} {definition}')
        first_groups = not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='access_groups'").fetchone()
        db.executescript("""
        CREATE TABLE IF NOT EXISTS access_groups(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
        CREATE TABLE IF NOT EXISTS group_users(group_id INTEGER REFERENCES access_groups(id), user_id INTEGER REFERENCES users(id), PRIMARY KEY(group_id,user_id));
        CREATE TABLE IF NOT EXISTS group_apps(group_id INTEGER REFERENCES access_groups(id), app_id TEXT REFERENCES apps(id), PRIMARY KEY(group_id,app_id));
        """)
        if first_groups:
            gid = db.execute("INSERT INTO access_groups(name) VALUES('Existing access')").lastrowid
            db.execute('INSERT INTO group_users SELECT ?,id FROM users', (gid,))
            db.execute('INSERT INTO group_apps SELECT ?,id FROM apps', (gid,))
        if not db.execute('SELECT 1 FROM users WHERE is_admin=1').fetchone():
            db.execute('INSERT INTO users(username,password,is_admin,must_change) VALUES(?,?,1,1)', ('admin@admin.com', password_hash('pass123')))
    os.chmod(DB, 0o600)

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT / 'public'), **kwargs)

    def log_message(self, fmt, *args):
        pass

    def end_headers(self):
        if not self.path.startswith('/api/'):
            self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'")
        super().end_headers()

    def reply(self, data, status=200, cookie=None):
        payload = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(payload)))
        if cookie:
            for value in cookie if isinstance(cookie, list) else [cookie]:
                self.send_header('Set-Cookie', value)
        self.end_headers()
        self.wfile.write(payload)

    def cookie_value(self, name):
        from http.cookies import SimpleCookie
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get('Cookie', ''))
            return cookie[name].value if name in cookie else ''
        except Exception:
            return ''

    def device_fingerprint(self):
        value = self.headers.get('X-OuthMan-Device', '')
        return value if re.fullmatch(r'[0-9a-f]{64}', value) else None

    def device_matches(self, account):
        fingerprint, token = self.device_fingerprint(), self.cookie_value('outhman_device')
        return bool(fingerprint and token and account['bound_hash'] and hmac.compare_digest(account['bound_hash'], digest(token + ':' + fingerprint)))

    def user(self, db):
        token = self.cookie_value('outhman')
        account = db.execute('SELECT u.* FROM users u JOIN sessions s ON u.id=s.user_id WHERE s.token=? AND s.expires_at>? AND u.deleted_at IS NULL', (digest(token), time.time())).fetchone()
        if account and not account['is_admin'] and (not account['approved'] or account['login_locked'] or account['suspended'] or not self.device_matches(account)):
            return None
        return account

    def failed_login(self, db, account, username, ip, now):
        self.failure(db, ip, now)
        self.event(db, 'Failed login', username[:120])
        if account and not account['is_admin']:
            count = min(3, account['login_failures'] + 1)
            db.execute('UPDATE users SET login_failures=?,login_locked=? WHERE id=?', (count, int(count >= 3), account['id']))
            if count >= 3:
                for table in ('sessions', 'codes', 'auth_pins'):
                    db.execute(f'DELETE FROM {table} WHERE user_id=?', (account['id'],))
                self.event(db, 'Account blocked after three failed logins', account['username'])
                return self.reply({'error': 'Account blocked after 3 failed login attempts. Ask an administrator to release it.', 'attempts_remaining': 0}, 423)
            remaining = 3 - count
            return self.reply({'error': f'Incorrect username or password. {remaining} login attempt(s) remaining.', 'attempts_remaining': remaining}, 401)
        return self.reply({'error': 'Incorrect username or password.'}, 401)

    def blocked(self, account, now):
        if account['blocked_at'] is None:
            return False
        if now < account['blocked_at'] + 300:
            self.reply({'error': 'Account blocked for five minutes, then suspended until an administrator releases it.'}, 423)
        else:
            self.reply({'error': 'Account suspended. Ask an administrator to release it.'}, 423)
        return True

    def public_user(self, user):
        return {**{k: user[k] for k in ('id', 'username', 'is_admin', 'must_change', 'code_limit', 'code_count', 'blocked_at', 'approved', 'bound_at', 'bound_browser', 'login_failures', 'login_locked', 'suspended')}, 'device_bound': bool(user['bound_hash'])}

    def event(self, db, action, username):
        db.execute('INSERT INTO events(action,username,ip,browser,created_at,app_id) VALUES(?,?,?,?,?,?)', (action, username, self.client_address[0], self.headers.get('User-Agent', 'Unknown')[:512], time.time(), getattr(self, 'authenticated_app_id', None)))

    def session(self, db, uid):
        token = secrets.token_urlsafe(32)
        db.execute('INSERT INTO sessions VALUES(?,?,?)', (digest(token), uid, time.time() + SESSION_AGE))
        secure = '; Secure' if os.environ.get('OUTHMAN_SECURE_COOKIE') == '1' else ''
        return f'outhman={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_AGE}{secure}'

    def send_response(self, code, message=None):
        self.response_status = code
        super().send_response(code, message)

    def record_api_request(self):
        if self.path.split('?', 1)[0].startswith(('/api/v1/', '/api/backups')):
            # Never store query strings, request bodies, Authorization, or responses.
            endpoint = self.path.split('?', 1)[0]
            if endpoint not in ('/api/v1/enroll', '/api/v1/verify', '/api/v1/confirm'):
                endpoint = '/api/backups' if endpoint.startswith('/api/backups') else '/api/v1/(unknown)'
            with connect() as db:
                db.execute('INSERT INTO api_requests(created_at,method,endpoint,ip,client,status,app_id) VALUES(?,?,?,?,?,?,?)', (time.time(), self.command, endpoint, self.client_address[0], self.headers.get('User-Agent', 'Unknown')[:512], getattr(self, 'response_status', 500), getattr(self, 'authenticated_app_id', None)))
                db.execute('DELETE FROM api_requests WHERE id <= (SELECT COALESCE(MAX(id),0)-10000 FROM api_requests)')

    def do_GET(self):
        self.authenticated_app_id = None
        with DATA_LOCK:
            try:
                self.handle_get()
            finally:
                self.record_api_request()

    def handle_get(self):
        if not self.path.startswith('/api/'):
            return super().do_GET()
        with connect() as db:
            user = self.user(db)
            if urlsplit(self.path).path == '/api/logs':
                return self.log_feed(db)
            if self.path == '/api/logs/keys' and user and user['is_admin'] and not user['must_change']:
                return self.reply({'keys': log_export.keys(DB)})
            if self.path.startswith('/api/backups'):
                return self.backup_get(db, user)
            if self.path == '/api/me':
                code = db.execute('SELECT value,expires_at FROM codes WHERE user_id=? AND expires_at>?', (user['id'], time.time())).fetchone() if user and not user['must_change'] and user['blocked_at'] is None else None
                return self.reply({'user': self.public_user(user) if user else None, 'code': dict(code) if code else None, 'features': ['integration-v1']})
            if self.path == '/api/admin' and user and user['is_admin'] and not user['must_change']:
                return self.reply({'api_requests': [dict(r) for r in db.execute('SELECT created_at,method,endpoint,ip,client,status FROM api_requests ORDER BY id DESC LIMIT 200')], 'acl': [r[0] for r in db.execute('SELECT network FROM api_acl ORDER BY network')], 'caller_ip': self.client_address[0], 'users': [self.public_user(r) for r in db.execute('SELECT * FROM users WHERE deleted_at IS NULL ORDER BY username')], 'groups': [dict(r, user_ids=[x[0] for x in db.execute('SELECT user_id FROM group_users WHERE group_id=?', (r['id'],))], app_ids=[x[0] for x in db.execute('SELECT app_id FROM group_apps WHERE group_id=?', (r['id'],))]) for r in db.execute('SELECT * FROM access_groups ORDER BY name')], 'invitations': [dict(r) for r in db.execute('SELECT id,created_at,expires_at,used_at,used_by FROM invitations ORDER BY id DESC LIMIT 100')], 'apps': [dict(r) for r in db.execute('SELECT id,name,created_at,revoked_at FROM apps ORDER BY created_at DESC')], 'events': [dict(r) for r in db.execute('SELECT action,username,ip,browser,created_at FROM events ORDER BY id DESC LIMIT 200')]})
        self.reply({'error': 'Access denied.'}, 403)

    def do_POST(self):
        self.authenticated_app_id = None
        try:
            self.handle_post()
        finally:
            with DATA_LOCK:
                self.record_api_request()

    def handle_post(self):
        # Same-origin JSON requests only; never trust forwarded IP headers.
        origin = self.headers.get('Origin')
        if origin and origin not in ('http://' + self.headers.get('Host', ''), 'https://' + self.headers.get('Host', '')):
            return self.reply({'error': 'Invalid request origin.'}, 403)
        try:
            length = int(self.headers.get('Content-Length', 0))
            maximum = 48 * 1024 * 1024 if self.path == '/api/backups/restore' else 8192
            if length < 1 or length > maximum or self.headers.get_content_type() != 'application/json':
                raise ValueError('Send a JSON request within the endpoint size limit.')
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError('Invalid request.')
            with DATA_LOCK:
                if self.path in ('/api/backups', '/api/backups/restore', '/api/backups/schedule', '/api/backups/keys', '/api/backups/keys/revoke', '/api/backups/trigger'):
                    return self.backup_post(data)
                with connect() as db:
                    db.execute('BEGIN IMMEDIATE')
                    self.post(db, data)
        except (ValueError, TypeError, KeyError) as exc:
            self.reply({'error': str(exc) or 'Invalid request.'}, 400)
        except sqlite3.IntegrityError:
            self.reply({'error': 'That username is already in use.'}, 409)

    def log_feed(self, db):
        if not self.acl_allows(db):
            return self.reply({'error': 'Caller IP is not allowed by the integration ACL.'}, 403)
        authorization = self.headers.get('Authorization', '')
        token = authorization[7:] if authorization.startswith('Bearer ') else ''
        key = log_export.authenticate(DB, token)
        if not key:
            return self.reply({'error': 'Invalid log API key.'}, 401)
        if key['app_id'] != '*' and not db.execute('SELECT 1 FROM apps WHERE id=? AND revoked_at IS NULL', (key['app_id'],)).fetchone():
            return self.reply({'error': 'Log access for this app is revoked.'}, 403)
        try:
            result, status = log_export.feed(db, urlsplit(self.path).query, key['app_id'])
        except ValueError as exc:
            return self.reply({'error': str(exc)}, 400)
        return self.reply(result, status)

    def acl_allows(self, db):
        caller = ipaddress.ip_address(self.client_address[0])
        if isinstance(caller, ipaddress.IPv6Address) and caller.ipv4_mapped:
            caller = caller.ipv4_mapped
        return any(caller in ipaddress.ip_network(r[0]) for r in db.execute('SELECT network FROM api_acl'))

    def backup_authorized(self, db, user):
        if not user or not user['is_admin'] or user['must_change'] or user['blocked_at'] is not None:
            self.reply({'error': 'A configured administrator session is required.'}, 403)
            return False
        if not self.acl_allows(db):
            self.reply({'error': 'Caller IP is not allowed by the integration ACL. Add this IP in Settings before accessing backups.'}, 403)
            return False
        return True

    def backup_get(self, db, user):
        authorization = self.headers.get('Authorization', '')
        key_id = None
        if authorization.startswith('Bearer ') and self.path != '/api/backups/status':
            if not self.acl_allows(db):
                return self.reply({'error': 'Caller IP is not allowed by the integration ACL.'}, 403)
            key_id = backup_service.authenticate(DB, authorization[7:])
            if not key_id:
                return self.reply({'error': 'Invalid backup download API key.'}, 401)
        elif not self.backup_authorized(db, user):
            return
        if self.path == '/api/backups/status':
            return self.reply(backup_service.status(DB))
        if self.path == '/api/backups':
            return self.reply({'backups': backups.listing(DB)})
        if self.path == '/api/backups/latest':
            files = backups.listing(DB)
            if not files:
                return self.reply({'error': 'No backups available yet.'}, 404)
            backup_id = files[0]['id']
        else:
            backup_id = self.path[len('/api/backups/'):]

        prefix = '/api/backups/'
        try:
            path = backups.path_for(DB, backup_id)
            payload = path.read_bytes()
        except ValueError:
            return self.reply({'error': 'Invalid backup ID.'}, 400)
        except FileNotFoundError:
            return self.reply({'error': 'Backup not found.'}, 404)
        self.event(db, 'Downloaded encrypted backup ' + path.stem, 'backup-key:' + key_id if key_id else user['username'])
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', f'attachment; filename="{path.name}"')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def backup_post(self, data):
        if self.path == '/api/backups/trigger':
            with connect() as db:
                if not self.acl_allows(db):
                    return self.reply({'error': 'Caller IP is not allowed by the integration ACL.'}, 403)
                authorization = self.headers.get('Authorization', '')
                record = backup_service.key_record(DB, authorization[7:] if authorization.startswith('Bearer ') else '')
                if not record:
                    return self.reply({'error': 'Invalid backup API key.'}, 401)
                if record['scope'] != 'backups:create,read':
                    return self.reply({'error': 'This key cannot trigger backups.'}, 403)
                request_id = data.get('request_id')
                if not isinstance(request_id, str) or not re.fullmatch(r'[0-9a-f]{32}', request_id):
                    raise ValueError('Use a fresh 32-character lowercase hexadecimal request_id for each backup job; reuse it only for retries.')
                backup_id = digest(record['id'] + ':' + request_id)[:32]
                reused = backups.path_for(DB, backup_id).exists()
                result = backups.create(DB, data.get('passphrase'), backup_id=backup_id)
                self.event(db, ('Reused' if reused else 'Created') + ' BackMan backup ' + backup_id, 'backup-key:' + record['id'])
                return self.reply({**result, 'request_id': request_id, 'reused': reused}, 200 if reused else 201)
        with connect() as db:
            user = self.user(db)
            if not self.backup_authorized(db, user):
                return
            username = user['username']
        if self.path == '/api/backups/schedule':
            return self.reply({'error': 'Backup scheduling is now managed by backMan_runner.py. Configure the external runner instead.'}, 410)
        if self.path == '/api/backups/keys':
            result = backup_service.create_key(DB, data.get('name'), data.get('scope', 'backups:read'))
            with connect() as db:
                self.event(db, 'Created backup download key ' + result['id'], username)
            return self.reply(result, 201)
        if self.path == '/api/backups/keys/revoke':
            backup_service.revoke_key(DB, data.get('id'))
            with connect() as db:
                self.event(db, 'Revoked backup download key', username)
            return self.reply({'ok': True})
        if self.path == '/api/backups':
            result = backups.create(DB, data.get('passphrase'))
            with connect() as db:
                self.event(db, 'Created encrypted backup ' + result['id'], username)
            return self.reply(result, 201)
        if data.get('confirm') is not True:
            raise ValueError('Confirm that restoring replaces current data and signs everyone out.')
        encoded = data.get('backup')
        if not isinstance(encoded, str):
            raise ValueError('Upload a base64-encoded encrypted backup file.')
        try:
            encrypted = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError('Invalid backup encoding.')
        safety = backups.restore(DB, encrypted, data.get('passphrase'))
        with connect() as db:
            self.event(db, 'Restored encrypted backup; recovery backup ' + safety['id'], username)
        return self.reply({'ok': True, 'recovery_backup_id': safety['id']}, cookie='outhman=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')

    def credentials(self, data):
        username = data.get('username', '')
        password = data.get('password', '')
        if not isinstance(username, str) or not isinstance(password, str):
            raise ValueError('Enter a username and password.')
        username = username.strip()
        if not 3 <= len(username) <= 120 or not 8 <= len(password) <= 256:
            raise ValueError('Use a username of 3–120 characters and a password of 8–256 characters.')
        return username, password

    def post(self, db, data):
        now = time.time()
        user = self.user(db)
        path = self.path
        ip = self.client_address[0]
        if path.startswith('/api/v1/'):
            return self.integration(db, data, now)
        if path in ('/api/login', '/api/register', '/api/check-invite'):
            attempt = db.execute('SELECT * FROM attempts WHERE ip=?', (ip,)).fetchone()
            if attempt and attempt['reset_at'] > now and attempt['failures'] >= 10:
                return self.reply({'error': 'Too many attempts. Try again in 15 minutes.'}, 429)
        if path == '/api/login':
            username, password = data.get('username', ''), data.get('password', '')
            if not isinstance(username, str) or not isinstance(password, str) or len(password) > 256:
                raise ValueError('Invalid credentials.')
            account = db.execute('SELECT * FROM users WHERE username=? AND deleted_at IS NULL', (username.strip(),)).fetchone()
            if account and account['suspended']:
                return self.reply({'error': 'Account suspended. Ask an administrator to release it.'}, 423)
            if account and not account['is_admin'] and account['login_locked']:
                return self.reply({'error': 'Account blocked after 3 failed login attempts. Ask an administrator to release it.', 'attempts_remaining': 0}, 423)
            if not account or not password_ok(password, account['password']) or not account['approved']:
                return self.failed_login(db, account, username, ip, now)
            device_cookie = None
            if not account['is_admin']:
                if not self.device_fingerprint() or (account['bound_hash'] and not self.device_matches(account)):
                    return self.failed_login(db, account, username, ip, now)
            if self.blocked(account, now):
                return
            if not account['is_admin'] and not account['bound_hash']:
                existing_device = self.cookie_value('outhman_device')
                token = existing_device if re.fullmatch(r'[A-Za-z0-9_-]{43}', existing_device) else secrets.token_urlsafe(32)
                db.execute('UPDATE users SET bound_hash=?,bound_at=?,bound_browser=? WHERE id=?', (digest(token + ':' + self.device_fingerprint()), now, self.headers.get('User-Agent', 'Unknown')[:512], account['id']))
                secure = '; Secure' if os.environ.get('OUTHMAN_SECURE_COOKIE') == '1' else ''
                device_cookie = f'outhman_device={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=31536000{secure}'
                self.event(db, 'Bound account to browser', account['username'])
                account = db.execute('SELECT * FROM users WHERE id=?', (account['id'],)).fetchone()
            db.execute('UPDATE users SET login_failures=0 WHERE id=?', (account['id'],))
            account = db.execute('SELECT * FROM users WHERE id=?', (account['id'],)).fetchone()
            db.execute('DELETE FROM attempts WHERE ip=?', (ip,))
            self.event(db, 'Logged in', account['username'])
            return self.reply({'user': self.public_user(account)}, cookie=[self.session(db, account['id'])] + ([device_cookie] if device_cookie else []))
        if path in ('/api/check-invite', '/api/register'):
            key = data.get('key', '')
            if not isinstance(key, str):
                raise ValueError('Invalid invitation key.')
            key = key.replace('-', '').replace(' ', '').lower()
            invite = db.execute('SELECT * FROM invitations WHERE token=? AND used_at IS NULL AND expires_at>?', (digest(key), now)).fetchone()
            if not invite:
                self.failure(db, ip, now)
                return self.reply({'error': 'This invitation is invalid, expired, or already used.'}, 400)
            if path == '/api/check-invite':
                return self.reply({'valid': True, 'expires_at': invite['expires_at']})
            username, password = self.credentials(data)
            uid = db.execute('INSERT INTO users(username,password,approved) VALUES(?,?,0)', (username, password_hash(password))).lastrowid
            # Erase the invitation secret on redemption; keep metadata for audit.
            db.execute('UPDATE invitations SET token=NULL,used_at=?,used_by=? WHERE id=?', (now, username, invite['id']))
            self.event(db, 'Registered with invitation #' + str(invite['id']), username)
            self.event(db, 'Awaiting administrator approval', username)
            return self.reply({'pending_approval': True}, 202)
        if not user:
            return self.reply({'error': 'Please sign in.'}, 401)
        if path == '/api/logout':
            db.execute('DELETE FROM sessions WHERE user_id=?', (user['id'],))
            return self.reply({'ok': True}, cookie='outhman=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
        if path == '/api/change-credentials':
            if not user['must_change']:
                return self.reply({'error': 'Credential setup is already complete.'}, 403)
            username, password = self.credentials(data)
            if username.lower() == user['username'].lower() or password_ok(password, user['password']):
                raise ValueError('Change both the default username and password.')
            db.execute('UPDATE users SET username=?,password=?,must_change=0 WHERE id=?', (username, password_hash(password), user['id']))
            db.execute('DELETE FROM sessions WHERE user_id=?', (user['id'],))
            self.event(db, 'Admin credentials changed', username)
            updated = db.execute('SELECT * FROM users WHERE id=?', (user['id'],)).fetchone()
            return self.reply({'user': self.public_user(updated)}, cookie=self.session(db, user['id']))
        if user['must_change']:
            return self.reply({'error': 'Change your default credentials first.'}, 403)
        if self.blocked(user, now):
            return
        if path in ('/api/users/approve', '/api/users/release-device', '/api/users/release-login', '/api/users/suspend', '/api/users/resume', '/api/users/delete') and user['is_admin']:
            uid = data.get('user_id')
            if type(uid) is not int:
                raise ValueError('Choose an existing user.')
            target = db.execute('SELECT * FROM users WHERE id=? AND deleted_at IS NULL', (uid,)).fetchone()
            if not target or target['is_admin']:
                raise ValueError('Choose a non-administrator account.')
            if path == '/api/users/delete':
                if data.get('confirm') is not True:
                    raise ValueError('Confirm user deletion.')
                for table in ('sessions', 'codes', 'auth_pins', 'app_users', 'group_users'):
                    db.execute(f'DELETE FROM {table} WHERE user_id=?', (uid,))
                # Keep only an anonymous ID tombstone so external immutable user IDs are never reused.
                db.execute('UPDATE users SET username=?,password=?,approved=0,suspended=1,deleted_at=?,bound_hash=NULL,bound_at=NULL,bound_browser=NULL,code_limit=NULL,code_count=0,blocked_at=NULL,login_failures=0,login_locked=0 WHERE id=?', ('deleted-' + secrets.token_hex(16), password_hash(secrets.token_urlsafe(32)), now, uid))
                self.event(db, 'Deleted account ' + target['username'], user['username'])
            elif path in ('/api/users/suspend', '/api/users/resume'):
                suspend = path == '/api/users/suspend'
                db.execute('UPDATE users SET suspended=? WHERE id=?', (int(suspend), uid))
                if suspend:
                    for table in ('sessions', 'codes', 'auth_pins'):
                        db.execute(f'DELETE FROM {table} WHERE user_id=?', (uid,))
                self.event(db, ('Suspended account ' if suspend else 'Resumed account ') + target['username'], user['username'])
            elif path == '/api/users/approve':
                db.execute('UPDATE users SET approved=1,login_failures=CASE WHEN login_locked=0 THEN 0 ELSE login_failures END WHERE id=?', (uid,))
                self.event(db, 'Approved account ' + target['username'], user['username'])
            elif path == '/api/users/release-login':
                db.execute('UPDATE users SET login_failures=0,login_locked=0 WHERE id=?', (uid,))
                self.event(db, 'Released login block for ' + target['username'], user['username'])
            else:
                db.execute('UPDATE users SET bound_hash=NULL,bound_at=NULL,bound_browser=NULL WHERE id=?', (uid,))
                for table in ('sessions', 'codes', 'auth_pins'):
                    db.execute(f'DELETE FROM {table} WHERE user_id=?', (uid,))
                self.event(db, 'Released browser binding for ' + target['username'], user['username'])
            return self.reply({'ok': True})
        if path == '/api/logs/keys' and user['is_admin']:
            app_id = data.get('app_id')
            if not isinstance(app_id, str) or (app_id != '*' and not db.execute('SELECT 1 FROM apps WHERE id=? AND revoked_at IS NULL', (app_id,)).fetchone()):
                raise ValueError('Choose an active app or the centralized all-logs scope.')
            result = log_export.issue(DB, data.get('name'), app_id)
            self.event(db, 'Created log export key ' + result['id'], user['username'])
            return self.reply(result, 201)
        if path == '/api/logs/keys/revoke' and user['is_admin']:
            log_export.revoke(DB, data.get('id'))
            self.event(db, 'Revoked log export key', user['username'])
            return self.reply({'ok': True})
        if path == '/api/acl' and user['is_admin']:
            networks = data.get('networks')
            if not isinstance(networks, list) or len(networks) > 100 or any(not isinstance(n, str) for n in networks):
                raise ValueError('Provide up to 100 IP addresses or CIDR networks.')
            try:
                normalized = sorted({str(ipaddress.ip_network(n.strip(), strict=False)) for n in networks})
            except ValueError:
                raise ValueError('Enter valid IPv4/IPv6 addresses or CIDR networks.')
            db.execute('DELETE FROM api_acl')
            db.executemany('INSERT INTO api_acl VALUES(?)', [(n,) for n in normalized])
            db.execute('DELETE FROM auth_pins')
            self.event(db, 'Updated integration IP allowlist', user['username'])
            return self.reply({'ok': True})
        if path == '/api/groups' and user['is_admin']:
            name = data.get('name', '')
            members, apps = data.get('user_ids', []), data.get('app_ids', [])
            if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
                raise ValueError('Enter a group name of 1–100 characters.')
            if not isinstance(members, list) or not isinstance(apps, list) or any(type(x) is not int for x in members) or any(not isinstance(x, str) for x in apps):
                raise ValueError('Invalid group membership.')
            if any(not db.execute('SELECT 1 FROM users WHERE id=? AND deleted_at IS NULL', (x,)).fetchone() for x in members) or any(not db.execute('SELECT 1 FROM apps WHERE id=? AND revoked_at IS NULL', (x,)).fetchone() for x in apps):
                raise ValueError('Choose existing users and active apps.')
            gid = data.get('id')
            if gid is None:
                gid = db.execute('INSERT INTO access_groups(name) VALUES(?)', (name.strip(),)).lastrowid
            else:
                if type(gid) is not int or not db.execute('SELECT 1 FROM access_groups WHERE id=?', (gid,)).fetchone():
                    raise ValueError('Unknown group.')
                db.execute('UPDATE access_groups SET name=? WHERE id=?', (name.strip(), gid))
                db.execute('DELETE FROM group_users WHERE group_id=?', (gid,))
                db.execute('DELETE FROM group_apps WHERE group_id=?', (gid,))
            db.executemany('INSERT INTO group_users VALUES(?,?)', [(gid, x) for x in set(members)])
            db.executemany('INSERT INTO group_apps VALUES(?,?)', [(gid, x) for x in set(apps)])
            db.execute('DELETE FROM auth_pins')
            self.event(db, 'Updated access group ' + name.strip(), user['username'])
            return self.reply({'ok': True})
        if path == '/api/users/policy' and user['is_admin']:
            uid, limit = data.get('user_id'), data.get('code_limit')
            if type(uid) is not int or (limit is not None and (type(limit) is not int or not 1 <= limit <= 100000)):
                raise ValueError('Choose a limit of 1–100000, or leave it unlimited.')
            target = db.execute('SELECT * FROM users WHERE id=? AND deleted_at IS NULL', (uid,)).fetchone()
            if not target or target['is_admin']:
                raise ValueError('Choose a non-administrator account.')
            db.execute('UPDATE users SET code_limit=? WHERE id=?', (limit, uid))
            if data.get('release') is True:
                db.execute('UPDATE users SET code_count=0,blocked_at=NULL WHERE id=?', (uid,))
            self.event(db, 'Updated account policy' + (' and released account' if data.get('release') is True else '') + ' for ' + target['username'], user['username'])
            return self.reply({'ok': True})
        if path == '/api/apps' and user['is_admin']:
            name = data.get('name', '')
            if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
                raise ValueError('Enter an app name of 1–100 characters.')
            app_id, secret = secrets.token_hex(8), secrets.token_hex(16)
            db.execute('INSERT INTO apps VALUES(?,?,?,?,NULL)', (app_id, name.strip(), digest(secret), now))
            self.event(db, 'Created integration app ' + app_id, user['username'])
            return self.reply({'app_id': app_id, 'app_secret': secret}, 201)
        if path == '/api/apps/revoke' and user['is_admin']:
            app_id = data.get('app_id')
            if not isinstance(app_id, str):
                raise ValueError('Invalid app ID.')
            db.execute('UPDATE apps SET revoked_at=? WHERE id=?', (now, app_id))
            db.execute('DELETE FROM auth_pins WHERE app_id=?', (app_id,))
            self.event(db, 'Revoked integration app ' + app_id, user['username'])
            return self.reply({'ok': True})
        if path == '/api/code':
            if not user['is_admin'] and user['code_limit'] is not None and user['code_count'] >= user['code_limit']:
                db.execute('UPDATE users SET blocked_at=? WHERE id=?', (now, user['id']))
                db.execute('DELETE FROM codes WHERE user_id=?', (user['id'],))
                db.execute('DELETE FROM auth_pins WHERE user_id=?', (user['id'],))
                self.event(db, 'Code limit exceeded; blocked then suspended', user['username'])
                return self.reply({'error': 'Code limit exceeded. Account blocked for five minutes, then suspended until admin release.'}, 423)
            db.execute('UPDATE users SET code_count=code_count+1 WHERE id=?', (user['id'],))
            code = f'{secrets.randbelow(1000000):06d}'
            expires = now + 60
            db.execute('INSERT OR REPLACE INTO codes VALUES(?,?,?)', (user['id'], code, expires))
            self.event(db, 'Generated access code', user['username'])
            return self.reply({'value': code, 'expires_at': expires})
        if path == '/api/invitations' and user['is_admin']:
            if 'duration' in data:
                if data['duration'] not in (30, 60, 600):
                    raise ValueError('Choose a supported duration.')
                expires = now + data['duration']
            else:
                expires = float(data.get('expires_at', 0))
            if not now < expires <= now + 10 * 365 * 86400:
                raise ValueError('Choose a future date within 10 years.')
            key = secrets.token_hex(8)
            db.execute('INSERT INTO invitations(token,created_at,expires_at) VALUES(?,?,?)', (digest(key), now, expires))
            self.event(db, 'Created invitation', user['username'])
            return self.reply({'key': key, 'expires_at': expires})
        self.reply({'error': 'Access denied.'}, 403)

    def integration(self, db, data, now):
        if not self.acl_allows(db):
            return self.reply({'error': 'Caller IP is not allowed by the integration ACL.'}, 403)
        app_id = self.headers.get('X-OuthMan-App', '')
        authorization = self.headers.get('Authorization', '')
        secret = authorization[7:] if authorization.startswith('Bearer ') else ''
        app = db.execute('SELECT * FROM apps WHERE id=? AND revoked_at IS NULL', (app_id,)).fetchone()
        ip_scope = 'integration-ip:' + self.client_address[0]
        def limited(scope):
            row = db.execute('SELECT * FROM attempts WHERE ip=?', (scope,)).fetchone()
            return row and row['reset_at'] > now and row['failures'] >= 10
        if limited(ip_scope):
            return self.reply({'error': 'Too many failed requests. Try again in 15 minutes.'}, 429)
        if not app or not hmac.compare_digest(digest(secret), app['secret_hash']):
            self.failure(db, ip_scope, now)
            return self.reply({'error': 'Invalid app credentials.'}, 401)
        self.authenticated_app_id = app_id
        path = self.path
        if path not in ('/api/v1/enroll', '/api/v1/verify', '/api/v1/confirm'):
            return self.reply({'error': 'Unknown integration endpoint.'}, 404)
        # Account throttling spans apps so registering more apps cannot bypass it.
        username = data.get('username', '')
        if not isinstance(username, str) or not 3 <= len(username.strip()) <= 120:
            raise ValueError('Enter a valid username.')
        username = username.strip()
        scope = 'integration-user:' + username.casefold()
        if limited(scope):
            return self.reply({'error': 'Too many failed requests. Try again in 15 minutes.'}, 429)
        account = db.execute('SELECT * FROM users WHERE username=? AND deleted_at IS NULL', (username,)).fetchone()
        def denied():
            self.failure(db, scope, now)
            self.failure(db, ip_scope, now)
            self.event(db, 'Rejected integration request from ' + app_id, username)
            return self.reply({'error': 'Verification failed or expired.'}, 401)
        if not account or account['must_change'] or not account['approved'] or account['login_locked'] or account['suspended'] or (not account['is_admin'] and not account['bound_hash']):
            return denied()
        if self.blocked(account, now):
            return
        uid = account['id']
        if not db.execute('SELECT 1 FROM group_users u JOIN group_apps a ON a.group_id=u.group_id WHERE u.user_id=? AND a.app_id=?', (uid, app_id)).fetchone():
            self.event(db, 'Denied app access for ' + app_id, username)
            return self.reply({'error': 'Account is not allowed to access this app.'}, 403)
        if path == '/api/v1/confirm':
            pin, request_id = data.get('auth_pin'), data.get('request_id')
            if not isinstance(pin, str) or not isinstance(request_id, str):
                return denied()
            receipt = db.execute('SELECT * FROM auth_pins WHERE token_hash=? AND app_id=? AND user_id=? AND request_id=? AND expires_at>?', (digest(pin), app_id, uid, request_id, now)).fetchone()
            if not receipt:
                return denied()
            db.execute('DELETE FROM auth_pins WHERE token_hash=?', (digest(pin),))
            self.event(db, 'Confirmed app login for ' + app_id, account['username'])
            return self.reply({'verified': True, 'app_id': app_id, 'user_id': uid, 'username': account['username'], 'request_id': request_id})
        password, code = data.get('password'), data.get('code')
        if not isinstance(password, str) or len(password) > 256 or not isinstance(code, str) or len(code) != 6 or not code.isascii() or not code.isdigit():
            return denied()
        if not password_ok(password, account['password']):
            return denied()
        active = db.execute('SELECT * FROM codes WHERE user_id=? AND expires_at>?', (uid, now)).fetchone()
        if not active or not hmac.compare_digest(active['value'], code):
            return denied()
        binding = db.execute('SELECT * FROM app_users WHERE app_id=? AND user_id=?', (app_id, uid)).fetchone()
        if path == '/api/v1/enroll':
            if binding:
                return self.reply({'error': 'Account already linked. Use the stored user_key for login.'}, 409)
            key = secrets.token_hex(16)
            db.execute('INSERT INTO app_users VALUES(?,?,?,?)', (app_id, uid, digest(key), now))
            db.execute('DELETE FROM codes WHERE user_id=?', (uid,))
            self.event(db, 'Linked account to app ' + app_id, account['username'])
            return self.reply({'app_id': app_id, 'user_id': uid, 'username': account['username'], 'user_key': key}, 201)
        key, request_id = data.get('user_key'), data.get('request_id')
        if not binding or not isinstance(key, str) or not hmac.compare_digest(digest(key), binding['key_hash']):
            return denied()
        if not isinstance(request_id, str) or not 16 <= len(request_id) <= 128:
            raise ValueError('Use a unique request_id of 16–128 characters for each login attempt.')
        db.execute('DELETE FROM codes WHERE user_id=?', (uid,))
        db.execute('DELETE FROM auth_pins WHERE expires_at<=?', (now,))
        pin = secrets.token_hex(16)
        db.execute('INSERT INTO auth_pins VALUES(?,?,?,?,?)', (digest(pin), app_id, uid, request_id, now + 30))
        self.event(db, 'Verified app credentials for ' + app_id, account['username'])
        return self.reply({'auth_pin': pin, 'expires_at': now + 30, 'request_id': request_id})

    def failure(self, db, ip, now):
        db.execute('INSERT INTO attempts VALUES(?,1,?) ON CONFLICT(ip) DO UPDATE SET failures=CASE WHEN reset_at<? THEN 1 ELSE failures+1 END, reset_at=CASE WHEN reset_at<? THEN excluded.reset_at ELSE reset_at END', (ip, now + 900, now, now))

if __name__ == '__main__':
    initialize()
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', '10070'))
    try:
        httpd = ThreadingHTTPServer((host, port), Handler)
    except PermissionError:
        raise SystemExit(f'Cannot bind to port {port}: permission denied. Try PORT=10070 python3 server.py (ports below 1024 may require elevated privileges).')
    except OSError as exc:
        raise SystemExit(f'Cannot start OuthMan on {host}:{port}: {exc}')
    print(f'OuthMan running at http://{host}:{port}', flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
