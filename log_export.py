"""Scoped read-only log export keys and incremental event feeds."""
import hashlib
import hmac
import secrets
import time
from urllib.parse import parse_qs

import backup_service


def keys(db_path):
    return [{k: v for k, v in row.items() if k != 'hash'} for row in backup_service.load(db_path).get('log_keys', [])]


def issue(db_path, name, app_id):
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
        raise ValueError('Enter a log key name of 1–100 characters.')
    config = backup_service.load(db_path)
    rows = config.setdefault('log_keys', [])
    if len(rows) >= 100:
        raise ValueError('Maximum 100 log keys. Revoke unused keys first.')
    token = 'olk_' + secrets.token_urlsafe(32)
    row = {'id': secrets.token_hex(8), 'name': name.strip(), 'app_id': app_id, 'scope': 'logs:read', 'created_at': time.time(), 'hash': hashlib.sha256(token.encode()).hexdigest()}
    rows.append(row)
    backup_service.save(db_path, config)
    return {'id': row['id'], 'api_key': token}


def revoke(db_path, key_id):
    if not isinstance(key_id, str):
        raise ValueError('Invalid log key ID.')
    config = backup_service.load(db_path)
    config['log_keys'] = [row for row in config.get('log_keys', []) if row['id'] != key_id]
    backup_service.save(db_path, config)


def authenticate(db_path, token):
    if not isinstance(token, str) or not 1 <= len(token) <= 256:
        return None
    hashed = hashlib.sha256(token.encode()).hexdigest()
    return next((row for row in backup_service.load(db_path).get('log_keys', []) if hmac.compare_digest(row['hash'], hashed)), None)


def feed(db, query, app_id):
    params = parse_qs(query, keep_blank_values=True)
    if set(params) - {'stream', 'after', 'limit', 'epoch'} or any(len(v) != 1 for v in params.values()):
        raise ValueError('Use stream, after, limit, and epoch once each.')
    stream = params.get('stream', ['activity'])[0]
    if stream not in ('activity', 'requests'):
        raise ValueError('Choose stream=activity or stream=requests.')
    try:
        after = int(params.get('after', ['0'])[0])
        limit = int(params.get('limit', ['100'])[0])
    except ValueError:
        raise ValueError('after and limit must be integers.')
    if not 0 <= after <= 9223372036854775807 or not 1 <= limit <= 500:
        raise ValueError('Use after >= 0 and a limit of 1–500.')
    epoch = db.execute("SELECT value FROM log_meta WHERE key='epoch'").fetchone()[0]
    table = 'events' if stream == 'activity' else 'api_requests'
    bounds = db.execute(f'SELECT MIN(id),MAX(id) FROM {table}').fetchone()
    oldest, high = bounds[0], bounds[1] or 0
    requested_epoch = params.get('epoch', [None])[0]
    if (requested_epoch is not None and requested_epoch != epoch) or after > high:
        return {'error': 'Log cursor expired or the database was restored. Start this stream from after=0 with the new epoch.', 'epoch': epoch, 'stream': stream, 'reset_required': True, 'next_after': 0}, 409
    fields = 'id,created_at,action,username,ip,browser,app_id' if stream == 'activity' else 'id,created_at,method,endpoint,ip,client,status,app_id'
    scope_sql, values = ('', [after]) if app_id == '*' else (' AND app_id=?', [after, app_id])
    rows = [dict(r) for r in db.execute(f'SELECT {fields} FROM {table} WHERE id>?{scope_sql} ORDER BY id LIMIT ?', (*values, limit + 1))]
    has_more = len(rows) > limit
    rows = rows[:limit]
    for row in rows:
        row['source'] = 'outhman'
        row['stream'] = stream
    next_after = rows[-1]['id'] if has_more else high
    return {'source': 'outhman', 'stream': stream, 'epoch': epoch, 'entries': rows, 'next_after': next_after, 'has_more': has_more, 'oldest_available_id': oldest, 'retention_gap': bool(after and oldest and after < oldest - 1)}, 200
