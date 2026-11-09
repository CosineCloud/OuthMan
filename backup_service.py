"""Local backup scheduling and download-only API keys; encrypted sidecar configuration."""
import calendar
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import re
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import backups


def paths(db_path):
    parent = Path(db_path).parent
    return parent / 'backup-control.key', parent / 'backup-control.enc'


def load(db_path):
    key_path, config_path = paths(db_path)
    if not config_path.exists():
        return {'schedule': {'enabled': False, 'frequency': 'daily', 'time': '00:00', 'timezone': 'America/Chicago', 'weekdays': [0], 'day_of_month': 1, 'interval_minutes': 1440}, 'keys': []}
    encrypted = config_path.read_bytes()
    raw = AESGCM(key_path.read_bytes()).decrypt(encrypted[:12], encrypted[12:], b'outhman-backup-control-v1')
    return json.loads(raw)


def save(db_path, config):
    key_path, config_path = paths(db_path)
    if not key_path.exists():
        with key_path.open('xb') as file:
            os.chmod(key_path, 0o600)
            file.write(secrets.token_bytes(32))
            file.flush()
            os.fsync(file.fileno())
    nonce = secrets.token_bytes(12)
    encrypted = nonce + AESGCM(key_path.read_bytes()).encrypt(nonce, json.dumps(config).encode(), b'outhman-backup-control-v1')
    temporary = config_path.with_suffix('.tmp')
    try:
        with temporary.open('wb') as file:
            os.chmod(temporary, 0o600)
            file.write(encrypted)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, config_path)
    finally:
        temporary.unlink(missing_ok=True)


def status(db_path):
    config = load(db_path)
    schedule = {k: v for k, v in config['schedule'].items() if k != 'passphrase'}
    schedule['has_passphrase'] = bool(config['schedule'].get('passphrase'))
    keys = [{k: v for k, v in row.items() if k != 'hash'} for row in config['keys']]
    return {'mode': 'external', 'host_scheduler_enabled': False, 'schedule': schedule, 'keys': keys}


def next_run(schedule, after):
    frequency = schedule.get('frequency', 'interval')
    if frequency == 'interval':
        return after + schedule['interval_minutes'] * 60
    zone = ZoneInfo(schedule['timezone'])
    hour, minute = map(int, schedule['time'].split(':'))
    start = datetime.fromtimestamp(after, zone).date()
    for offset in range(370):
        day = start + timedelta(days=offset)
        if frequency == 'weekly' and day.weekday() not in schedule['weekdays']:
            continue
        if frequency == 'monthly' and day.day != min(schedule['day_of_month'], calendar.monthrange(day.year, day.month)[1]):
            continue
        wall = datetime.combine(day, datetime.min.time()).replace(hour=hour, minute=minute)
        # For skipped DST wall times, use the first real minute after the gap.
        # For repeated times, use fold=0 only, preventing two runs on that date.
        for adjustment in range(1441):
            candidate = wall + timedelta(minutes=adjustment)
            if candidate.date() != day:
                break
            stamp = candidate.replace(tzinfo=zone, fold=0).timestamp()
            if datetime.fromtimestamp(stamp, zone).replace(tzinfo=None) == candidate:
                if stamp > after:
                    return stamp
                break
    raise ValueError('Could not calculate the next scheduled backup.')


def configure(db_path, data, now=None):
    now = time.time() if now is None else now
    enabled = data.get('enabled')
    frequency = data.get('frequency', 'interval')
    if type(enabled) is not bool or frequency not in ('interval', 'daily', 'weekly', 'monthly'):
        raise ValueError('Choose daily, weekly, monthly, or an interval, and an enabled state.')
    settings = {'frequency': frequency}
    if frequency == 'interval':
        interval = data.get('interval_minutes')
        if type(interval) is not int or not 5 <= interval <= 43200:
            raise ValueError('Choose an interval of 5–43200 minutes.')
        settings['interval_minutes'] = interval
    else:
        clock, timezone = data.get('time'), data.get('timezone', 'America/Chicago')
        if not isinstance(clock, str) or not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]', clock):
            raise ValueError('Choose a valid backup time.')
        if not isinstance(timezone, str) or len(timezone) > 100:
            raise ValueError('Choose a valid IANA timezone, such as America/Chicago.')
        try:
            ZoneInfo(timezone)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError('Choose a valid IANA timezone, such as America/Chicago.')
        settings.update(time=clock, timezone=timezone)
        if frequency == 'weekly':
            weekdays = data.get('weekdays')
            if not isinstance(weekdays, list) or not 1 <= len(weekdays) <= 7 or any(type(d) is not int or not 0 <= d <= 6 for d in weekdays):
                raise ValueError('Select at least one weekday.')
            settings['weekdays'] = sorted(set(weekdays))
        if frequency == 'monthly':
            day = data.get('day_of_month')
            if type(day) is not int or not 1 <= day <= 31:
                raise ValueError('Choose a monthly date from 1 to 31.')
            settings['day_of_month'] = day
    config = load(db_path)
    schedule = config['schedule']
    passphrase = data.get('passphrase', '')
    if not isinstance(passphrase, str) or (passphrase and not 12 <= len(passphrase) <= 256):
        raise ValueError('Use a backup passphrase of 12–256 characters.')
    if passphrase:
        schedule['passphrase'] = passphrase
    if enabled and not schedule.get('passphrase'):
        raise ValueError('Set a passphrase before enabling automatic backups.')
    schedule.update(settings)
    schedule.update(enabled=enabled, next_run=next_run(schedule, now) if enabled else None)
    save(db_path, config)
    return status(db_path)


def create_key(db_path, name, scope='backups:read'):
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
        raise ValueError('Enter a key name of 1–100 characters.')
    if scope not in ('backups:read', 'backups:create,read'):
        raise ValueError('Choose download-only or BackMan trigger and download access.')
    config = load(db_path)
    if len(config['keys']) >= 100:
        raise ValueError('Maximum 100 backup keys. Revoke unused keys first.')
    token = secrets.token_hex(16)
    row = {'id': secrets.token_hex(8), 'name': name.strip(), 'created_at': time.time(), 'scope': scope, 'bits': 128, 'hash': hashlib.sha256(token.encode()).hexdigest()}
    config['keys'].append(row)
    save(db_path, config)
    return {'id': row['id'], 'api_key': token}


def revoke_key(db_path, key_id):
    if not isinstance(key_id, str):
        raise ValueError('Invalid key ID.')
    config = load(db_path)
    config['keys'] = [row for row in config['keys'] if row['id'] != key_id]
    save(db_path, config)


def key_record(db_path, token):
    if not isinstance(token, str) or not 1 <= len(token) <= 256:
        return None
    hashed = hashlib.sha256(token.encode()).hexdigest()
    return next((row for row in load(db_path)['keys'] if hmac.compare_digest(row['hash'], hashed)), None)


def authenticate(db_path, token):
    row = key_record(db_path, token)
    return row['id'] if row else None


def tick(db_path, now=None):
    now = time.time() if now is None else now
    config = load(db_path)
    schedule = config['schedule']
    if not schedule.get('enabled') or schedule.get('next_run', now + 1) > now:
        return None
    try:
        result = backups.create(db_path, schedule['passphrase'])
        schedule.update(last_run=now, last_backup_id=result['id'], last_error=None)
    except Exception:
        # Do not persist exception text: it may contain paths or sensitive values.
        schedule.update(last_error='Automatic backup failed. Check storage space, database size, and local backup configuration.', last_attempt=now)
        result = None
    schedule['next_run'] = next_run(schedule, now)
    save(db_path, config)
    return result
