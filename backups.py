"""Versioned authenticated backups. Passphrases and plaintext never go to disk."""
import os
import hashlib
from pathlib import Path
import re
import secrets
import sqlite3
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b'OUTHMAN-BACKUP\x01'
MAX_FILE = 32 * 1024 * 1024
TRANSIENT = ('sessions', 'codes', 'auth_pins', 'attempts')


def passphrase_key(passphrase, salt):
    if not isinstance(passphrase, str) or not 12 <= len(passphrase) <= 256:
        raise ValueError('Use a backup passphrase of 12–256 characters.')
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode())


def folder(db_path):
    directory = Path(db_path).parent / 'backups'
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    return directory


def path_for(db_path, backup_id):
    if not isinstance(backup_id, str) or not re.fullmatch(r'[0-9a-f]{32}', backup_id):
        raise ValueError('Invalid backup ID.')
    return folder(db_path) / (backup_id + '.outhman')


def listing(db_path):
    return sorted([{'id': p.stem, 'filename': p.name, 'created_at': p.stat().st_mtime, 'size': p.stat().st_size}
                   for p in folder(db_path).glob('*.outhman') if re.fullmatch(r'[0-9a-f]{32}', p.stem)],
                  key=lambda row: row['created_at'], reverse=True)


def metadata(db_path, backup_id):
    path = path_for(db_path, backup_id)
    with path.open('rb') as file:
        checksum = hashlib.file_digest(file, 'sha256').hexdigest()
    return {'id': backup_id, 'filename': path.name, 'created_at': path.stat().st_mtime, 'size': path.stat().st_size, 'sha256': checksum}


def create(db_path, passphrase, backup_id=None):
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = passphrase_key(passphrase, salt)
    if backup_id is not None and path_for(db_path, backup_id).exists():
        return metadata(db_path, backup_id)
    snapshot = sqlite3.connect(':memory:')
    try:
        source = sqlite3.connect(db_path)
        try:
            source.backup(snapshot)
        finally:
            source.close()
        snapshot.execute('PRAGMA secure_delete=ON')
        with snapshot:
            for table in TRANSIENT:
                snapshot.execute(f'DELETE FROM {table}')
        snapshot.execute('VACUUM')
        plain = snapshot.serialize()
    finally:
        snapshot.close()
    if len(plain) > MAX_FILE - 1024:
        raise ValueError('Database exceeds the 32 MB backup limit.')
    header = MAGIC + salt + nonce
    encrypted = header + AESGCM(key).encrypt(nonce, plain, header)
    backup_id = backup_id or secrets.token_hex(16)
    path = path_for(db_path, backup_id)
    temporary = path.with_suffix('.tmp')
    try:
        with temporary.open('xb') as file:
            os.chmod(temporary, 0o600)
            file.write(encrypted)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return {'id': backup_id, 'filename': path.name, 'created_at': path.stat().st_mtime, 'size': len(encrypted), 'sha256': hashlib.sha256(encrypted).hexdigest()}


def restore(db_path, encrypted, passphrase):
    if not isinstance(encrypted, bytes) or not len(MAGIC) + 44 <= len(encrypted) <= MAX_FILE or not encrypted.startswith(MAGIC):
        raise ValueError('Invalid or oversized OuthMan backup file.')
    offset = len(MAGIC)
    salt, nonce = encrypted[offset:offset+16], encrypted[offset+16:offset+28]
    header = encrypted[:offset+28]
    key = passphrase_key(passphrase, salt)
    try:
        plain = AESGCM(key).decrypt(nonce, encrypted[offset+28:], header)
    except InvalidTag:
        raise ValueError('Incorrect passphrase or damaged backup file.')
    snapshot = sqlite3.connect(':memory:')
    try:
        snapshot.deserialize(plain)
        snapshot.execute('PRAGMA trusted_schema=OFF')
        if snapshot.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Backup database integrity check failed.')
        with sqlite3.connect(db_path) as target:
            tables = [r[0] for r in target.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            incoming = {r[0] for r in snapshot.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if 'log_meta' in tables and 'log_meta' not in incoming:
                snapshot.execute('CREATE TABLE log_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
                incoming.add('log_meta')
            for table in ('events', 'api_requests'):
                if 'app_id' not in {r[1] for r in snapshot.execute(f'PRAGMA table_info({table})')}:
                    snapshot.execute(f'ALTER TABLE {table} ADD COLUMN app_id TEXT')
            if incoming != set(tables) or snapshot.execute("SELECT 1 FROM sqlite_master WHERE type IN ('view','trigger')").fetchone():
                raise ValueError('Backup schema is incompatible with this app version.')
            # Additive compatibility for backups made before approval/device binding.
            old_columns = {r[1] for r in snapshot.execute('PRAGMA table_info(users)')}
            security_columns = [('approved', 'INTEGER NOT NULL DEFAULT 1'), ('bound_hash', 'TEXT'), ('bound_at', 'REAL'), ('bound_browser', 'TEXT'), ('login_failures', 'INTEGER NOT NULL DEFAULT 0'), ('login_locked', 'INTEGER NOT NULL DEFAULT 0'), ('suspended', 'INTEGER NOT NULL DEFAULT 0'), ('deleted_at', 'REAL')]
            for name, definition in security_columns:
                if name not in old_columns:
                    snapshot.execute(f'ALTER TABLE users ADD COLUMN {name} {definition}')
            if 'approved' not in old_columns:
                snapshot.execute('UPDATE users SET approved=0 WHERE is_admin=0')
            snapshot.commit()
            for table in tables:
                if {r[1]: r[2:] for r in snapshot.execute(f'PRAGMA table_info({table})')} != {r[1]: r[2:] for r in target.execute(f'PRAGMA table_info({table})')}:
                    raise ValueError('Backup schema is incompatible with this app version.')
            if snapshot.execute('PRAGMA foreign_key_check').fetchone():
                raise ValueError('Backup contains invalid account references.')
            if not snapshot.execute('SELECT 1 FROM users WHERE is_admin=1 AND must_change=0 AND approved=1 AND suspended=0 AND deleted_at IS NULL AND blocked_at IS NULL').fetchone():
                raise ValueError('Backup must contain an active, configured administrator.')
            # Before replacing live rows, keep an encrypted recovery copy with the same passphrase.
            safety = create(db_path, passphrase)
            target.execute('PRAGMA foreign_keys=ON')
            target.execute('BEGIN IMMEDIATE')
            target.execute('PRAGMA defer_foreign_keys=ON')
            for table in tables:
                target.execute(f'DELETE FROM {table}')
            for table in tables:
                if table in TRANSIENT:
                    continue
                rows = snapshot.execute(f'SELECT * FROM {table}')
                placeholders = ','.join('?' for _ in rows.description)
                columns = ','.join('"'+column[0]+'"' for column in rows.description)
                target.executemany(f'INSERT INTO {table} ({columns}) VALUES({placeholders})', rows)
            target.execute("INSERT OR REPLACE INTO log_meta VALUES('epoch',?)", (secrets.token_hex(16),))
            if target.execute('PRAGMA foreign_key_check').fetchone():
                raise ValueError('Backup contains invalid account references.')
        return safety
    except sqlite3.DatabaseError:
        raise ValueError('Invalid or incompatible backup database.')
    finally:
        snapshot.close()
