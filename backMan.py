#!/usr/bin/env python3
"""BackMan main: trigger host backups via curl, verify bytes, and transfer to CSO.
Standard library + curl only. Run directly once or let backMan_runner.py schedule it.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
from urllib.parse import urlsplit
import ipaddress

MAX_BACKUP = 32 * 1024 * 1024


class TransferError(Exception):
    pass


def load_json(path):
    return json.loads(Path(path).read_text())


def write_json(path, value):
    path = Path(path)
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as file:
        os.chmod(temporary, 0o600)
        json.dump(value, file, indent=2)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)


def work_directory(config, config_path):
    directory = Path(config.get('work_dir', './backman-data'))
    if not directory.is_absolute():
        directory = Path(config_path).resolve().parent / directory
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    return directory


@contextmanager
def lock(directory, name):
    with (directory / name).open('a') as file:
        os.chmod(directory / name, 0o600)
        try:
            fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise TransferError('Another BackMan process is already running.')
        try:
            yield
        finally:
            fcntl.flock(file, fcntl.LOCK_UN)


def base_url(value):
    if not isinstance(value, str):
        raise TransferError('Configure a valid service URL.')
    parsed = urlsplit(value)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise TransferError('Service URLs must be http(s), without credentials, query, or fragment.')
    if parsed.scheme == 'http':
        try:
            local = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            local = parsed.hostname == 'localhost'
        if not local:
            raise TransferError('Use HTTPS for services outside localhost.')
    return value.rstrip('/')


def secret(config, field):
    name = config.get(field)
    value = os.environ.get(name, '') if isinstance(name, str) else ''
    if not value or '\r' in value or '\n' in value:
        raise TransferError(f'Set the environment variable configured by {field}.')
    return value


def checksum(path):
    with Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def curl_quote(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('\r', '\\r').replace('\n', '\\n') + '"'


def request(url, key, output, method='GET', payload=None, upload=None, cloud_path=None, max_bytes=16*1024*1024):
    # Credentials and JSON bodies are supplied on stdin, never command arguments.
    options = ['header = ' + curl_quote('Authorization: Bearer ' + key)]
    if payload is not None:
        options += ['header = "Content-Type: application/json"', 'data-binary = ' + curl_quote(json.dumps(payload))]
    command = ['curl', '--silent', '--show-error', '--fail-with-body', '--connect-timeout', '10', '--max-time', '900', '--max-filesize', str(max_bytes), '--config', '-', '--request', method, '--output', str(output), '--write-out', '%{http_code}', '--url', url]
    if upload is not None:
        # Quoted multipart file syntax handles commas/semicolons in a local path.
        file_name = str(Path(upload).resolve()).replace('\\', '\\\\').replace('"', '\\"')
        command += ['--form', f'file=@"{file_name}"', '--form-string', 'path=' + cloud_path]
    result = subprocess.run(command, input='\n'.join(options)+'\n', text=True, capture_output=True)
    if result.returncode or result.stdout.strip() not in ('200', '201'):
        # Never print response bodies/stderr that might contain credentials or user data.
        status = result.stdout.strip()
        raise TransferError('Transfer failed' + (' (HTTP '+status+')' if re.fullmatch(r'\d{3}', status) else '') + '. Pending job retained for safe retry.')
    return int(result.stdout.strip())


def json_request(url, key, output, **kwargs):
    request(url, key, output, **kwargs)
    if Path(output).stat().st_size > 16*1024*1024:
        raise TransferError('JSON response exceeds the client limit.')
    try:
        return load_json(output)
    except (ValueError, OSError):
        raise TransferError('Service returned an invalid JSON response.')


def validate_metadata(value):
    if not isinstance(value, dict) or not re.fullmatch(r'[0-9a-f]{32}', str(value.get('id', ''))) or not re.fullmatch(r'[0-9a-f]{64}', str(value.get('sha256', ''))) or type(value.get('size')) is not int or not 0 < value['size'] <= MAX_BACKUP:
        raise TransferError('Host returned invalid backup metadata.')
    return {k: value[k] for k in ('id', 'filename', 'created_at', 'size', 'sha256') if k in value}


def cloud_prefix(value):
    if not isinstance(value, str) or '\\' in value or any(part in ('', '.', '..') for part in value.split('/')) or any(c in value for c in '\r\n'):
        raise TransferError('Configure a relative CSO path prefix with ordinary folder segments.')
    return value


def run(config_path):
    os.umask(0o077)
    config = load_json(config_path)
    directory = work_directory(config, config_path)
    with lock(directory, 'main.lock'):
        state_path = directory / 'state.json'
        state = load_json(state_path) if state_path.exists() else {'hosts': {}}
        cso = config['cso']
        cso_url, cso_key = base_url(cso['url']), secret(cso, 'api_key_env')
        prefix = cloud_prefix(cso.get('path_prefix', 'backups'))
        hosts = config.get('hosts', [])
        names = [h.get('name', '') for h in hosts]
        if not names or len(names) != len(set(names)) or any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', str(n)) for n in names):
            raise TransferError('Configure at least one uniquely named host using letters, digits, hyphens, or underscores.')
        cycle = state.get('cycle') or {'completed': []}
        state['cycle'] = cycle
        write_json(state_path, state)
        for host in hosts:
            name = host['name']
            if name in cycle['completed']:
                continue
            host_url, host_key = base_url(host['url']), secret(host, 'api_key_env')
            passphrase = secret(host, 'passphrase_env')
            host_state = state['hosts'].setdefault(name, {})
            job = host_state.get('pending')
            if not job:
                job = {'request_id': secrets.token_hex(16), 'host_url': host_url, 'cso_url': cso_url, 'prefix': prefix}
                host_state['pending'] = job
                write_json(state_path, state)
            if (job['host_url'], job['cso_url'], job['prefix']) != (host_url, cso_url, prefix):
                raise TransferError('A pending job belongs to different endpoints/prefix. Resolve it before changing configuration.')
            response_file = directory / (name + '-response.json')
            if 'backup' not in job:
                metadata = json_request(host_url+'/api/backups/trigger', host_key, response_file, method='POST', payload={'request_id': job['request_id'], 'passphrase': passphrase})
                job['backup'] = validate_metadata(metadata)
                job['cloud_path'] = prefix+'/'+name+'/'+metadata['id']+'.outhman'
                write_json(state_path, state)
            metadata = validate_metadata(job['backup'])
            local = directory / (name+'-'+metadata['id']+'.outhman')
            if not local.exists() or local.stat().st_size != metadata['size'] or checksum(local) != metadata['sha256']:
                partial = local.with_suffix('.part')
                request(host_url+'/api/backups/'+metadata['id'], host_key, partial, max_bytes=MAX_BACKUP)
                if partial.stat().st_size != metadata['size'] or checksum(partial) != metadata['sha256']:
                    raise TransferError('Host backup checksum verification failed.')
                os.replace(partial, local)
            files = json_request(cso_url+'/api/v1/files', cso_key, response_file).get('files')
            if not isinstance(files, list):
                raise TransferError('CSO returned an invalid file listing.')
            matches = [f for f in files if f.get('path') == job['cloud_path']]
            if len(matches) > 1:
                raise TransferError('CSO returned duplicate backup paths.')
            if matches:
                remote = matches[0]
            else:
                remote = json_request(cso_url+'/api/v1/files', cso_key, response_file, method='POST', upload=local, cloud_path=job['cloud_path'])
            if type(remote.get('id')) is not int or remote['id'] < 1 or remote.get('path') != job['cloud_path'] or remote.get('size') != metadata['size']:
                raise TransferError('CSO returned incompatible uploaded-file metadata.')
            # CSO returns original bytes after its own decrypt/decompress transforms.
            verification = directory / (name+'-cloud-verify.part')
            request(cso_url+'/api/v1/files/'+str(remote['id']), cso_key, verification, max_bytes=MAX_BACKUP)
            if verification.stat().st_size != metadata['size'] or checksum(verification) != metadata['sha256']:
                raise TransferError('Cloud download checksum verification failed; previous backups were not deleted.')
            verification.unlink()
            response_file.unlink(missing_ok=True)
            host_state['last_success'] = {'backup': metadata, 'cso_file_id': remote['id'], 'cloud_path': job['cloud_path']}
            host_state['pending'] = None
            cycle['completed'].append(name)
            write_json(state_path, state)
            print('Verified backup completed for '+name+'.', flush=True)
        state['cycle'] = None
        write_json(state_path, state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    try:
        run(args.config)
    except TransferError as exc:
        print('BackMan: '+str(exc), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError):
        print('BackMan failed. Check configuration, credentials, service availability, and pending job state. Secrets were not logged.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
