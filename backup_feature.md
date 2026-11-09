# BackMan-driven encrypted backups

This replaces the former host-managed backup timer. OuthMan creates encrypted database files; the external BackMan runner decides when to create them, downloads them, and transfers them to CSO using the contract in [Backup_API.md](Backup_API.md).

## Architecture

```text
backMan_runner.py (schedule / supervision)
    -> backMan.py (main transfer script, invokes curl)
        -> OuthMan: trigger encrypted snapshot, then download exact ID
        -> CSO: multipart upload into one Storage space
        -> CSO: download original bytes and verify SHA-256
```

Both client scripts use Python 3.11+ standard-library modules and the installed `curl` binary. They do not need Flask, requests, cryptography, or a database driver beyond Python's standard library. The host still needs `requirements.txt` for its encrypted snapshot implementation. The runner uses Unix file locking and supports macOS/Linux. CSO and OuthMan must be separately running/reachable; these scripts do not start either service.

## What the host shows

**Settings → Backup & restore** shows the encrypted backup files currently present on the host, each file's name, size, backup time, and download action. It also lets an admin issue/revoke backup keys and restore an encrypted file. The file list is not a CSO/cloud listing and does not claim an upload has succeeded.

The host no longer starts a backup timer. Old timer configuration is preserved as legacy encrypted instance data but is not executed. POST `/api/backups/schedule` returns 410 directing callers to the external runner. Transfer the desired schedule to BackMan's config. Existing encrypted backups remain usable; existing download-only keys remain read-only.

## 1. Prepare OuthMan and CSO

1. In OuthMan **Settings → IP allowlist**, allow the BackMan machine's actual connecting IP/network. Use `127.0.0.1` if it runs on the same machine. Forwarded headers are ignored.
2. In **Settings → Backup & restore → BackMan access**, enter a name and choose **BackMan — trigger & download**. Create the API key and copy it immediately.
3. New host keys have **128 bits of entropy**, represented as exactly **32 hexadecimal characters**. Only hashes are stored; keys are shown once and can be revoked. The trigger/download scope cannot restore data, manage accounts, create other keys, or change settings. Download-only keys cannot trigger creation.
4. In CSO, connect cloud storage and create a dedicated Storage space. Save its Storage space API key. Set a quota and single-file size limit large enough for the encrypted backup. See `Backup_API.md` for CSO setup, transformations, and errors.
5. Choose a host backup passphrase of 12–256 characters. Preserve it independently for restore. This is separate from both API keys and from CSO's own encryption material.

Use HTTPS for non-local services. The BackMan scripts reject remote plain-HTTP URLs; loopback HTTP is allowed for development. The example loopback addresses work only when both servers run on the BackMan machine. Exposing a service requires proper hosting/proxy configuration, not merely changing a client URL.

## 2. Configure the two scripts

Copy `backMan.example.json` to `backMan.config.json` and edit URLs, host name, path prefix, and schedule. Paths in the example work directory are relative to the config file.

```json
{
  "work_dir": "./backman-data",
  "hosts": [
    {
      "name": "outhman",
      "url": "http://127.0.0.1:10070",
      "api_key_env": "OUTHMAN_BACKUP_KEY",
      "passphrase_env": "OUTHMAN_BACKUP_PASSPHRASE"
    }
  ],
  "cso": {
    "url": "http://127.0.0.1:10081",
    "api_key_env": "CSO_KEY",
    "path_prefix": "backups"
  },
  "schedule": {
    "frequency": "daily",
    "time": "01:00",
    "timezone": "America/Chicago"
  }
}
```

Host names must be unique and use letters, digits, hyphens, or underscores. Add additional compatible hosts to `hosts` if needed. Each host can have a separate key/passphrase environment variable. The single config schedule triggers a cycle over all configured hosts.

Set the environment variables named in your config through your service's secret store or local environment. For a one-time interactive test without placing secrets in command arguments or shell history:

```sh
python3 - <<'PY'
import getpass, os, subprocess, sys
env = os.environ.copy()
for name in ('OUTHMAN_BACKUP_KEY', 'OUTHMAN_BACKUP_PASSPHRASE', 'CSO_KEY'):
    env[name] = getpass.getpass(name + ': ')
sys.exit(subprocess.call([sys.executable, 'backMan_runner.py', '--config', 'backMan.config.json', '--once'], env=env))
PY
```

The example prompts match the environment variable names above; adjust them for a customized config. For unattended operation, supply those values through the runner's service environment.

Run the main script once immediately:

```sh
python3 backMan.py --config backMan.config.json
```

Or have the runner invoke it once:

```sh
python3 backMan_runner.py --config backMan.config.json --once
```

Run the persistent scheduler:

```sh
python3 backMan_runner.py --config backMan.config.json
```

Keep the runner running (for example under your own launchd/systemd service). Closing its terminal stops it unless a supervisor keeps it alive. `Ctrl+C` stops it. OuthMan does not start BackMan automatically. No real cloud transfer occurs until valid endpoints and both services' credentials are configured.

## 3. Scheduling belongs to the runner

`time` uses `HH:MM` and the explicitly configured IANA timezone. Midnight is `00:00`; 1 PM is `13:00`.

Daily:

```json
{"frequency":"daily","time":"01:00","timezone":"America/Chicago"}
```

Weekly, Saturday and Sunday (Monday=0, Sunday=6):

```json
{"frequency":"weekly","weekdays":[5,6],"time":"01:00","timezone":"America/Chicago"}
```

Monthly, the 31st or the last day in shorter months:

```json
{"frequency":"monthly","day_of_month":31,"time":"00:00","timezone":"America/Chicago"}
```

Interval:

```json
{"frequency":"interval","interval_minutes":60}
```

Intervals support 5–43200 minutes. The first interval waits one full interval; calendar schedules pick the next future occurrence. The runner checks at most every 30 seconds, persists its deadline, and runs one overdue cycle after restart rather than replaying every missed occurrence. Spring-forward gaps run at the first valid minute afterward; repeated fall-back times run once. Failed pending work is retried no more than once per minute using saved job state. Changes to `schedule` are picked up while running; restart after changing work-directory configuration.

## 4. Host API: trigger, list, download

All of these require a permitted caller IP plus a backup Bearer key. A configured admin cookie can still list/download and use the legacy manual-create route, but `/trigger` specifically requires a scoped BackMan key.

| Method / endpoint | Permission | Purpose |
| --- | --- | --- |
| POST `/api/backups/trigger` | `backups:create,read` | Create or return an idempotent encrypted backup |
| GET `/api/backups` | Either backup key scope | List files: `{backups:[{id,filename,created_at,size}]}` |
| GET `/api/backups/<id>` | Either backup key scope | Download exact encrypted bytes |
| GET `/api/backups/latest` | Either backup key scope | Convenience download; BackMan uses exact IDs |
| POST `/api/backups/restore` | Admin cookie only | Confirmed restore; no backup key can restore |

Trigger request:

```json
{
  "request_id": "32_lowercase_hex_characters_for_this_job",
  "passphrase": "YOUR_BACKUP_ENCRYPTION_PASSPHRASE"
}
```

Generate a fresh `request_id` once per intended backup and reuse it only for retries. The response is 201 when created, or 200 when the same key/request ID already created the file:

```json
{
  "id": "32_hex_backup_id",
  "filename": "32_hex_backup_id.outhman",
  "created_at": 1794103200.0,
  "size": 1048576,
  "sha256": "64_hex_SHA256_of_encrypted_file",
  "request_id": "same_request_id",
  "reused": false
}
```

The key ID and request ID deterministically select the host backup ID. The host does not create another file for a retry while that file exists. Preserve the host file, key, request ID, and original passphrase until the pending job completes. Deleting the file or rotating credentials during an ambiguous trigger can defeat retry continuity.

For manual curl inspection after setting environment variables (BackMan itself supplies secrets to curl on stdin instead of command arguments):

```sh
curl --fail-with-body \
  -H "Authorization: Bearer $OUTHMAN_BACKUP_KEY" \
  http://127.0.0.1:10070/api/backups
```

For a one-off trigger without creating a JSON file (this starts a new job each time; use BackMan for persisted retries):

```sh
python3 -c 'import json,secrets,getpass; print(json.dumps({"request_id":secrets.token_hex(16),"passphrase":getpass.getpass("Backup passphrase: ")}))' \
  | curl --fail-with-body \
      -H "Authorization: Bearer $OUTHMAN_BACKUP_KEY" \
      -H 'Content-Type: application/json' --data-binary @- \
      http://127.0.0.1:10070/api/backups/trigger
```

`@-` reads JSON from the pipeline. BackMan constructs this body automatically, supplies credentials on curl's stdin, and persists the request ID before sending it.

Download using the actual returned ID (replace `BACKUP_ID`), then compare its SHA-256 to the trigger response:

```sh
curl --fail -H "Authorization: Bearer $OUTHMAN_BACKUP_KEY" \
  --output downloaded.outhman.part \
  http://127.0.0.1:10070/api/backups/BACKUP_ID \
  && mv downloaded.outhman.part downloaded.outhman
```

Status: 400 invalid request/passphrase; 401 invalid/revoked key; 403 denied IP or insufficient key scope; 404 missing file; 410 obsolete host schedule endpoint. JSON endpoints are `no-store`; binary responses are attachments. API logs never include request bodies, passphrases, or Authorization.

## 5. BackMan → CSO flow

BackMan follows `Backup_API.md` exactly:

1. Persist a new host request ID before triggering creation.
2. POST the host trigger and persist returned metadata/expected checksum.
3. GET that exact host file into `.part`, verify size/SHA-256, then atomically accept it locally.
4. GET CSO `/api/v1/files` and check for the exact intended path: `backups/<host_name>/<backup_id>.outhman` by default.
5. If absent, POST CSO `/api/v1/files` as multipart with `file=@...` and `path=...`. Let curl generate Content-Type/boundary. The host API key is never sent to CSO; the CSO Storage space key is never sent to the host.
6. Save/validate CSO's returned numeric ID/path/original size. Uploads are synchronous; curl allows up to 15 minutes per request.
7. GET CSO `/api/v1/files/<id>` and compare the downloaded original bytes' size/SHA-256. CSO reverses its own compression/encryption, leaving the host's `.outhman` encryption intact.
8. Only after verification, mark the host job complete and record the CSO file ID, path, and host checksum in local state.

If an upload's success response is lost, the pending job remains. A retry lists CSO paths first, finds a completed matching upload, downloads/verifies it, and does not blindly upload again. If CSO still reports in-progress/duplicate 409, the job stays pending for a later retry. The runner preserves completed hosts within a partially failed cycle instead of starting their backups again.

Read-back verification consumes another download's worth of CSO bandwidth. Ensure your space quota, single-file limit, and transfer allowance permit both upload and verification. CSO settings control compression/encryption; encrypted host files may not compress much. The script does not set per-upload compression/encryption flags or use the browser ticket API.

There is no retention deletion in BackMan, and it does not delete host/cloud files. Do not delete the last usable backup. Pending jobs/local files remain available after a failure. The work directory retains successful downloads as well; apply an explicit operator retention policy only after verification.

## 6. State, safety, and restore

`work_dir` contains private JSON state, downloaded encrypted files, temporary transfer files, and process locks. It is created 0700 and files 0600. `state.json` records pending request IDs, expected hashes, remote IDs/paths, and last successful results, not keys or passphrases. `runner-state.json` records the schedule/deadline. Keep state across restarts; do not change host/CSO URLs, prefixes, or credentials while a job is pending. Inspect/resolve pending jobs before replacing configuration. These scripts use one runner and a main-process lock per work directory; run one coordinated instance per config.

Backup contents, AES-GCM/scrypt encryption, 32 MB host limit, approval/device/login state, audit records, and excluded transient sessions/codes/PINs remain as before. The host keeps encryption passphrases in memory for manual/external triggers; BackMan obtains them from its environment. Existing legacy timer passphrases remain in encrypted host control configuration for compatibility, but are not executed by a timer.

To restore, obtain CSO's stored file ID from BackMan state (or list CSO paths), then use the CSO download command in `Backup_API.md`. In OuthMan Settings select the downloaded `.outhman` file and enter its original host passphrase. CSO may decrypt its storage wrapper, but it does not know this host passphrase. Restore requires admin confirmation, validates the file/database, preserves an encrypted recovery copy, and invalidates OuthMan sessions/codes/PINs. Log export epochs rotate. Instance API keys are outside DB backups, and a restore does not revive revoked keys.

Preserve CSO's own catalog/encryption material separately as its guide requires. Cloud provider objects alone may not be recoverable without that CSO metadata. Preserve host passphrases independently; neither a host API key nor CSO credentials can recover a lost host passphrase.

## 7. Reusing the host feature in other apps

Expose the same scoped trigger/list/download contract. The host remains responsible for producing a consistent, encrypted, versioned snapshot of its own durable data. Generate 128-bit random API keys, hash them, show once, support revoke, check caller IP and key scope, and keep restore/admin operations separate. Implement deterministic retry IDs or equivalent server-side idempotency so collectors do not create duplicate snapshots after ambiguous responses. Return exact file size, creation timestamp, immutable ID, and SHA-256.

For another DB or application files, write an app-specific snapshot/restore adapter instead of copying the SQLite implementation blindly. BackMan expects the documented host contract and `.outhman`-style opaque bytes; adapt extension/format handling when generalizing to another product. Never send cloud-provider or CSO credentials to the source application. Each destination should have its own dedicated CSO space/key and path prefix.

Reference files: `backups.py`, `backup_service.py`, host routes in `server.py`, `backMan.py`, `backMan_runner.py`, `backMan.example.json`, and `test_backman.py`. End-to-end tests use a temporary host and a simulated CSO API, including a successful upload with a lost response. They do not connect to a real cloud account.
