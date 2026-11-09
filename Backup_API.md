# CSO Backup API

External applications and backup scripts can upload, list, download, and delete backup files using the API key generated for a **Storage space** in CSO. A backup is an ordinary file; CSO does not create database dumps or backup archives for you.

## 1. Configure access

1. In CSO, connect a cloud account and create a Storage space with the required quota, maximum single-file size, compression, and encryption settings.
2. Save the generated **Storage space API key**. If necessary, use **Rotate API key** to generate a replacement; the old key stops working immediately.
3. Configure your backup client:

```sh
export CSO_URL='http://127.0.0.1:10081'
export CSO_KEY='YOUR_STORAGE_SPACE_API_KEY'
```

This local address works only on the CSO server itself. For a client on another machine, configure a reachable server address and use HTTPS, for example `https://cso.example.com`. CSO binds to loopback by default; external access requires appropriate hosting/reverse-proxy configuration. Setting the client URL alone does not expose the server.

Send this header with every request:

```http
Authorization: Bearer YOUR_STORAGE_SPACE_API_KEY
```

`X-API-Key: YOUR_STORAGE_SPACE_API_KEY` is also supported. Use the Storage space key, not OuthMan credentials or cloud-provider keys. API clients do not need a browser login or CSRF token. Each key permits uploads, listing, downloads, and deletion **only within its own space**. There are no separate read-only or upload-only permissions for these keys. Store keys in your server's secret configuration.

## 2. Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/v1/files` | Upload a backup |
| GET | `/api/v1/files` | List backups in the key's space |
| GET | `/api/v1/files/{id}` | Download a backup by numeric ID |
| DELETE | `/api/v1/files/{id}` | Permanently delete a backup |
| GET | `/api/v1/storage` | Read space quota and usage |

All examples below use the environment variables above. `curl --fail-with-body` returns a nonzero exit code for HTTP errors.

## 3. Upload a backup

Create your backup archive first, then send **multipart/form-data**:

```sh
curl --fail-with-body \
  -H "Authorization: Bearer $CSO_KEY" \
  -F 'file=@/path/to/database-backup.tar.gz' \
  -F 'path=backups/database/2026-11-08/database-backup.tar.gz' \
  "$CSO_URL/api/v1/files"
```

- `file`: required; the local file's contents.
- `path`: optional; the logical path within the Storage space. Defaults to the uploaded filename. Use `/` for nested folders. Absolute paths, backslashes, empty segments, `.` and `..` segments are rejected.
- Use a unique path for every backup. Existing paths are not overwritten; a duplicate or concurrently uploading path returns `409`.
- Do not manually set the multipart Content-Type header; your HTTP client must generate its boundary.

Successful upload returns **201 Created**, for example:

```json
{
  "id": 42,
  "path": "backups/database/2026-11-08/database-backup.tar.gz",
  "size": 1048576,
  "stored_size": 1048576,
  "compression": "none",
  "saved_bytes": 0,
  "created": "2026-11-08T18:00:00+00:00"
}
```

Save `id` for later download/deletion. `size` is the original file size in bytes; `stored_size` is the provider payload size after configured compression/encryption. Actual compression and savings vary by file.

Uploads through this external API are **synchronous**: the response waits for an execution slot, processing, and cloud transfer. Keep the connection open and configure client/proxy timeouts for large backups. The browser's background-upload ticket flow is separate and is not used here. There is no resumable-upload endpoint. If the connection is lost, list files and check the path before retrying: the upload may have completed despite the lost response.

## 4. List backups

```sh
curl --fail-with-body \
  -H "Authorization: Bearer $CSO_KEY" \
  "$CSO_URL/api/v1/files"
```

Successful response: **200 OK**.

```json
{
  "files": [
    {
      "id": 42,
      "path": "backups/database/2026-11-08/database-backup.tar.gz",
      "size": 1048576,
      "created": "2026-11-08T18:00:00+00:00"
    }
  ]
}
```

An empty space returns `{"files": []}`. The endpoint returns all file metadata in the space; filter paths and sort timestamps in your client. There are no server-side search, pagination, or retention parameters on this endpoint.

## 5. Download a backup

Replace `42` with the returned file ID:

```sh
curl --fail-with-body \
  -H "Authorization: Bearer $CSO_KEY" \
  --output restored-backup.tar.gz.part \
  "$CSO_URL/api/v1/files/42" && \
  mv restored-backup.tar.gz.part restored-backup.tar.gz
```

Successful response: **200 OK** with binary file contents. CSO automatically decrypts and decompresses configured storage transformations, delivering the original uploaded bytes. Your own `.tar.gz`, `.zip`, or database backup format remains intact. The attachment filename is the final component of the logical path.

Only use the downloaded file after the request succeeds. With `--fail-with-body`, an error response may be written into the `.part` file; the command above renames it only on success. For backup verification, save a SHA-256 checksum at creation and compare it after restoring.

## 6. Delete a backup

Deletion is permanent. Confirm the ID from the listing before calling:

```sh
curl --fail-with-body \
  -X DELETE \
  -H "Authorization: Bearer $CSO_KEY" \
  "$CSO_URL/api/v1/files/42"
```

Successful response: **200 OK**:

```json
{"ok": true}
```

CSO deletes the provider object before removing its catalog entry and releasing recorded storage usage. This does not purge unrelated files or other versions created outside CSO. A repeated delete returns `404`; a file belonging to another Storage space also returns `404`.

For retention, have your backup client list files, select expired backups within its own path prefix, and delete their IDs. Verify a new backup before deleting the previous usable copy. CSO does not implement automatic retention through these endpoints.

## 7. Check quota and transfer allowance

```sh
curl --fail-with-body \
  -H "Authorization: Bearer $CSO_KEY" \
  "$CSO_URL/api/v1/storage"
```

Example **200 OK** response:

```json
{
  "name": "Database backups",
  "quota": 10737418240,
  "used": 1048576,
  "encrypted": true,
  "bandwidth_limit": 0,
  "bandwidth_used": 1048576
}
```

All sizes are bytes. `bandwidth_limit: 0` means unlimited. Space quota and monthly transfer accounting use original file sizes; cloud capacity accounting uses stored payload sizes. Both uploads and downloads consume the space's transfer allowance. The effective single-file upload limit is the lower of the space setting and the server ceiling. Provider capacity and transfer restrictions also apply.

## 8. Errors and retries

Errors normally return JSON:

```json
{"error": "Explanation of the failure."}
```

| HTTP status | Meaning / client action |
| --- | --- |
| 400 | Invalid input/path or exceeded transfer allowance; inspect `error`. |
| 401 | Missing, invalid, or rotated Storage space API key. |
| 404 | File not found in this key's space. |
| 409 | Duplicate/in-progress path, or space being deleted; inspect `error`. |
| 413 | Request/file limit or Storage space quota exceeded. |
| 507 | No suitable cloud capacity or pinned cloud is full. |
| 502 | Cloud provider operation failed; inspect `error`. |

A proxy may return its own error format or size/timeout limit. Do not blindly retry uploads after an ambiguous timeout; check the file listing first. Retry transient failures with a bounded delay/backoff. There is no idempotency-key or overwrite API.

## 9. Where backup data is stored

For a cloud provider, CSO stages uploads temporarily on the server while queued/processing/transferring, then deletes the staged copy when the operation succeeds or fails. Crash leftovers are cleaned on server startup. Completed file contents remain with the selected provider; the server retains the catalog, configuration, and operation history. A space assigned to **Local storage** retains its files on the CSO server instead.

Compression and encryption are controlled by the Storage space settings, not per-upload API parameters. Preserve and back up CSO's catalog and encryption-key material separately: provider objects alone are not a complete recovery plan for CSO-managed encrypted backups.

## OuthMan / BackMan client

This repository includes a client implementation: `backMan.py` creates/downloads a host backup and uses the CSO multipart API above; `backMan_runner.py` schedules the main script. See [backup_feature.md](backup_feature.md) and `backMan.example.json` for configuration. OuthMan's 128-bit backup key and CSO's Storage space API key are separate credentials for separate servers.
