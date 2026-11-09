# OuthMan Docker deployment on Raspberry Pi

This guide builds OuthMan from `https://github.com/CosineCloud/OuthMan` and runs it with persistent data. The supplied image targets **64-bit Raspberry Pi OS (`linux/arm64`)** on a Pi 3/4/5 or another compatible ARM64 device. It also builds for `linux/amd64`. This setup does not claim support for 32-bit Pi OS or ARMv6 Pi/Zero models.

The Python official image supports ARM64; Docker's guidance for 64-bit Raspberry Pi OS is to use the Debian ARM64 installation. References: [Docker Raspberry Pi guidance](https://docs.docker.com/engine/install/raspberry-pi-os/), [Debian Docker installation](https://docs.docker.com/engine/install/debian/), [Python official image](https://hub.docker.com/_/python).

## 1. Check the Pi and install Docker

On the Raspberry Pi:

```sh
uname -m
dpkg --print-architecture
```

Expected: `aarch64` and `arm64`. If you see `armv7l` or `armhf`, install Raspberry Pi OS 64-bit before following this guide.

If Docker is not installed, follow the official **Debian** Docker instructions linked above for your supported Debian/Raspberry Pi OS release. Install Docker Engine, Buildx, and the Compose plugin. Avoid the separate 32-bit Raspbian package instructions on an ARM64 OS.

Verify the installation:

```sh
sudo docker version
sudo docker compose version
sudo docker run --rm hello-world
```

Install Git if needed:

```sh
sudo apt-get update
sudo apt-get install -y git
```

Commands below use `sudo docker` so no Docker group changes are required. Docker Desktop users on a development Mac/PC normally omit `sudo`.

## 2. Clone and configure

```sh
git clone https://github.com/CosineCloud/OuthMan.git
cd OuthMan
cp .env.example .env
```

The default `.env` is:

```dotenv
OUTHMAN_BIND_ADDRESS=127.0.0.1
OUTHMAN_HOST_PORT=10070
OUTHMAN_SECURE_COOKIE=0
```

This publishes the service only on the Pi's loopback interface. The app listens on `0.0.0.0:10070` **inside** the container; this is necessary for Docker port forwarding and does not itself publish a LAN port.

There are no credentials in `.env.example`. Never commit `.env`, databases, encrypted backups, browser cookie jars, or private API keys. The repository and Docker context exclude those local files.

## 3. Build and start the container

Build natively on the Pi; Docker selects its ARM64 base image automatically:

```sh
sudo docker compose up -d --build
sudo docker compose ps
sudo docker compose logs --tail=100 outhman
```

The image uses Python 3.12 and binary cryptography wheels, avoiding a Rust source build on the Pi. Installations need enough RAM/disk for Docker and the build; Pi 4/5 with at least 2 GB RAM are practical starting points. Native builds take longer on smaller models.

Check the HTTP service:

```sh
curl --fail-with-body http://127.0.0.1:10070/api/me
```

Before login, the response contains `"user": null`. Container health becomes `healthy` after startup. Fresh installs initialize `admin@admin.com` / `pass123`; the first browser login requires changing both. Existing persistent data keeps its existing admin credentials.

## 4. Open the UI from another computer

Browser fingerprinting uses Web Crypto, which requires HTTPS or a trusted localhost context. Opening `http://PI_IP:10070` directly is not the recommended browser access method.

For a quick private deployment, use an SSH tunnel from your laptop. Replace `YOUR_PI_USER` and the Pi hostname/IP:

```sh
ssh -N -L 10071:127.0.0.1:10070 YOUR_PI_USER@raspberrypi.local
```

Open **http://127.0.0.1:10071** on the laptop. Keep the SSH session open. The separate laptop port 10071 avoids conflicting with a local development server already using 10070. Leave secure cookies at `0` for this localhost HTTP tunnel.

For routine network access, put a configured HTTPS reverse proxy in front of the service and set:

```dotenv
OUTHMAN_SECURE_COOKIE=1
```

Then recreate the app:

```sh
sudo docker compose up -d
```

Use the same public origin for browser pages and API calls. Configure the proxy's trusted hostname and certificates according to your infrastructure. The included service is the project's existing Python HTTP server; Docker packaging does not replace it with a production application server or provide TLS automatically.

A proxy running on the Pi host can connect to the loopback port. A proxy container should join the Compose network and use `http://outhman:10070`; do not point its loopback at the Pi host. If you intentionally publish a LAN interface by changing `OUTHMAN_BIND_ADDRESS`, protect that interface appropriately and use HTTPS for user access. Do not expose the bootstrap account to an untrusted network.

## 5. Persistent data and permissions

Compose has the fixed project name `outhman`. Its named volume is normally **`outhman_outhman-data`**, mounted at `/data`. It contains:

- `/data/outhman.sqlite3`: accounts, app links, activity, ACL, and log cursor metadata.
- `/data/backups/`: encrypted database backup files.
- `/data/backup-control.key` and `/data/backup-control.enc`: encrypted instance key/configuration data, including backup and log API key hashes.

The container runs as non-root UID/GID **10001:10001**, with a read-only app filesystem, a temporary `/tmp`, dropped capabilities, and a no-new-privileges policy. Docker initializes the named volume with the image's `/data` ownership. Files are not stored in the container's disposable writable layer.

Restart or rebuild without losing data:

```sh
sudo docker compose restart
sudo docker compose up -d --build
```

Stop/remove the container while retaining the volume:

```sh
sudo docker compose down
```

**Do not add `--volumes` / `-v` unless you intend to delete all persistent app data.** Keep the control key and encrypted control config together when moving a full installation; database-only restores intentionally do not restore API key configuration.

If you choose a bind mount instead of the supplied named volume, create the directory and assign it to UID/GID 10001 before mounting it:

```sh
sudo install -d -m 0700 -o 10001 -g 10001 /srv/outhman-data
```

Replace the Compose volume mapping with `/srv/outhman-data:/data`. Do not mount the repository's live development database while another OuthMan process is writing to it.

## 6. ACL and integration clients in Docker

In **Settings → IP allowlist**, allow the directly connected IP/network used by your integrating backend, BackMan, and log collector. Docker port forwarding and reverse proxies can make the server see a bridge/gateway/proxy IP rather than the original client. Check the caller IP shown in Settings and the request logs before choosing a narrow rule. OuthMan deliberately ignores forwarded IP headers.

Use a different app credential for each integration/environment and assign users/apps to appropriate groups. Review manual account approval and browser binding in `README.md`.

## 7. BackMan and CSO from a Pi deployment

The app image contains the host backup API; it does not run the external BackMan scheduler or contain your cloud credentials. Run the two lightweight scripts on the Pi host or on a separate authorized machine. On the Pi host, published `http://127.0.0.1:10070` works with BackMan's localhost allowance. A different machine must use a reachable HTTPS host URL.

On the Pi, install the client prerequisites:

```sh
sudo apt-get install -y python3 curl
cp backMan.example.json backMan.config.json
```

Configure URLs and named secret environment variables as documented in [backup_feature.md](backup_feature.md). Generate a 128-bit trigger/download key in OuthMan and a separate Storage space key in CSO. The client uses only Python's standard library plus curl; do not install the host's cryptography dependency just to run BackMan.

One test cycle, after configuring secrets:

```sh
python3 backMan_runner.py --config backMan.config.json --once
```

Persistent daily/weekly/monthly scheduling:

```sh
python3 backMan_runner.py --config backMan.config.json
```

Keep that process running under your own supervisor for unattended backups. Do not use the same loopback URL for CSO unless CSO is actually reachable on the Pi host at its configured port. Container loopback addresses refer to that container, not another container or another computer. See [Backup_API.md](Backup_API.md) for CSO upload/list/download behavior and [LOG_API_INT.MD](LOG_API_INT.MD) for log collection.

## 8. Full installation transfer / recovery copy

Encrypted database backups are the routine application recovery path. To additionally preserve the instance's API keys/configuration for a full move, stop the app and archive the whole data volume. This tar archive contains private server key material: store it securely outside the public repository.

```sh
sudo docker compose stop outhman
sudo docker run --rm --user 0:0 \
  -v outhman_outhman-data:/data:ro \
  -v "$PWD:/transfer" \
  --entrypoint sh outhman:local \
  -c 'umask 077; tar -C /data -czf /transfer/outhman-volume.tar.gz .'
sudo docker compose start outhman
```

The archive is not automatically encrypted. Restrict and encrypt it using your organization's storage process. For a transfer to another Pi, use the same UID/GID, create the destination volume, extract this trusted archive into it while the destination app is stopped, then start Compose. Do not extract arbitrary untrusted archives into a data volume.

## 9. Tests and multi-platform image builds

Run the full test suite inside an isolated Linux image (temporary test DBs only):

```sh
sudo docker build --target test -t outhman:test .
```

Build an ARM64 app image on a Pi:

```sh
sudo docker build --platform linux/arm64 --target app -t outhman:local .
```

Cross-build on a Mac/PC with a suitable Buildx builder/emulation setup:

```sh
docker buildx build --platform linux/arm64 --target app --load -t outhman:pi .
```

A multi-platform image can be exported to a local OCI archive without publishing:

```sh
docker buildx build --platform linux/amd64,linux/arm64 --target app \
  --output type=oci,dest=outhman-images.tar .
```

Publishing an image to a registry is separate from pushing this source repository; use your own registry name and authorized credentials if you choose to publish. See [Docker multi-platform build guidance](https://docs.docker.com/build/building/multi-platform/). The included GitHub workflow runs container tests and builds both architectures without publishing an image.

## 10. Updates and troubleshooting

```sh
git pull --ff-only
sudo docker compose up -d --build
sudo docker compose ps
sudo docker compose logs --tail=100 outhman
```

Before updates, keep a current encrypted backup and, when moving installations, a protected full-volume copy.

- **Cannot connect to Docker daemon:** start Docker Engine (`sudo systemctl start docker` on a configured Pi) or Docker Desktop on a development machine.
- **Port already allocated:** change `OUTHMAN_HOST_PORT` in `.env`; keep the internal app port 10070 for the included healthcheck.
- **Permission denied on `/data`:** use the named volume or fix the bind mount ownership to 10001:10001.
- **No matching ARM image/wheel:** verify `aarch64`/`arm64`, use the supplied Python 3.12 Dockerfile, and rebuild with current package access. A 32-bit host requires a separate tested image strategy.
- **User login fails through plain Pi IP:** use the localhost SSH tunnel or HTTPS, then check approval, binding, suspension, and login-block status as admin.
- **Backup/log API returns 403:** review the directly connected Docker/proxy caller IP and key scope.
- **App restarts after updating:** check logs for database/configuration permissions and dependency errors; persistent files remain in the named volume.

## Validation performed

The Linux test image ran all 21 tests successfully as UID 10001. Both `linux/amd64` and `linux/arm64` app images were built and started with a read-only root filesystem and persistent volumes. Their healthchecks passed. The ARM64 image created an encrypted backup and retained it after the container was replaced using the same volume. ARM64 runtime validation used Docker emulation on a development machine; physical Raspberry Pi hardware was not available for this check.
