<!-- Badges (replace href/src with your own) -->
<p align="center">
  <a href="ASSET_URL_BADGE_BUILD"><img src="ASSET_URL_BADGE_BUILD" alt="Build Status"></a>
  <a href="ASSET_URL_BADGE_PI"><img src="ASSET_URL_BADGE_PI" alt="Raspberry Pi"></a>
  <a href="ASSET_URL_BADGE_LICENSE"><img src="ASSET_URL_BADGE_LICENSE" alt="License"></a>
</p>

<h1 align="center">Ars0n Framework — Raspberry Pi Edition 🛠️</h1>
<p align="center">ARM64-optimized fork with a hardened, reproducible setup. Fixes the classic “Failed to fetch” by steering the frontend to the Pi’s API IP.</p>

<p align="center">
  <img src="ASSET_URL_HERO" alt="Ars0n Pi Edition Hero" width="860">
</p>

---

## Table of Contents
- [Quick Start](#-quick-start-5-steps)
- [Architecture](#-architecture)
- [Detailed Setup](#-detailed-setup)
- [Ignition Script](#-ignition-script)
- [Autostart on Boot](#-autostart-on-boot)
- [Verification Checklist](#-verification-checklist)
- [Troubleshooting](#-troubleshooting)
- [FAQ](#-faq)

---

## 🚀 Quick Start (5 steps)

1) **Install prerequisites**  
   Docker + Docker Compose. Ensure your user is in `docker` group.

2) **Configure frontend environment**  
   Detect your Pi’s LAN IP and inject into client build:
   ```bash
   PI_IP=$(hostname -I | awk '{print $1}')
   echo "REACT_APP_SERVER_IP=${PI_IP}" > client/.env
````

3. **Build & run the stack**

   ```bash
   docker compose down
   docker compose build --no-cache
   docker compose up -d
   ```

4. **Open the app**
   UI: `http://${PI_IP}:3000`
   API: `https://${PI_IP}:8443`

5. **(Optional) Enable autostart**
   See [Autostart on Boot](#-autostart-on-boot).

---

## 🧭 Architecture

<p align="center">
  <img src="ASSET_URL_ARCH" alt="High-level Architecture" width="860">
</p>

**Flow summary**

* **Client** (React) reads `REACT_APP_SERVER_IP` at build time → calls **API** at `https://${IP}:8443`.
* **API** serves requests, talks to **PostgreSQL**, orchestrates modules (assetfinder, gospider, nuclei, etc.).
* All services live on Docker network `ars0n-network`.

**Ports**

* Client → `3000/tcp` (host → container)
* API → `8443/tcp` (host → container)
* DB → `5432/tcp` (internal only unless you expose it)

---

## 📋 Detailed Setup

### Prereqs & Permissions

* Raspberry Pi 4 (8 GB recommended), ARM64 Linux.
* Docker daemon running.
* Add your user to docker:

  ```bash
  sudo usermod -aG docker ${USER}
  newgrp docker
  ```

### Configure Frontend → API

Create the `.env` **before** building:

```bash
PI_IP=$(hostname -I | awk '{print $1}')
echo "REACT_APP_SERVER_IP=${PI_IP}" > client/.env
```

This writes something like:

```
REACT_APP_SERVER_IP=192.168.1.92
```

### Build & Run

```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```

---

## 🔥 Ignition Script

Use this one-liner setup script to automate IP detection, env generation, and deployment.

> Save as `ignition.sh` in repo root, then `chmod +x ignition.sh` and run `./ignition.sh`.

```bash
#!/usr/bin/env bash
set -e

echo "[+] Detecting Pi IP address..."
PI_IP=$(hostname -I | awk '{print $1}')
if [ -z "$PI_IP" ]; then
  echo "Error: Could not detect local IP address. Exiting."
  exit 1
fi
echo "Detected IP: $PI_IP"

echo "[+] Writing frontend env configuration (client/.env)..."
mkdir -p client
cat > client/.env <<EOF
REACT_APP_SERVER_IP=${PI_IP}
EOF

echo "[+] Shutting down any existing containers..."
docker compose down || true

echo "[+] Building containers (no cache)..."
docker compose build --no-cache

echo "[+] Starting containers..."
docker compose up -d

echo "[+] Setup complete."
echo "UI  : http://${PI_IP}:3000"
echo "API : https://${PI_IP}:8443"
```

<p align="center">
  <img src="ASSET_URL_FLOW" alt="Ignition Flow" width="720">
</p>

---

## 🧷 Autostart on Boot

Create `/etc/systemd/system/ars0n.service`:

```ini
[Unit]
Description=Ars0n Framework Service
Requires=docker.service
After=network-online.target docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=${USER}
Group=${USER}
WorkingDirectory=/path/to/your/repo
ExecStart=/usr/bin/docker compose up -d --build
ExecStop=/usr/bin/docker compose down
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

Enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ars0n.service
```

---

## ✅ Verification Checklist

* [ ] `client/.env` exists and contains `REACT_APP_SERVER_IP=<Pi IP>`
* [ ] `docker compose up -d` completes without errors
* [ ] `docker compose ps` shows `client`, `api`, `db` `Up`
* [ ] UI reachable at `http://${PI_IP}:3000`
* [ ] API reachable at `https://${PI_IP}:8443`
* [ ] Browser DevTools Network calls go to your Pi IP, not `127.0.0.1`

---

## 🛠️ Troubleshooting

| Symptom                           | Root Cause                           | Remediation                                                                    |
| --------------------------------- | ------------------------------------ | ------------------------------------------------------------------------------ |
| “Failed to fetch” / cannot import | Frontend still points to `127.0.0.1` | Recreate `client/.env` and rebuild. Confirm requests hit `https://${IP}:8443`. |
| CORS error in browser             | API origin not allowed               | Configure API to allow `http://${PI_IP}:3000`.                                 |
| UI loads, actions fail            | API unreachable or wrong protocol    | Test with `curl -k https://${PI_IP}:8443/…`. Fix protocol or certificate.      |
| Nothing on `:3000`                | Client not exposed or bound          | Confirm `ports: "3000:3000"` and client listens on `0.0.0.0`.                  |
| DB errors                         | DB not healthy or wrong env          | Check `docker compose logs db` and API `DATABASE_URL`.                         |

Logs:

```bash
docker compose logs client
docker compose logs api
docker compose logs db
```

Network and ports:

```bash
docker compose ps
ss -tulpen | grep -E '(:3000|:8443)'
```

---

## ❓ FAQ

**Q:** Do I need to edit the compose file for my IP?
**A:** No. Create `client/.env` with `REACT_APP_SERVER_IP` or run `./ignition.sh`. Then build.

**Q:** Can I change the UI port?
**A:** Yes. Edit the client service `ports` mapping in `docker-compose.yml`.

**Q:** Will this work on non-Pi hosts?
**A:** Yes, as long as `REACT_APP_SERVER_IP` reflects the host IP the browser should call.

---

## 📦 Client snippet (reference)

```yaml
client:
  container_name: ars0n-framework-v2-client-1
  build:
    context: ./client
    args:
      REACT_APP_SERVER_IP: 192.168.1.92
  ports:
    - "3000:3000"
  depends_on:
    - api
  restart: unless-stopped
  networks:
    - ars0n-network
```

> Ensure your full compose file follows the same pattern.

---

<p align="center">
  <img src="ASSET_URL_FOOTER" alt="Footer" width="680">
</p>
