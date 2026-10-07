#!/bin/bash
# LNX-VR deployment on the fixed REMnux guest (MalTrace 7.1 prerequisite).
# 2026-10-06/07 executed end-to-end; two-triage hard acceptance passed.
# Run ON the guest (or drive via ssh). Requires: internet-reachable host
# performed the binary download first (see README).
set -eu
VELO_VER=v0.77.3
BIN_SHA16=93171158fa081c07   # first 16 hex of sha256 (linux-amd64-musl)

sudo mkdir -p /opt/velociraptor
sudo install -m 0755 "$1" /opt/velociraptor/velociraptor   # binary arg

# 1. server config: self-signed, all listeners on 127.0.0.1 only.
#    Generated non-interactively via:
#      velociraptor config generate --nobanner --merge '{"Client":{ \
#        "ServerUrls":["https://127.0.0.1:8000/"]},"Frontend":{ \
#        "bind_address":"127.0.0.1","bind_port":8000},"GUI":{ \
#        "bind_address":"127.0.0.1","bind_port":8889},"API":{ \
#        "bind_address":"127.0.0.1","bind_port":8001}}'
#    Reference copies: server.config.yaml / client.config.yaml here.
#    NOTE: client config must contain ONLY version+Client+CA — v0.77
#    rejects top-level writeback_* fields (put them under Client).
sudo install -m 0600 "$(dirname "$0")/server.config.yaml" \
  /opt/velociraptor/server.config.yaml
sudo install -m 0600 "$(dirname "$0")/client.config.yaml" \
  /opt/velociraptor/client.config.yaml

# 2. api client credentials (administrator+api), root 0600
sudo /opt/velociraptor/velociraptor --config /opt/velociraptor/server.config.yaml \
  config api_client --name api --role administrator,api /opt/velociraptor/api_client.yaml
sudo chmod 600 /opt/velociraptor/api_client.yaml
# guest-local VQL runner copy: root-owned 0700 dir + 0600 file, never world-readable
sudo install -d -m 0700 -o root -g root /opt/velociraptor/api-access
sudo install -m 0600 -o root -g root /opt/velociraptor/api_client.yaml /opt/velociraptor/api-access/api_client.yaml

# 3. systemd units (server 8000/8001/8889, client)
sudo tee /etc/systemd/system/velociraptor-server.service >/dev/null <<'U'
[Unit]
Description=Velociraptor server (LNX-VR)
After=network.target
[Service]
Type=simple
ExecStart=/opt/velociraptor/velociraptor --config /opt/velociraptor/server.config.yaml frontend -v
Restart=on-failure
RestartSec=3
User=root
NoNewPrivileges=yes
[Install]
WantedBy=multi-user.target
U
sudo tee /etc/systemd/system/velociraptor-client.service >/dev/null <<'U'
[Unit]
Description=Velociraptor client (LNX-VR, fixed REMnux endpoint)
After=network.target
[Service]
Type=simple
ExecStart=/opt/velociraptor/velociraptor --config /opt/velociraptor/client.config.yaml client -v
Restart=on-failure
RestartSec=5
User=root
NoNewPrivileges=yes
[Install]
WantedBy=multi-user.target
U
sudo systemctl daemon-reload
sudo systemctl enable --now velociraptor-server.service
sleep 5
sudo systemctl enable --now velociraptor-client.service

# 4. Linux domain module + acceptance runner (from this repo)
sudo mkdir -p /opt/velociraptor-linux-domain
sudo install -m 0644 "$(dirname "$0")/../../velociraptor_linux_domain.py" \
  /opt/velociraptor-linux-domain/
sudo install -m 0755 "$(dirname "$0")/../../tests/linux_domain_runner.py" \
  /opt/velociraptor-linux-domain/

echo "verify:"
sleep 10
systemctl is-active velociraptor-server.service velociraptor-client.service
sudo /opt/velociraptor/velociraptor --api_config /opt/velociraptor/api-access/api_client.yaml query \
  'SELECT client_id, os_info.system AS os FROM clients()' --format json | head -5
