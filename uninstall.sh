#!/bin/bash
# uninstall.sh - Debian systemd uninstaller

echo "[1/3] Stopping and disabling service..."
sudo systemctl stop insys-tlm
sudo systemctl disable insys-tlm
sudo rm /etc/systemd/system/insys-tlm.service
sudo systemctl daemon-reload

echo "[2/3] Closing Firewall Port..."
sudo ufw delete allow 9090/tcp

echo "[3/3] Removing installation directory..."
sudo rm -rf /opt/insys-tlm

echo "Uninstallation Complete."