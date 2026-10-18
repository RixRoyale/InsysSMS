#!/bin/bash
# install.sh - Debian systemd installer

echo "[1/4] Creating installation directory in /opt/insys-tlm..."
sudo mkdir -p /opt/insys-tlm
sudo cp -r public /opt/insys-tlm/
sudo cp insys-tlm-service /opt/insys-tlm/
sudo chmod +x /opt/insys-tlm/insys-tlm-service

echo "[2/4] Creating systemd service file..."
sudo bash -c 'cat > /etc/systemd/system/insys-tlm.service <<EOF
[Unit]
Description=INSYS Telematics Management System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/insys-tlm
ExecStart=/opt/insys-tlm/insys-tlm-service
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF'

echo "[3/4] Opening UFW Firewall Port 9090..."
sudo ufw allow 9090/tcp

echo "[4/4] Starting and enabling the service..."
sudo systemctl daemon-reload
sudo systemctl enable insys-tlm
sudo systemctl start insys-tlm

echo "======================================================="
echo " INSYS TLM System Installed Successfully on Debian!"
echo " Installed at: /opt/insys-tlm"
echo " Running at: http://YOUR_SERVER_IP:9090"
echo " To check status, run: sudo systemctl status insys-tlm"
echo "======================================================="