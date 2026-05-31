#!/bin/bash
# Auto-generated remediation script
# Generated: Sun May 31 02:22:45 PM WAT 2026
# WARNING: Review before executing. Ensure console/VM access before running.

sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.1780233765


# --- Firewall Remediation ---
sudo apt-get update -qq
sudo apt-get install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh # CRITICAL: ensure console access first
sudo ufw --force enable
sudo sed -i 's/^#*\s*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#*\s*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config || printf '%s\n' 'MaxAuthTries 4' | sudo tee -a /etc/ssh/sshd_config >/dev/null
sudo sed -i 's/^#*\s*ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config || printf '%s\n' 'ClientAliveInterval 300' | sudo tee -a /etc/ssh/sshd_config >/dev/null
sudo sed -i 's/^#*\s*ClientAliveCountMax.*/ClientAliveCountMax 3/' /etc/ssh/sshd_config || printf '%s\n' 'ClientAliveCountMax 3' | sudo tee -a /etc/ssh/sshd_config >/dev/null
printf '%s\n' 'Authorized use only. All activity is monitored.' | sudo tee /etc/ssh/banner >/dev/null
sudo sed -i 's/^#*\s*Banner.*/Banner \/etc\/ssh\/banner/' /etc/ssh/sshd_config || printf '%s\n' 'Banner /etc/ssh/banner' | sudo tee -a /etc/ssh/sshd_config >/dev/null

# Restart SSH service to apply changes
sudo systemctl restart sshd 2>/dev/null || sudo service ssh restart
