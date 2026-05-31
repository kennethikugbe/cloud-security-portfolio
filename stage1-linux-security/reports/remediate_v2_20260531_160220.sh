#!/bin/bash
# Auto-generated remediation script (v2)
# Generated: Sun May 31 04:02:21 PM WAT 2026
# Uses drop-in overrides instead of in-place file editing


# --- Firewall Remediation ---
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw --force enable

# --- SSH Hardening Remediation ---
# Writes drop-in overrides instead of editing main sshd_config
sudo mkdir -p /etc/ssh/sshd_config.d
{
  echo '# Auto-generated SSH hardening - Kenneth'
  echo 'PermitRootLogin no'
  echo 'PasswordAuthentication no'
  echo 'MaxAuthTries 4'
  echo 'ClientAliveInterval 300'
  echo 'ClientAliveCountMax 3'
  echo 'X11Forwarding no'
  echo 'HostbasedAuthentication no'
  echo 'PermitEmptyPasswords no'
  echo "Banner /etc/ssh/banner"
} | sudo tee /etc/ssh/sshd_config.d/99-hardening.conf >/dev/null

printf '%%s\n' 'Authorized use only. All activity is monitored.' | sudo tee /etc/ssh/banner >/dev/null

# Validate before restart
sudo sshd -t
sudo systemctl restart ssh
