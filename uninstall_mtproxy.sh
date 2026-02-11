#!/bin/bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Запустите скрипт от root: sudo bash $0"
  exit 1
fi

SERVICE_FILE="/etc/systemd/system/MTProxy.service"
INSTALL_DIR="/opt/MTProxy"
PORT=""

if [[ -f "$SERVICE_FILE" ]]; then
  PORT=$(awk '/-H/ {for(i=1;i<=NF;i++) if($i=="-H") {print $(i+1); exit}}' "$SERVICE_FILE" || true)
  systemctl stop MTProxy.service >/dev/null 2>&1 || true
  systemctl disable MTProxy.service >/dev/null 2>&1 || true
  rm -f "$SERVICE_FILE"
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

if crontab -l >/dev/null 2>&1; then
  (crontab -l 2>/dev/null | grep -v "getProxyConfig") | crontab -
fi

if [[ -n "$PORT" ]]; then
  if command -v ufw >/dev/null 2>&1; then
    ufw delete allow "${PORT}/tcp" >/dev/null 2>&1 || true
  elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --remove-port="${PORT}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  elif command -v iptables >/dev/null 2>&1; then
    iptables -D INPUT -p tcp --dport "$PORT" -j ACCEPT >/dev/null 2>&1 || true
  fi
fi

rm -rf "$INSTALL_DIR"

echo "MTProxy полностью удалён"
