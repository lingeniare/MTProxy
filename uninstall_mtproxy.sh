#!/bin/bash
# ============================================================
#  Деинсталляция MTProxy — полное удаление всех компонентов
# ============================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Запустите скрипт от root: sudo bash $0"
  exit 1
fi

SERVICE_FILE="/etc/systemd/system/MTProxy.service"
INSTALL_DIR="/opt/MTProxy"
CONFIG_DIR="/etc/mtproxy"
PORT=""

# --- Остановка и удаление сервиса ---
if [[ -f "$SERVICE_FILE" ]]; then
  PORT=$(awk '/-H/ {for(i=1;i<=NF;i++) if($i=="-H") {print $(i+1); exit}}' "$SERVICE_FILE" || true)
  systemctl stop MTProxy.service >/dev/null 2>&1 || true
  systemctl disable MTProxy.service >/dev/null 2>&1 || true
  rm -f "$SERVICE_FILE"
  systemctl daemon-reload >/dev/null 2>&1 || true
  echo "[OK] Сервис остановлен и удалён"
fi

# --- Удаление задания планировщика ---
if crontab -l >/dev/null 2>&1; then
  (crontab -l 2>/dev/null | grep -v "update_config\|getProxyConfig") | crontab - 2>/dev/null || true
  echo "[OK] Задание планировщика удалено"
fi

# --- Удаление правил межсетевого экрана ---
if [[ -n "$PORT" ]]; then
  if command -v ufw >/dev/null 2>&1; then
    ufw delete allow "${PORT}/tcp" >/dev/null 2>&1 || true
  elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --remove-port="${PORT}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi

  # Удаление правил rate-limiting
  if command -v iptables >/dev/null 2>&1; then
    iptables -D INPUT -p tcp --dport "$PORT" -j ACCEPT >/dev/null 2>&1 || true
    iptables -D INPUT -p tcp --dport "$PORT" -m conntrack --ctstate NEW -j MTPROXY_LIMIT >/dev/null 2>&1 || true
    iptables -F MTPROXY_LIMIT >/dev/null 2>&1 || true
    iptables -X MTPROXY_LIMIT >/dev/null 2>&1 || true
    if command -v netfilter-persistent >/dev/null 2>&1; then
      netfilter-persistent save >/dev/null 2>&1 || true
    fi
  fi
  echo "[OK] Правила межсетевого экрана удалены"
fi

# --- Удаление системного пользователя ---
if id mtproxy &>/dev/null; then
  userdel mtproxy 2>/dev/null || true
  echo "[OK] Пользователь mtproxy удалён"
fi

# --- Удаление файлов и конфигураций ---
rm -rf "$INSTALL_DIR"
rm -rf "$CONFIG_DIR"

echo ""
echo "MTProxy полностью деинсталлирован."
