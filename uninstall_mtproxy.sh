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
# Порт берём из env (wrapper скрывает -H из unit), fallback — разбор unit
if [[ -f "$CONFIG_DIR/env" ]]; then
  # shellcheck disable=SC1091
  source "$CONFIG_DIR/env" 2>/dev/null || true
  PORT="${PROXY_PORT:-}"
fi
if [[ -z "$PORT" && -f "$SERVICE_FILE" ]]; then
  PORT=$(awk '/-H/ {for(i=1;i<=NF;i++) if($i=="-H") {print $(i+1); exit}}' "$SERVICE_FILE" || true)
fi
if [[ -f "$SERVICE_FILE" ]]; then
  systemctl stop MTProxy.service >/dev/null 2>&1 || true
  systemctl disable MTProxy.service >/dev/null 2>&1 || true
  rm -f "$SERVICE_FILE"
  echo "[OK] Сервис остановлен и удалён"
fi

# --- Удаление watchdog (timer + service) ---
systemctl stop mtproxy-watchdog.timer >/dev/null 2>&1 || true
systemctl disable mtproxy-watchdog.timer >/dev/null 2>&1 || true
rm -f /etc/systemd/system/mtproxy-watchdog.timer
rm -f /etc/systemd/system/mtproxy-watchdog.service
systemctl daemon-reload >/dev/null 2>&1 || true
echo "[OK] Watchdog удалён"

# --- Удаление утилиты управления пользователями ---
rm -f /usr/local/bin/mtproxy-user.sh

# --- Удаление задания планировщика ---
if crontab -l >/dev/null 2>&1; then
  (crontab -l 2>/dev/null | grep -v "update_config\|getProxyConfig\|update_binary") | crontab - 2>/dev/null || true
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

  # Удаление правил rate-limiting (точный --dport, не трогаем чужие ACCEPT)
  if command -v iptables >/dev/null 2>&1; then
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
# Удаляем sysctl drop-in без глобального sysctl --system (не трогаем чужие настройки)
rm -f /etc/sysctl.d/90-mtproxy.conf
rm -f /etc/systemd/journald.conf.d/90-mtproxy.conf
rm -f /run/mtproxy-watchdog.fails /run/mtproxy-update.lock /run/mtproxy-watchdog.lock
rm -f /tmp/mtproxy-build.log
systemctl restart systemd-journald >/dev/null 2>&1 || true
echo "[OK] Файлы, sysctl и journald drop-in удалены"

echo ""
echo "MTProxy полностью деинсталлирован."
