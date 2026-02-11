#!/bin/bash
# ============================================================
#  MTProxy — автоматическая установка для Ubuntu 22/24
#  https://github.com/TelegramMessenger/MTProxy
# ============================================================
set -euo pipefail

# ─── Цвета ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Параметры ──────────────────────────────────────────────
PROXY_PORT=0
STATS_PORT=2398           # Локальный порт статистики
WORKERS=1                 # Количество воркеров
INSTALL_DIR="/opt/MTProxy" # Директория установки
PROXY_TAG=""

# ─── Функции ────────────────────────────────────────────────
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }
generate_port() {
    local port
    while true; do
        port=$(shuf -i 20000-60999 -n 1)
        if ! ss -lnt | awk '{print $4}' | grep -qE ":${port}$"; then
            echo "$port"
            return
        fi
    done
}

# ─── Аргументы ──────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag|-P)
            PROXY_TAG="${2:-}"
            [[ -n "$PROXY_TAG" ]] || fail "Не указан тег после $1"
            shift 2
            ;;
        *)
            fail "Неизвестный аргумент: $1"
            ;;
    esac
done

# ─── Проверка root ──────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    fail "Запустите скрипт от root:  sudo bash $0"
fi

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║     MTProxy — установка и настройка      ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════╝${NC}"
echo ""

# ─── 1. Зависимости ────────────────────────────────────────
info "Устанавливаю зависимости..."
apt-get update -qq
apt-get install -y -qq git curl build-essential libssl-dev zlib1g-dev xxd iproute2 coreutils > /dev/null 2>&1
ok "Зависимости установлены"

# ─── Переиспользуем настройки при повторном запуске ─────────
SERVICE_FILE="/etc/systemd/system/MTProxy.service"
if [[ -f "$SERVICE_FILE" ]]; then
    EXISTING_PORT=$(awk '/-H/ {for(i=1;i<=NF;i++) if($i=="-H") {print $(i+1); exit}}' "$SERVICE_FILE")
    EXISTING_SECRET=$(awk '/-S/ {for(i=1;i<=NF;i++) if($i=="-S") {print $(i+1); exit}}' "$SERVICE_FILE")
    if [[ -n "$EXISTING_PORT" && -n "$EXISTING_SECRET" ]]; then
        PROXY_PORT="$EXISTING_PORT"
        SECRET="$EXISTING_SECRET"
        ok "Переиспользую порт и секрет из текущего сервиса"
    fi
fi

if [[ -z "${PROXY_PORT:-}" || "$PROXY_PORT" == "0" ]]; then
    PROXY_PORT=$(generate_port)
    ok "Выбран случайный порт: $PROXY_PORT"
fi

# ─── 2. Сборка MTProxy ─────────────────────────────────────
if [[ -d "$INSTALL_DIR" ]]; then
    warn "Директория $INSTALL_DIR уже существует — обновляю..."
    cd "$INSTALL_DIR"
    git pull --quiet
    make clean > /dev/null 2>&1 || true
else
    info "Клонирую MTProxy..."
    git clone --quiet https://github.com/TelegramMessenger/MTProxy "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

info "Собираю MTProxy (это займёт ~1 мин)..."
make -j"$(nproc)" > /dev/null 2>&1
ok "MTProxy собран"

# ─── 3. Конфигурация Telegram ──────────────────────────────
info "Загружаю конфигурацию Telegram..."
curl -s https://core.telegram.org/getProxySecret -o "$INSTALL_DIR/proxy-secret"
curl -s https://core.telegram.org/getProxyConfig -o "$INSTALL_DIR/proxy-multi.conf"
ok "Конфигурация загружена"

# ─── 4. Генерация секрета ──────────────────────────────────
if [[ -z "${SECRET:-}" ]]; then
    SECRET=$(head -c 16 /dev/urandom | xxd -ps)
    ok "Секрет сгенерирован"
else
    ok "Секрет сохранён из предыдущей установки"
fi

# ─── 5. Systemd сервис ─────────────────────────────────────
info "Создаю systemd-сервис..."
cat > /etc/systemd/system/MTProxy.service <<EOF
[Unit]
Description=MTProxy Telegram Proxy
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/objs/bin/mtproto-proxy \\
    -u nobody \\
    -p $STATS_PORT \\
    -H $PROXY_PORT \\
    -S $SECRET \\
    ${PROXY_TAG:+-P $PROXY_TAG} \\
    --aes-pwd $INSTALL_DIR/proxy-secret \\
    $INSTALL_DIR/proxy-multi.conf \\
    -M $WORKERS
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable MTProxy.service > /dev/null 2>&1
systemctl restart MTProxy.service
ok "Сервис MTProxy запущен и добавлен в автозагрузку"

# ─── 6. Cron: обновление конфига каждый день в 04:00 ───────
CRON_CMD="curl -s https://core.telegram.org/getProxyConfig -o $INSTALL_DIR/proxy-multi.conf && systemctl restart MTProxy.service"
CRON_LINE="0 4 * * * $CRON_CMD"

# Добавляем если ещё нет
(crontab -l 2>/dev/null | grep -v "getProxyConfig" ; echo "$CRON_LINE") | crontab -
ok "Cron настроен: конфиг обновляется ежедневно в 04:00"

# ─── 7. Firewall (UFW) ─────────────────────────────────────
if command -v ufw &> /dev/null; then
    if ufw status | grep -qi inactive; then
        warn "UFW не активен — правило добавлено, но фаервол выключен"
    fi
    ufw allow "$PROXY_PORT"/tcp > /dev/null 2>&1
    ok "UFW: порт $PROXY_PORT/tcp открыт"
elif command -v firewall-cmd &> /dev/null; then
    if ! firewall-cmd --state >/dev/null 2>&1; then
        warn "firewalld не активен — правило добавлено, но фаервол выключен"
    fi
    firewall-cmd --permanent --add-port="$PROXY_PORT"/tcp > /dev/null 2>&1 || true
    firewall-cmd --reload > /dev/null 2>&1 || true
    ok "firewalld: порт $PROXY_PORT/tcp открыт"
elif command -v iptables &> /dev/null; then
    if ! iptables -C INPUT -p tcp --dport "$PROXY_PORT" -j ACCEPT 2>/dev/null; then
        iptables -I INPUT -p tcp --dport "$PROXY_PORT" -j ACCEPT > /dev/null 2>&1 || true
    fi
    ok "iptables: порт $PROXY_PORT/tcp открыт"
else
    warn "Фаервол не найден — откройте порт $PROXY_PORT/tcp вручную в вашем файрволе"
fi

# ─── 8. Определяем IP сервера ──────────────────────────────
SERVER_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")

# ─── Результат ──────────────────────────────────────────────
DD_SECRET="dd${SECRET}"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  ${GREEN}✅  MTProxy успешно установлен!${NC}${BOLD}                                        ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║${NC}                                                                          ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}  ${CYAN}Сервер:${NC}  $SERVER_IP"
echo -e "${BOLD}║${NC}  ${CYAN}Порт:${NC}    $PROXY_PORT"
echo -e "${BOLD}║${NC}  ${CYAN}Секрет:${NC}  $DD_SECRET"
echo -e "${BOLD}║${NC}                                                                          ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}  ${YELLOW}Ссылка для подключения:${NC}"
echo -e "${BOLD}║${NC}  tg://proxy?server=${SERVER_IP}&port=${PROXY_PORT}&secret=${DD_SECRET}"
echo -e "${BOLD}║${NC}                                                                          ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}  ${YELLOW}Или через браузер:${NC}"
echo -e "${BOLD}║${NC}  https://t.me/proxy?server=${SERVER_IP}&port=${PROXY_PORT}&secret=${DD_SECRET}"
echo -e "${BOLD}║${NC}                                                                          ${BOLD}║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║${NC}  ${CYAN}Полезные команды:${NC}                                                       ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}    systemctl status MTProxy    — статус сервиса                          ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}    systemctl restart MTProxy   — перезапуск                              ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}    systemctl stop MTProxy      — остановка                               ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}    curl localhost:$STATS_PORT/stats   — статистика                            ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}                                                                          ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}  ${CYAN}Зарегистрируйте прокси:${NC}  https://t.me/MTProxybot                       ${BOLD}║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
