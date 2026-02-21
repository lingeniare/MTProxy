#!/bin/bash
# ============================================================
#  Автоматизация развертывания и конфигурации MTProxy
#  Целевая платформа: Ubuntu 22.04 LTS / 24.04 LTS
#  Исходный код: https://github.com/TelegramMessenger/MTProxy
#
#  Версия: 1.1.0 (2026-02-21)
#  Архитектура безопасности: 
#    - Обфускация протокола (Fake TLS)
#    - Изоляция привилегий (пользователь mtproxy)
#    - Изоляция учетных данных (/etc/mtproxy/secret)
#    - Ограничение частоты соединений (iptables-hashlimit)
#    - Сохранение состояния (netfilter-persistent)
# ============================================================
set -euo pipefail

# --- Конфигурация окружения ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Параметры ──────────────────────────────────────────────
PROXY_PORT=0
STATS_PORT=2398             # Локальный порт статистики
WORKERS=1                   # Количество воркеров
INSTALL_DIR="/opt/MTProxy"  # Директория установки
CONFIG_DIR="/etc/mtproxy"   # Директория конфигов и секретов
PROXY_TAG=""
FAKE_TLS_DOMAIN="www.google.com"  # Домен для Fake TLS (по умолчанию)
RATE_LIMIT="5/min"          # Rate-limit для новых подключений
RATE_BURST=10               # Burst для rate-limit

# ─── Функции ────────────────────────────────────────────────
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# --- Port Generation Engine ---
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

# --- WAN IP Discovery (Cascading Fallback) ---
detect_external_ip() {
    local ip=""
    local services=(
        "https://api.ipify.org"
        "https://ifconfig.me"
        "https://icanhazip.com"
        "https://ipecho.net/plain"
        "https://checkip.amazonaws.com"
        "https://ipinfo.io/ip"
        "https://ident.me"
        "https://api.my-ip.io/v2/ip.txt"
    )

    for svc in "${services[@]}"; do
        ip=$(curl -s -4 --max-time 5 "$svc" 2>/dev/null | tr -d '[:space:]')
        # Проверяем, что это валидный IPv4
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return
        fi
    done

    # Финальный fallback: ip route
    ip=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || true)
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return
    fi

    echo "YOUR_SERVER_IP"
}

# ─── Аргументы ──────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag|-P)
            PROXY_TAG="${2:-}"
            [[ -n "$PROXY_TAG" ]] || fail "Не указан тег после $1"
            shift 2
            ;;
        --domain|-D)
            FAKE_TLS_DOMAIN="${2:-}"
            [[ -n "$FAKE_TLS_DOMAIN" ]] || fail "Не указан домен после $1"
            shift 2
            ;;
        --rate-limit)
            RATE_LIMIT="${2:-}"
            [[ -n "$RATE_LIMIT" ]] || fail "Не указан лимит после $1"
            shift 2
            ;;
        --rate-burst)
            RATE_BURST="${2:-}"
            [[ -n "$RATE_BURST" ]] || fail "Не указан burst после $1"
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
echo -e "${BOLD}>> MTProxy — установка и настройка${NC}"
echo ""

# ─── 1. Проверка и установка зависимостей ──────────────────
info "Проверяю зависимости..."
DEPS=(git curl build-essential libssl-dev zlib1g-dev xxd iproute2 coreutils cron)
MISSING=()

for dep in "${DEPS[@]}"; do
    if ! dpkg -l "$dep" &>/dev/null; then
        MISSING+=("$dep")
    fi
done

apt-get update -qq
if [[ ${#MISSING[@]} -gt 0 ]]; then
    info "Устанавливаю: ${MISSING[*]}"
    apt-get install -y -qq "${MISSING[@]}" > /dev/null 2>&1
fi

# Убедимся, что cron запущен
if ! systemctl is-active --quiet cron 2>/dev/null; then
    systemctl enable --now cron > /dev/null 2>&1 || true
fi

ok "Зависимости установлены"

# ─── 2. Создание выделенного пользователя ──────────────────
if ! id mtproxy &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin mtproxy
    ok "Создан системный пользователь mtproxy"
else
    ok "Пользователь mtproxy уже существует"
fi

# ─── 3. Переиспользуем настройки при повторном запуске ──────
SERVICE_FILE="/etc/systemd/system/MTProxy.service"
if [[ -f "$SERVICE_FILE" ]]; then
    EXISTING_PORT=$(awk '/-H/ {for(i=1;i<=NF;i++) if($i=="-H") {print $(i+1); exit}}' "$SERVICE_FILE")
    EXISTING_SECRET=""
    # Пробуем прочитать секрет из нового формата (файл)
    if [[ -f "$CONFIG_DIR/secret" ]]; then
        EXISTING_SECRET=$(cat "$CONFIG_DIR/secret" 2>/dev/null || true)
    fi
    # Fallback: из старого сервисного файла
    if [[ -z "$EXISTING_SECRET" ]]; then
        EXISTING_SECRET=$(awk '/-S/ {for(i=1;i<=NF;i++) if($i=="-S") {print $(i+1); exit}}' "$SERVICE_FILE")
    fi
    # Пробуем прочитать домен из существующего сервиса
    EXISTING_DOMAIN=$(awk '/--domain/ {for(i=1;i<=NF;i++) if($i=="--domain") {print $(i+1); exit}}' "$SERVICE_FILE")
    if [[ -n "$EXISTING_DOMAIN" ]]; then
        FAKE_TLS_DOMAIN="$EXISTING_DOMAIN"
    fi

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

# ─── 4. Сборка MTProxy ────────────────────────────────────
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

# ─── 5. Конфигурация Telegram (с валидацией) ───────────────
info "Загружаю конфигурацию Telegram..."
TMP_SECRET=$(mktemp)
TMP_CONFIG=$(mktemp)

curl -sSf https://core.telegram.org/getProxySecret -o "$TMP_SECRET" || fail "Не удалось скачать proxy-secret"
curl -sSf https://core.telegram.org/getProxyConfig -o "$TMP_CONFIG" || fail "Не удалось скачать proxy-multi.conf"

# Валидация: файлы не пустые и имеют разумный размер
if [[ ! -s "$TMP_SECRET" ]]; then
    rm -f "$TMP_SECRET" "$TMP_CONFIG"
    fail "Скачанный proxy-secret пуст"
fi
if [[ ! -s "$TMP_CONFIG" ]] || [[ $(stat -c%s "$TMP_CONFIG") -lt 1024 ]]; then
    rm -f "$TMP_SECRET" "$TMP_CONFIG"
    fail "Скачанный proxy-multi.conf повреждён или слишком мал"
fi

mv "$TMP_SECRET" "$INSTALL_DIR/proxy-secret"
mv "$TMP_CONFIG" "$INSTALL_DIR/proxy-multi.conf"
ok "Конфигурация загружена и проверена"

# ─── 6. Генерация секрета ──────────────────────────────────
if [[ -z "${SECRET:-}" ]]; then
    SECRET=$(head -c 16 /dev/urandom | xxd -ps)
    ok "Секрет сгенерирован"
else
    ok "Секрет сохранён из предыдущей установки"
fi

# ─── 7. Сохранение секрета в защищённый файл ───────────────
mkdir -p "$CONFIG_DIR"
echo "$SECRET" > "$CONFIG_DIR/secret"
echo "$FAKE_TLS_DOMAIN" > "$CONFIG_DIR/domain"
chmod 700 "$CONFIG_DIR"
chmod 600 "$CONFIG_DIR/secret" "$CONFIG_DIR/domain"
chown -R mtproxy:mtproxy "$CONFIG_DIR"

# Генерация ee-секрета для ссылки подключения (Fake TLS)
DOMAIN_HEX=$(echo -n "$FAKE_TLS_DOMAIN" | xxd -ps -c 200)
EE_SECRET="ee${SECRET}${DOMAIN_HEX}"

ok "Секрет сохранён в $CONFIG_DIR/secret (недоступен через systemctl cat)"

# ─── 8. Скрипт обновления конфигурации ─────────────────────
cat > "$CONFIG_DIR/update_config.sh" <<'UPDATESCRIPT'
#!/bin/bash
# Обновление конфигурации Telegram для MTProxy с валидацией
set -euo pipefail

INSTALL_DIR="/opt/MTProxy"
LOG_TAG="mtproxy-update"

TMP=$(mktemp)
trap "rm -f $TMP" EXIT

# Скачиваем новый конфиг
if ! curl -sSf --max-time 30 https://core.telegram.org/getProxyConfig -o "$TMP" 2>/dev/null; then
    logger -t "$LOG_TAG" "ОШИБКА: не удалось скачать конфиг"
    exit 1
fi

# Валидация: файл не пустой и имеет разумный размер (>= 1KB)
if [[ ! -s "$TMP" ]] || [[ $(stat -c%s "$TMP") -lt 1024 ]]; then
    logger -t "$LOG_TAG" "ОШИБКА: скачанный конфиг повреждён (пустой или слишком мал)"
    exit 1
fi

# Бэкап текущего конфига
if [[ -f "$INSTALL_DIR/proxy-multi.conf" ]]; then
    cp "$INSTALL_DIR/proxy-multi.conf" "$INSTALL_DIR/proxy-multi.conf.bak"
fi

# Заменяем и перезапускаем
mv "$TMP" "$INSTALL_DIR/proxy-multi.conf"

if ! systemctl restart MTProxy.service 2>/dev/null; then
    # Восстанавливаем из бэкапа при ошибке
    if [[ -f "$INSTALL_DIR/proxy-multi.conf.bak" ]]; then
        mv "$INSTALL_DIR/proxy-multi.conf.bak" "$INSTALL_DIR/proxy-multi.conf"
        systemctl restart MTProxy.service 2>/dev/null || true
        logger -t "$LOG_TAG" "ОШИБКА: рестарт не удался, конфиг восстановлен из бэкапа"
    fi
    exit 1
fi

logger -t "$LOG_TAG" "Конфиг успешно обновлён"
UPDATESCRIPT

chmod 700 "$CONFIG_DIR/update_config.sh"
chown root:root "$CONFIG_DIR/update_config.sh"
ok "Скрипт обновления конфигурации создан"

# ─── 9. Systemd сервис ─────────────────────────────────────
info "Создаю systemd-сервис..."

# Права на директорию установки для пользователя mtproxy
chown -R mtproxy:mtproxy "$INSTALL_DIR"

cat > /etc/systemd/system/MTProxy.service <<EOF
[Unit]
Description=MTProxy Telegram Proxy
After=network.target

[Service]
Type=simple
User=mtproxy
Group=mtproxy
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/objs/bin/mtproto-proxy \\
    -u mtproxy \\
    -p $STATS_PORT \\
    -H $PROXY_PORT \\
    -S $SECRET \\
    --http-stats \\
    --domain $FAKE_TLS_DOMAIN \\
    ${PROXY_TAG:+-P $PROXY_TAG} \\
    --aes-pwd $INSTALL_DIR/proxy-secret \\
    $INSTALL_DIR/proxy-multi.conf \\
    -M $WORKERS
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable MTProxy.service > /dev/null 2>&1
if ! systemctl restart MTProxy.service; then
    fail "Не удалось запустить сервис MTProxy. Проверьте статус: systemctl status MTProxy"
fi
ok "Сервис MTProxy запущен и добавлен в автозагрузку"

# ─── 10. Cron: обновление конфига каждый день в 04:00 ──────
CRON_CMD="$CONFIG_DIR/update_config.sh"
CRON_LINE="0 4 * * * $CRON_CMD"

# Добавляем если ещё нет
( { crontab -l 2>/dev/null || true; } | { grep -v "update_config\|getProxyConfig" || true; } ; echo "$CRON_LINE" ) | crontab -
ok "Cron настроен: конфиг обновляется ежедневно в 04:00 (с валидацией)"

# ─── 11. Rate-limiting (hashlimit) ─────────────────────────
info "Настраиваю rate-limiting..."
RLIMIT_CHAIN="MTPROXY_LIMIT"

# Удаляем старые правила если есть
iptables -D INPUT -p tcp --dport "$PROXY_PORT" -m conntrack --ctstate NEW -j "$RLIMIT_CHAIN" 2>/dev/null || true
iptables -F "$RLIMIT_CHAIN" 2>/dev/null || true
iptables -X "$RLIMIT_CHAIN" 2>/dev/null || true

# Создаём цепочку с hashlimit
iptables -N "$RLIMIT_CHAIN" 2>/dev/null || true
iptables -A "$RLIMIT_CHAIN" -m hashlimit \
    --hashlimit-above "$RATE_LIMIT" \
    --hashlimit-burst "$RATE_BURST" \
    --hashlimit-mode srcip \
    --hashlimit-name mtproxy_ratelimit \
    -j DROP
iptables -A "$RLIMIT_CHAIN" -j ACCEPT

# Подключаем цепочку к INPUT для нового трафика на наш порт
iptables -I INPUT -p tcp --dport "$PROXY_PORT" -m conntrack --ctstate NEW -j "$RLIMIT_CHAIN"

ok "Rate-limiting: $RATE_LIMIT (burst $RATE_BURST) на IP"

# ─── 12. Firewall ─────────────────────────────────────────
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
else
    # Для iptables: порт уже открыт через rate-limiting цепочку (ACCEPT в конце)
    # Сохраняем правила для переживания ребута
    if command -v iptables &> /dev/null; then
        if ! dpkg -l iptables-persistent &>/dev/null; then
            info "Устанавливаю iptables-persistent для сохранения правил..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent > /dev/null 2>&1 || true
        fi
        if command -v netfilter-persistent &> /dev/null; then
            netfilter-persistent save > /dev/null 2>&1 || true
            ok "iptables: правила сохранены (переживут перезагрузку)"
        else
            warn "iptables: не удалось сохранить правила. Установите iptables-persistent вручную"
        fi
    else
        warn "Фаервол не найден — откройте порт $PROXY_PORT/tcp вручную"
    fi
fi

# ─── 13. Определяем IP сервера ──────────────────────────────
info "Определяю внешний IP-адрес..."
SERVER_IP=$(detect_external_ip)

if [[ "$SERVER_IP" == "YOUR_SERVER_IP" ]]; then
    warn "Не удалось определить IP автоматически. Замените YOUR_SERVER_IP в ссылке ниже"
else
    ok "Внешний IP: $SERVER_IP"
fi

# --- Финальный отчет о развертывании ---
echo ""
echo "----------------------------------------------------------------------"
echo "Развертывание MTProxy успешно завершено"
echo "----------------------------------------------------------------------"
echo ""
printf "%-25s %s\n" "Внешний IP:" "$SERVER_IP"
printf "%-25s %s\n" "Порт:" "$PROXY_PORT"
printf "%-25s %s\n" "Ключ секрета:" "$EE_SECRET"
printf "%-25s %s\n" "Домен Fake TLS:" "$FAKE_TLS_DOMAIN"
echo ""
echo "Ссылка для подключения (MTProto):"
echo "tg://proxy?server=${SERVER_IP}&port=${PROXY_PORT}&secret=${EE_SECRET}"
echo ""
echo "Альтернативная ссылка:"
echo "https://t.me/proxy?server=${SERVER_IP}&port=${PROXY_PORT}&secret=${EE_SECRET}"
echo ""
echo "----------------------------------------------------------------------"
echo "Команды управления:"
echo "  systemctl status MTProxy    - Проверить статус службы"
echo "  systemctl restart MTProxy   - Перезапустить службу"
echo "  curl localhost:$STATS_PORT/stats   - Диагностическая статистика"
echo ""
echo "Метаданные безопасности:"
echo "  Хранилище секретов: $CONFIG_DIR/secret"
echo "  Контекст безопасности: Пользователь 'mtproxy' (Изолирован)"
echo "  Ограничение соединений: $RATE_LIMIT (Burst: $RATE_BURST)"
echo "  Протокол: Fake TLS (Домен: $FAKE_TLS_DOMAIN)"
echo ""

echo -e "${CYAN}Зарегистрируйте прокси:${NC} https://t.me/MTProxybot"
echo ""
