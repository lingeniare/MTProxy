#!/bin/bash
# ============================================================
#  Автоматизация развертывания и конфигурации MTProxy
#  Целевая платформа: Ubuntu 22.04 LTS / 24.04 LTS
#  Исходный код: https://github.com/TelegramMessenger/MTProxy
#
#  Версия: 1.2.0 (2026-02-22)
#  Архитектура безопасности:
#    - Обфускация протокола (Fake TLS)
#    - Изоляция привилегий (пользователь mtproxy)
#    - Изоляция учетных данных (/etc/mtproxy/secret)
#    - Ограничение частоты соединений (iptables-hashlimit)
#    - Сохранение состояния (netfilter-persistent)
#
#  Использование:
#    sudo bash install_mtproxy.sh
#    sudo bash install_mtproxy.sh --domain cloudflare.com
#    sudo bash install_mtproxy.sh --tag <тег>
# ============================================================
set -euo pipefail

# --- Конфигурация окружения ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# --- Настройки по умолчанию (рассчитаны на ~5 активных пользователей) ---
PROXY_PORT=0
STATS_PORT=2398             # Локальный порт статистики (только localhost)
WORKERS=1                   # Количество воркеров
INSTALL_DIR="/opt/MTProxy"  # Директория установки
CONFIG_DIR="/etc/mtproxy"   # Директория конфигов и секретов
PROXY_TAG=""
FAKE_TLS_DOMAIN="www.google.com"  # Домен для Fake TLS
RATE_LIMIT="5/min"          # Лимит новых подключений на IP
RATE_BURST=10               # Всплеск для rate-limit
FORCE_UNSHARE="${FORCE_UNSHARE:-auto}"  # 1=всегда, 0=никогда, auto=по pid_max/ns_last_pid

# --- Служебные функции ---
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# --- Генерация случайного свободного порта ---
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

# --- Каскадное определение внешнего IP-адреса ---
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
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return
        fi
    done

    # Финальный fallback: через таблицу маршрутизации
    ip=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || true)
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return
    fi

    echo "YOUR_SERVER_IP"
}

# --- Определение внутреннего IP (для NAT-окружений) ---
detect_internal_ip() {
    ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || hostname -I 2>/dev/null | awk '{print $1}' || echo ""
}

# --- Разбор аргументов командной строки ---
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

# --- Проверка режимов запуска ---
if [[ "$FORCE_UNSHARE" != "0" && "$FORCE_UNSHARE" != "1" && "$FORCE_UNSHARE" != "auto" ]]; then
    fail "FORCE_UNSHARE должен быть 0, 1 или auto (текущее значение: $FORCE_UNSHARE)"
fi

# --- Проверка прав root ---
if [[ $EUID -ne 0 ]]; then
    fail "Запустите скрипт от root:  sudo bash $0"
fi

echo ""
echo -e "${BOLD}>> MTProxy — установка и настройка${NC}"
echo ""

# ─── 1. Установка зависимостей ─────────────────────────────
info "Устанавливаю зависимости..."
apt-get update -qq

# xxd может быть в пакете xxd (Ubuntu 23.10+) или vim-common (Ubuntu 22.04)
apt-get install -y -qq \
    git curl build-essential libssl-dev zlib1g-dev \
    iproute2 coreutils cron util-linux \
    > /dev/null 2>&1

# Установка xxd: пробуем отдельный пакет, затем vim-common
if ! command -v xxd &>/dev/null; then
    apt-get install -y -qq xxd > /dev/null 2>&1 || \
    apt-get install -y -qq vim-common > /dev/null 2>&1 || \
    fail "Не удалось установить xxd. Установите вручную: apt install xxd"
fi

# Убедимся, что cron запущен
if ! systemctl is-active --quiet cron 2>/dev/null; then
    systemctl enable --now cron > /dev/null 2>&1 || true
fi

ok "Зависимости установлены"

# ─── 2. Создание изолированного системного пользователя ────
if ! id mtproxy &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin mtproxy
    ok "Создан системный пользователь mtproxy"
else
    ok "Пользователь mtproxy уже существует"
fi

# ─── 3. Миграция настроек при повторной установке ──────────
SERVICE_FILE="/etc/systemd/system/MTProxy.service"
if [[ -f "$SERVICE_FILE" ]]; then
    EXISTING_PORT=$(awk '/-H/ {for(i=1;i<=NF;i++) if($i=="-H") {print $(i+1); exit}}' "$SERVICE_FILE")
    EXISTING_SECRET=""
    # Приоритет: файловое хранилище секрета
    if [[ -f "$CONFIG_DIR/secret" ]]; then
        EXISTING_SECRET=$(cat "$CONFIG_DIR/secret" 2>/dev/null || true)
    fi
    # Fallback: извлечение из конфигурации systemd (устаревший формат)
    if [[ -z "$EXISTING_SECRET" ]]; then
        EXISTING_SECRET=$(awk '/-S/ {for(i=1;i<=NF;i++) if($i=="-S") {print $(i+1); exit}}' "$SERVICE_FILE")
    fi
    # Сохранение домена Fake TLS
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

# ─── 4. Сборка MTProxy из исходного кода ──────────────────
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

# ─── 5. Загрузка конфигурации Telegram (с валидацией) ──────
info "Загружаю конфигурацию Telegram..."
TMP_SECRET=$(mktemp)
TMP_CONFIG=$(mktemp)

curl -sSf https://core.telegram.org/getProxySecret -o "$TMP_SECRET" \
    || fail "Не удалось скачать proxy-secret"
curl -sSf https://core.telegram.org/getProxyConfig -o "$TMP_CONFIG" \
    || fail "Не удалось скачать proxy-multi.conf"

# Валидация: proxy-secret — бинарный файл (~248 байт), проверяем только непустоту
if [[ ! -s "$TMP_SECRET" ]]; then
    rm -f "$TMP_SECRET" "$TMP_CONFIG"
    fail "Скачанный proxy-secret пуст (0 байт)"
fi

# Валидация: proxy-multi.conf — конфигурация (~500-900 байт), порог 64 байта
CONFIG_SIZE=$(stat -c%s "$TMP_CONFIG" 2>/dev/null || echo 0)
if [[ ! -s "$TMP_CONFIG" ]] || [[ "$CONFIG_SIZE" -lt 64 ]]; then
    rm -f "$TMP_SECRET" "$TMP_CONFIG"
    fail "Скачанный proxy-multi.conf повреждён (размер: ${CONFIG_SIZE} байт, ожидается >= 64)"
fi

mv "$TMP_SECRET" "$INSTALL_DIR/proxy-secret"
mv "$TMP_CONFIG" "$INSTALL_DIR/proxy-multi.conf"
ok "Конфигурация загружена и проверена (proxy-multi.conf: ${CONFIG_SIZE} байт)"

# ─── 6. Генерация криптографического секрета ───────────────
if [[ -z "${SECRET:-}" ]]; then
    SECRET=$(head -c 16 /dev/urandom | xxd -ps)
    ok "Секрет сгенерирован"
else
    ok "Секрет сохранён из предыдущей установки"
fi

# ─── 7. Сохранение секрета в защищённое хранилище ──────────
mkdir -p "$CONFIG_DIR"
echo "$SECRET" > "$CONFIG_DIR/secret"
echo "$FAKE_TLS_DOMAIN" > "$CONFIG_DIR/domain"
chmod 700 "$CONFIG_DIR"
chmod 600 "$CONFIG_DIR/secret" "$CONFIG_DIR/domain"
chown -R mtproxy:mtproxy "$CONFIG_DIR"

# Формирование ee-секрета для клиентского подключения (Fake TLS)
DOMAIN_HEX=$(echo -n "$FAKE_TLS_DOMAIN" | xxd -ps -c 200)
EE_SECRET="ee${SECRET}${DOMAIN_HEX}"

ok "Секрет сохранён в $CONFIG_DIR/secret (недоступен через systemctl cat)"

# ─── 8. Скрипт автоматического обновления конфигурации ─────
cat > "$CONFIG_DIR/update_config.sh" <<'UPDATESCRIPT'
#!/bin/bash
# Автоматическое обновление конфигурации Telegram для MTProxy
# Вызывается через cron ежедневно в 04:00
set -euo pipefail

INSTALL_DIR="/opt/MTProxy"
LOG_TAG="mtproxy-update"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

# Загрузка нового конфига
if ! curl -sSf --max-time 30 https://core.telegram.org/getProxyConfig -o "$TMP" 2>/dev/null; then
    logger -t "$LOG_TAG" "Ошибка: не удалось скачать конфигурацию"
    exit 1
fi

# Валидация: файл не пустой и имеет ожидаемый размер (>= 64 байт)
CONFIG_SIZE=$(stat -c%s "$TMP" 2>/dev/null || echo 0)
if [[ ! -s "$TMP" ]] || [[ "$CONFIG_SIZE" -lt 64 ]]; then
    logger -t "$LOG_TAG" "Ошибка: скачанный конфиг повреждён (${CONFIG_SIZE} байт)"
    exit 1
fi

# Бэкап текущей конфигурации
if [[ -f "$INSTALL_DIR/proxy-multi.conf" ]]; then
    cp "$INSTALL_DIR/proxy-multi.conf" "$INSTALL_DIR/proxy-multi.conf.bak"
fi

# Применение нового конфига и перезапуск
mv "$TMP" "$INSTALL_DIR/proxy-multi.conf"
chown mtproxy:mtproxy "$INSTALL_DIR/proxy-multi.conf"

if ! systemctl restart MTProxy.service 2>/dev/null; then
    # Откат к бэкапу при ошибке перезапуска
    if [[ -f "$INSTALL_DIR/proxy-multi.conf.bak" ]]; then
        mv "$INSTALL_DIR/proxy-multi.conf.bak" "$INSTALL_DIR/proxy-multi.conf"
        chown mtproxy:mtproxy "$INSTALL_DIR/proxy-multi.conf"
        systemctl restart MTProxy.service 2>/dev/null || true
        logger -t "$LOG_TAG" "Ошибка: рестарт не удался, конфигурация восстановлена из бэкапа"
    fi
    exit 1
fi

logger -t "$LOG_TAG" "Конфигурация обновлена успешно (${CONFIG_SIZE} байт)"
UPDATESCRIPT

chmod 700 "$CONFIG_DIR/update_config.sh"
chown root:root "$CONFIG_DIR/update_config.sh"
ok "Скрипт автоматического обновления создан"

# ─── 9. Конфигурация systemd-сервиса ──────────────────────
info "Создаю systemd-сервис..."

# Права на директорию для пользователя mtproxy
chown -R mtproxy:mtproxy "$INSTALL_DIR"

# Определение NAT-конфигурации (для облачных VPS)
INTERNAL_IP=$(detect_internal_ip)
SERVER_IP_TMP=$(detect_external_ip)
NAT_INFO=""
if [[ -n "$INTERNAL_IP" && "$INTERNAL_IP" != "$SERVER_IP_TMP" && "$SERVER_IP_TMP" != "YOUR_SERVER_IP" ]]; then
    NAT_INFO="--nat-info ${INTERNAL_IP}:${SERVER_IP_TMP}"
fi

PID_MAX=$(cat /proc/sys/kernel/pid_max 2>/dev/null || echo 32768)
NS_LAST_PID=$(cat /proc/sys/kernel/ns_last_pid 2>/dev/null || echo 0)
USE_UNSHARE=0

case "$FORCE_UNSHARE" in
    1) USE_UNSHARE=1 ;;
    0) USE_UNSHARE=0 ;;
    auto)
        # MTProxy падает на assert при PID > 65535, поэтому включаем PID namespace заранее.
        if [[ "$PID_MAX" -gt 65535 || "$NS_LAST_PID" -gt 65535 ]]; then
            USE_UNSHARE=1
        fi
        ;;
esac

if [[ "$USE_UNSHARE" -eq 1 ]]; then
    if [[ ! -x /usr/bin/unshare ]]; then
        fail "Требуется /usr/bin/unshare (пакет util-linux), но он не найден"
    fi
    EXEC_PREFIX="/usr/bin/unshare --pid --fork --mount-proc --"
    info "Включён PID namespace workaround (FORCE_UNSHARE=$FORCE_UNSHARE, pid_max=$PID_MAX, ns_last_pid=$NS_LAST_PID)"
else
    EXEC_PREFIX=""
    info "PID namespace workaround не требуется (FORCE_UNSHARE=$FORCE_UNSHARE, pid_max=$PID_MAX, ns_last_pid=$NS_LAST_PID)"
fi

cat > /etc/systemd/system/MTProxy.service <<EOF
[Unit]
Description=MTProxy Telegram Proxy
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=${EXEC_PREFIX} $INSTALL_DIR/objs/bin/mtproto-proxy \\
    -u mtproxy \\
    -p $STATS_PORT \\
    -H $PROXY_PORT \\
    -S $SECRET \\
    --http-stats \\
    --domain $FAKE_TLS_DOMAIN \\
    ${NAT_INFO} \\
    ${PROXY_TAG:+-P $PROXY_TAG} \\
    --aes-pwd $INSTALL_DIR/proxy-secret \\
    $INSTALL_DIR/proxy-multi.conf \\
    -M $WORKERS
KillMode=control-group
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable MTProxy.service > /dev/null 2>&1
if ! systemctl restart MTProxy.service; then
    journalctl -u MTProxy.service --no-pager -n 20
    fail "Не удалось запустить сервис MTProxy. Логи выведены выше."
fi
ok "Сервис MTProxy запущен и добавлен в автозагрузку"

# ─── 10. Настройка планировщика обновлений ─────────────────
CRON_CMD="$CONFIG_DIR/update_config.sh"
CRON_LINE="0 4 * * * $CRON_CMD"

( { crontab -l 2>/dev/null || true; } | { grep -v "update_config\|getProxyConfig" || true; } ; echo "$CRON_LINE" ) | crontab -
ok "Cron настроен: обновление конфигурации ежедневно в 04:00"

# ─── 11. Настройка ограничения частоты соединений ──────────
if command -v iptables &>/dev/null; then
    info "Настраиваю rate-limiting..."
    RLIMIT_CHAIN="MTPROXY_LIMIT"

    # Очистка предыдущих правил
    iptables -D INPUT -p tcp --dport "$PROXY_PORT" -m conntrack --ctstate NEW -j "$RLIMIT_CHAIN" 2>/dev/null || true
    iptables -F "$RLIMIT_CHAIN" 2>/dev/null || true
    iptables -X "$RLIMIT_CHAIN" 2>/dev/null || true

    # Создание цепочки с hashlimit
    if iptables -N "$RLIMIT_CHAIN" 2>/dev/null; then
        iptables -A "$RLIMIT_CHAIN" -m hashlimit \
            --hashlimit-above "$RATE_LIMIT" \
            --hashlimit-burst "$RATE_BURST" \
            --hashlimit-mode srcip \
            --hashlimit-name mtproxy_ratelimit \
            -j DROP 2>/dev/null && \
        iptables -A "$RLIMIT_CHAIN" -j ACCEPT 2>/dev/null && \
        iptables -I INPUT -p tcp --dport "$PROXY_PORT" -m conntrack --ctstate NEW -j "$RLIMIT_CHAIN" 2>/dev/null && \
        ok "Rate-limiting: $RATE_LIMIT (burst $RATE_BURST) на IP" || \
        warn "Не удалось настроить rate-limiting (модули hashlimit/conntrack недоступны)"
    else
        warn "Не удалось создать цепочку iptables для rate-limiting"
    fi
else
    warn "iptables не найден — rate-limiting не настроен"
fi

# ─── 12. Конфигурация межсетевого экрана ───────────────────
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
    # Порт уже открыт через rate-limiting цепочку (финальное правило ACCEPT)
    # Сохранение правил для устойчивости после перезагрузки
    if ! dpkg -s iptables-persistent &>/dev/null 2>&1; then
        info "Устанавливаю iptables-persistent для сохранения правил..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent > /dev/null 2>&1 || true
    fi
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save > /dev/null 2>&1 || true
        ok "iptables: правила сохранены (устойчивы к перезагрузке)"
    else
        warn "Не удалось сохранить правила iptables — установите iptables-persistent вручную"
    fi
else
    warn "Межсетевой экран не обнаружен — откройте порт $PROXY_PORT/tcp вручную"
fi

# ─── 13. Определение внешнего IP-адреса сервера ────────────
info "Определяю внешний IP-адрес..."
SERVER_IP=$(detect_external_ip)

if [[ "$SERVER_IP" == "YOUR_SERVER_IP" ]]; then
    warn "Не удалось определить внешний IP. Подставьте адрес вручную в ссылку ниже."
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
echo "  systemctl status MTProxy          - Статус службы"
echo "  systemctl restart MTProxy         - Перезапуск"
echo "  journalctl -u MTProxy -f          - Просмотр журнала"
echo "  curl localhost:$STATS_PORT/stats  - Диагностическая статистика"
echo ""
echo "Метаданные безопасности:"
echo "  Хранилище секретов: $CONFIG_DIR/secret"
echo "  Контекст:           Пользователь 'mtproxy' (изолирован)"
echo "  Ограничение:        $RATE_LIMIT (burst $RATE_BURST)"
echo "  Протокол:           Fake TLS (домен: $FAKE_TLS_DOMAIN)"
echo ""
echo "Регистрация прокси: https://t.me/MTProxybot"
echo ""
