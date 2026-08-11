#!/bin/bash
# ============================================================
#  Автоматизация развертывания и конфигурации MTProxy
#  Целевая платформа: Ubuntu 22.04 LTS / 24.04 LTS
#  Исходный код: https://github.com/TelegramMessenger/MTProxy
#
#  Версия: 1.3.0 (2026-08-11)
#  Архитектура безопасности:
#    - Обфускация протокола (Fake TLS с автовыбором правдоподобного домена)
#    - Изоляция привилегий (пользователь mtproxy) + hardening systemd
#    - Изоляция учетных данных (/etc/mtproxy/secrets.d, по секрету на пользователя)
#    - Ограничение частоты соединений (iptables-hashlimit)
#    - Сохранение состояния (netfilter-persistent)
#    - Watchdog (systemd timer) с автовосстановлением
#    - Синхронизация времени (NTP), опциональный сетевой тюнинг (BBR)
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
PORT_MODE="auto"            # auto | 443 | <номер порта>
STATS_PORT=2398             # Локальный порт статистики (только localhost)
WORKERS=1                   # Количество воркеров
INSTALL_DIR="/opt/MTProxy"  # Директория установки
CONFIG_DIR="/etc/mtproxy"   # Директория конфигов и секретов
SECRETS_DIR="$CONFIG_DIR/secrets.d"  # Секреты по пользователям
PROXY_TAG=""
FAKE_TLS_DOMAIN=""          # Пусто = автовыбор из TLS_DOMAINS
# Правдоподобные домены для Fake TLS (реально обслуживают TLS 1.3).
# НЕ используйте домены вроде google.com: DPI выявляет подмену по несовпадению
# SNI и владельца IP-адреса сервера, что ведёт к активному зондированию и блоку.
TLS_DOMAINS=(
    "www.microsoft.com"
    "cdn.discordapp.com"
    "ajax.googleapis.com"
    "www.cloudflare.com"
    "github.githubassets.com"
)
RATE_LIMIT="5/min"          # Лимит новых подключений на IP
RATE_BURST=10               # Всплеск для rate-limit
TUNE_NET=0                  # 1 = сетевой тюнинг sysctl (BBR, буферы)
ENABLE_IPV6=0               # 1 = анонсировать IPv6 в ссылке
FORCE_UNSHARE="${FORCE_UNSHARE:-auto}"  # 1=всегда, 0=никогда, auto=по pid_max/ns_last_pid
CLI_DOMAIN_SET=0
CLI_PORT_SET=0

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

# --- Проверка занятости TCP-порта ---
port_in_use() {
    ss -lnt | awk '{print $4}' | grep -qE ":${1}$"
}

# --- Валидация Fake-TLS домена: DNS + реальный TLS 1.3 ---
validate_domain() {
    local d="$1"
    getent hosts "$d" >/dev/null 2>&1 || return 1
    curl -s --tlsv1.3 --tls-max 1.3 --max-time 6 -o /dev/null "https://${d}/" 2>/dev/null
}

# --- Автовыбор домена: случайный порядок, первый прошедший валидацию ---
select_fake_tls_domain() {
    local d
    while IFS= read -r d; do
        if validate_domain "$d"; then
            echo "$d"
            return 0
        fi
        warn "Домен $d не прошёл проверку (DNS/TLS 1.3) — пропускаю"
    done < <(printf '%s\n' "${TLS_DOMAINS[@]}" | shuf)
    return 1
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
            CLI_DOMAIN_SET=1
            shift 2
            ;;
        --domain-list)
            [[ -n "${2:-}" ]] || fail "Не указан список доменов после $1"
            IFS=',' read -ra TLS_DOMAINS <<< "$2"
            shift 2
            ;;
        --port)
            PORT_MODE="${2:-}"
            [[ -n "$PORT_MODE" ]] || fail "Не указан порт после $1"
            CLI_PORT_SET=1
            shift 2
            ;;
        --tune-net)
            TUNE_NET=1
            shift
            ;;
        --ipv6)
            ENABLE_IPV6=1
            shift
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

# qrencode — опционально, для QR-кода ссылки подключения
if ! command -v qrencode &>/dev/null; then
    apt-get install -y -qq qrencode > /dev/null 2>&1 || true
fi

ok "Зависимости установлены"

# ─── 1a. Синхронизация времени (критично для MTProto/TLS) ──
info "Настраиваю синхронизацию времени..."
if command -v timedatectl &>/dev/null; then
    timedatectl set-ntp true > /dev/null 2>&1 || true
fi
if ! timedatectl show -p NTP --value 2>/dev/null | grep -qi '^yes$'; then
    apt-get install -y -qq chrony > /dev/null 2>&1 && \
        systemctl enable --now chrony > /dev/null 2>&1 && \
        ok "Установлен и запущен chrony" || \
        warn "Не удалось настроить NTP — проверьте синхронизацию времени вручную"
else
    ok "NTP уже активен"
fi

# ─── 2. Создание изолированного системного пользователя ────
if ! id mtproxy &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin mtproxy
    ok "Создан системный пользователь mtproxy"
else
    ok "Пользователь mtproxy уже существует"
fi

# ─── 3. Миграция настроек при повторной установке ──────────
SERVICE_FILE="/etc/systemd/system/MTProxy.service"

# Приоритет 1: env-файл текущей установки (новый формат)
if [[ -f "$CONFIG_DIR/env" ]]; then
    CLI_DOMAIN_VALUE="$FAKE_TLS_DOMAIN"
    # shellcheck disable=SC1091
    source "$CONFIG_DIR/env"
    # CLI-аргумент --domain важнее сохранённого значения
    if [[ "$CLI_DOMAIN_SET" == "1" ]]; then
        FAKE_TLS_DOMAIN="$CLI_DOMAIN_VALUE"
    fi
    ok "Переиспользую настройки из $CONFIG_DIR/env"
fi

# Приоритет 2: разбор старого unit-файла (формат <= 1.2.x)
if [[ -f "$SERVICE_FILE" && ! -f "$CONFIG_DIR/env" ]]; then
    EXISTING_PORT=$(awk '/-H/ {for(i=1;i<=NF;i++) if($i=="-H") {print $(i+1); exit}}' "$SERVICE_FILE")
    EXISTING_PORT="${EXISTING_PORT%%\\}"
    EXISTING_SECRET=""
    # Приоритет: файловое хранилище секрета
    if [[ -f "$CONFIG_DIR/secret" ]]; then
        EXISTING_SECRET=$(cat "$CONFIG_DIR/secret" 2>/dev/null || true)
    fi
    # Fallback: извлечение из конфигурации systemd (устаревший формат)
    if [[ -z "$EXISTING_SECRET" ]]; then
        EXISTING_SECRET=$(awk '/-S/ {for(i=1;i<=NF;i++) if($i=="-S") {print $(i+1); exit}}' "$SERVICE_FILE")
        EXISTING_SECRET="${EXISTING_SECRET%%\\}"
    fi
    # Сохранение домена Fake TLS
    EXISTING_DOMAIN=$(awk '/--domain/ {for(i=1;i<=NF;i++) if($i=="--domain") {print $(i+1); exit}}' "$SERVICE_FILE")
    EXISTING_DOMAIN="${EXISTING_DOMAIN%%\\}"
    if [[ -n "$EXISTING_DOMAIN" && "$CLI_DOMAIN_SET" == "0" ]]; then
        FAKE_TLS_DOMAIN="$EXISTING_DOMAIN"
    fi

    if [[ -n "$EXISTING_PORT" && -n "$EXISTING_SECRET" ]]; then
        PROXY_PORT="$EXISTING_PORT"
        SECRET="$EXISTING_SECRET"
        ok "Переиспользую порт и секрет из текущего сервиса"
    fi
fi

# CLI-аргументы имеют приоритет над сохранёнными настройками
if [[ "$CLI_PORT_SET" == "1" ]]; then
    PROXY_PORT=0
fi

# ─── 3a. Выбор порта ───────────────────────────────────────
if [[ -z "${PROXY_PORT:-}" || "$PROXY_PORT" == "0" ]]; then
    case "$PORT_MODE" in
        auto)
            PROXY_PORT=$(generate_port)
            ok "Выбран случайный порт: $PROXY_PORT"
            ;;
        443)
            if port_in_use 443; then
                warn "Порт 443 занят — использую случайный порт"
                PROXY_PORT=$(generate_port)
            else
                PROXY_PORT=443
            fi
            ok "Выбран порт 443 (маскировка под HTTPS)"
            ;;
        *)
            if ! [[ "$PORT_MODE" =~ ^[0-9]+$ ]] || [[ "$PORT_MODE" -lt 1 || "$PORT_MODE" -gt 65535 ]]; then
                fail "Некорректный порт: $PORT_MODE (ожидается auto, 443 или 1-65535)"
            fi
            if port_in_use "$PORT_MODE"; then
                fail "Порт $PORT_MODE уже занят другим процессом"
            fi
            PROXY_PORT="$PORT_MODE"
            ok "Выбран порт: $PROXY_PORT"
            ;;
    esac
fi

# ─── 3b. Выбор Fake-TLS домена ─────────────────────────────
if [[ -z "${FAKE_TLS_DOMAIN:-}" ]]; then
    info "Подбираю домен для Fake TLS (проверка DNS + TLS 1.3)..."
    FAKE_TLS_DOMAIN=$(select_fake_tls_domain) \
        || fail "Ни один домен из списка не прошёл валидацию. Укажите вручную: --domain example.com"
    ok "Выбран домен Fake TLS: $FAKE_TLS_DOMAIN"
else
    if ! validate_domain "$FAKE_TLS_DOMAIN"; then
        warn "Домен $FAKE_TLS_DOMAIN не прошёл проверку DNS/TLS 1.3 — использую как указано"
    fi
fi

# ─── 4. Сборка MTProxy из исходного кода ──────────────────
if [[ -d "$INSTALL_DIR" ]]; then
    warn "Директория $INSTALL_DIR уже существует — обновляю..."
    cd "$INSTALL_DIR"
    git config --global --add safe.directory "$INSTALL_DIR"
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

# ─── 6. Генерация криптографических секретов (по пользователям) ──
mkdir -p "$SECRETS_DIR"

# Если пользовательских секретов ещё нет — создаём default из старого секрета
# либо генерируем новый
if ! compgen -G "$SECRETS_DIR/*.secret" > /dev/null; then
    if [[ -z "${SECRET:-}" ]]; then
        SECRET=$(head -c 16 /dev/urandom | xxd -ps)
        ok "Секрет сгенерирован"
    else
        ok "Секрет сохранён из предыдущей установки"
    fi
    echo "$SECRET" > "$SECRETS_DIR/default.secret"
fi

# Основной секрет для ссылки (default, либо первый доступный)
if [[ -f "$SECRETS_DIR/default.secret" ]]; then
    SECRET=$(cat "$SECRETS_DIR/default.secret")
else
    SECRET=$(cat "$(ls "$SECRETS_DIR"/*.secret | head -n1)")
fi

USER_COUNT=$(ls "$SECRETS_DIR"/*.secret 2>/dev/null | wc -l)
ok "Секретов в хранилище: $USER_COUNT (управление: mtproxy-user.sh)"

# ─── 7. Сохранение секретов в защищённое хранилище ─────────
echo "$SECRET" > "$CONFIG_DIR/secret"   # совместимость со старыми скриптами
echo "$FAKE_TLS_DOMAIN" > "$CONFIG_DIR/domain"
chmod 700 "$CONFIG_DIR" "$SECRETS_DIR"
chmod 600 "$CONFIG_DIR/secret" "$CONFIG_DIR/domain" "$SECRETS_DIR"/*.secret
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

# ─── 8a. Утилита управления пользователями (мультисекреты) ──
cat > /usr/local/bin/mtproxy-user.sh <<'USERSCRIPT'
#!/bin/bash
# Управление пользователями MTProxy: add/del/list/link
set -euo pipefail

CONFIG_DIR="/etc/mtproxy"
SECRETS_DIR="$CONFIG_DIR/secrets.d"
SERVICE_FILE="/etc/systemd/system/MTProxy.service"

if [[ $EUID -ne 0 ]]; then
    echo "Запустите от root: sudo mtproxy-user.sh ..." >&2
    exit 1
fi

# shellcheck disable=SC1091
source "$CONFIG_DIR/env"

usage() {
    echo "Использование:"
    echo "  mtproxy-user.sh add <имя>   — создать пользователя и вывести ссылку"
    echo "  mtproxy-user.sh del <имя>   — отозвать доступ"
    echo "  mtproxy-user.sh list        — список пользователей"
    echo "  mtproxy-user.sh link <имя>  — показать ссылку подключения"
    exit 1
}

valid_name() { [[ "$1" =~ ^[a-zA-Z0-9_-]+$ ]]; }

make_link() {
    local name="$1" secret domain_hex ip
    secret=$(cat "$SECRETS_DIR/$name.secret")
    domain_hex=$(echo -n "$FAKE_TLS_DOMAIN" | xxd -ps -c 200)
    ip=$(curl -s -4 --max-time 5 https://api.ipify.org 2>/dev/null || echo "YOUR_SERVER_IP")
    echo "tg://proxy?server=${ip}&port=${PROXY_PORT}&secret=ee${secret}${domain_hex}"
}

# Пересобрать строки -S в unit-файле из secrets.d и перезапустить сервис
apply_secrets() {
    local block tmp
    block=$(mktemp)
    tmp=$(mktemp)
    local f
    for f in "$SECRETS_DIR"/*.secret; do
        [[ -e "$f" ]] || { echo "Нет ни одного секрета — операция отменена" >&2; rm -f "$block" "$tmp"; exit 1; }
        printf '    -S %s \\\n' "$(cat "$f")" >> "$block"
    done
    sed -e '/^[[:space:]]*-S[[:space:]]/d' \
        -e "/^[[:space:]]*-H[[:space:]]/r $block" \
        "$SERVICE_FILE" > "$tmp"
    cat "$tmp" > "$SERVICE_FILE"
    rm -f "$block" "$tmp"
    systemctl daemon-reload
    systemctl restart MTProxy.service
    systemctl is-active --quiet MTProxy.service || {
        echo "Сервис не поднялся после изменения секретов — смотрите journalctl -u MTProxy" >&2
        exit 1
    }
}

cmd="${1:-}"
name="${2:-}"
case "$cmd" in
    add)
        [[ -n "$name" ]] || usage
        valid_name "$name" || { echo "Имя: только латиница, цифры, - и _" >&2; exit 1; }
        [[ -f "$SECRETS_DIR/$name.secret" ]] && { echo "Пользователь $name уже существует" >&2; exit 1; }
        head -c 16 /dev/urandom | xxd -ps > "$SECRETS_DIR/$name.secret"
        chmod 600 "$SECRETS_DIR/$name.secret"
        chown mtproxy:mtproxy "$SECRETS_DIR/$name.secret"
        apply_secrets
        echo "Пользователь $name создан. Ссылка:"
        make_link "$name"
        ;;
    del)
        [[ -n "$name" ]] || usage
        [[ -f "$SECRETS_DIR/$name.secret" ]] || { echo "Пользователь $name не найден" >&2; exit 1; }
        rm -f "$SECRETS_DIR/$name.secret"
        apply_secrets
        echo "Доступ для $name отозван"
        ;;
    list)
        { ls -1 "$SECRETS_DIR"/*.secret 2>/dev/null || true; } | xargs -r -n1 basename | sed 's/\.secret$//'
        ;;
    link)
        [[ -n "$name" ]] || usage
        [[ -f "$SECRETS_DIR/$name.secret" ]] || { echo "Пользователь $name не найден" >&2; exit 1; }
        make_link "$name"
        ;;
    *)
        usage
        ;;
esac
USERSCRIPT

chmod 700 /usr/local/bin/mtproxy-user.sh
chown root:root /usr/local/bin/mtproxy-user.sh
ok "Утилита mtproxy-user.sh установлена в /usr/local/bin"

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

# ─── 9a. IPv6 (опционально, -6 включает поддержку IPv6) ────
IPV6_ARGS=""
IPV6_ADDR=""
if [[ "$ENABLE_IPV6" == "1" ]]; then
    IPV6_ADDR=$(curl -s -6 --max-time 5 https://api64.ipify.org 2>/dev/null | tr -d '[:space:]' || true)
    if [[ "$IPV6_ADDR" =~ : ]]; then
        IPV6_ARGS="-6"
        ok "IPv6 включён: $IPV6_ADDR"
    else
        warn "Публичный IPv6 не обнаружен — флаг --ipv6 проигнорирован"
        IPV6_ADDR=""
    fi
fi

# ─── 9b. Сохранение настроек в env-файл (для переустановки и mtproxy-user.sh) ──
cat > "$CONFIG_DIR/env" <<EOF
INSTALL_DIR="$INSTALL_DIR"
CONFIG_DIR="$CONFIG_DIR"
STATS_PORT="$STATS_PORT"
PROXY_PORT="$PROXY_PORT"
WORKERS="$WORKERS"
FAKE_TLS_DOMAIN="$FAKE_TLS_DOMAIN"
PROXY_TAG="$PROXY_TAG"
NAT_INFO="$NAT_INFO"
EXEC_PREFIX="$EXEC_PREFIX"
IPV6_ARGS="$IPV6_ARGS"
IPV6_ADDR="$IPV6_ADDR"
EOF
chmod 600 "$CONFIG_DIR/env"
chown root:root "$CONFIG_DIR/env"

# ─── 9c. Unit-файл со всеми секретами и hardening ──────────
UNIT_SECRET_LINES=""
for secret_file in "$SECRETS_DIR"/*.secret; do
    UNIT_SECRET_LINES+="    -S $(cat "$secret_file") \\"
    UNIT_SECRET_LINES+=$'\n'
done

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
${UNIT_SECRET_LINES}    --http-stats \\
    --domain $FAKE_TLS_DOMAIN \\
    ${NAT_INFO} \\
    ${IPV6_ARGS} \\
    ${PROXY_TAG:+-P $PROXY_TAG} \\
    --aes-pwd $INSTALL_DIR/proxy-secret \\
    $INSTALL_DIR/proxy-multi.conf \\
    -M $WORKERS
KillMode=control-group
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
MemoryMax=256M
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$INSTALL_DIR
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

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

# ─── 9d. Watchdog: автовосстановление сервиса ──────────────
cat > "$CONFIG_DIR/watchdog.sh" <<'WATCHDOGSCRIPT'
#!/bin/bash
# Watchdog MTProxy: проверка активности и эндпоинта статистики
set -uo pipefail

# shellcheck disable=SC1091
source /etc/mtproxy/env
FAILS_FILE="/run/mtproxy-watchdog.fails"
LOG_TAG="mtproxy-watchdog"

if ! systemctl is-active --quiet MTProxy.service; then
    logger -t "$LOG_TAG" "Сервис не активен — перезапуск"
    systemctl restart MTProxy.service
    exit 0
fi

if curl -s --max-time 5 "http://127.0.0.1:${STATS_PORT}/stats" > /dev/null 2>&1; then
    rm -f "$FAILS_FILE"
else
    fails=$(( $(cat "$FAILS_FILE" 2>/dev/null || echo 0) + 1 ))
    echo "$fails" > "$FAILS_FILE"
    if [[ "$fails" -ge 3 ]]; then
        logger -t "$LOG_TAG" "Эндпоинт статистики недоступен ${fails} проверок подряд — перезапуск"
        systemctl restart MTProxy.service
        rm -f "$FAILS_FILE"
    fi
fi
WATCHDOGSCRIPT

chmod 700 "$CONFIG_DIR/watchdog.sh"
chown root:root "$CONFIG_DIR/watchdog.sh"

cat > /etc/systemd/system/mtproxy-watchdog.service <<EOF
[Unit]
Description=MTProxy watchdog check
After=MTProxy.service

[Service]
Type=oneshot
ExecStart=$CONFIG_DIR/watchdog.sh
EOF

cat > /etc/systemd/system/mtproxy-watchdog.timer <<EOF
[Unit]
Description=MTProxy watchdog timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
Unit=mtproxy-watchdog.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now mtproxy-watchdog.timer > /dev/null 2>&1
ok "Watchdog настроен (проверка каждые 2 минуты)"

# ─── 10. Настройка планировщика обновлений ─────────────────
CRON_CMD="$CONFIG_DIR/update_config.sh"
CRON_LINE="0 4 * * * $CRON_CMD"

# Еженедельное обновление бинарника с откатом при неудачной сборке
cat > "$CONFIG_DIR/update_binary.sh" <<'BINSCRIPT'
#!/bin/bash
# Еженедельное обновление mtproto-proxy из upstream с откатом
set -euo pipefail

INSTALL_DIR="/opt/MTProxy"
LOG_TAG="mtproxy-update-bin"

cd "$INSTALL_DIR"
git config --global --add safe.directory "$INSTALL_DIR"
git fetch --quiet origin

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse '@{u}' 2>/dev/null || echo "$LOCAL")
[[ "$LOCAL" == "$REMOTE" ]] && exit 0

if ! git merge --ff-only "$REMOTE" > /dev/null 2>&1; then
    logger -t "$LOG_TAG" "Ошибка: fast-forward до $REMOTE не удался"
    exit 1
fi

BACKUP=$(mktemp)
cp -a objs/bin/mtproto-proxy "$BACKUP" 2>/dev/null || true

if make -j"$(nproc)" > /dev/null 2>&1; then
    chown -R mtproxy:mtproxy "$INSTALL_DIR"
    systemctl restart MTProxy.service || true
    sleep 3
    if systemctl is-active --quiet MTProxy.service; then
        logger -t "$LOG_TAG" "Обновлён до ${REMOTE:0:8}"
        rm -f "$BACKUP"
        exit 0
    fi
fi

# Откат при неудачной сборке или падении сервиса
if [[ -s "$BACKUP" ]]; then
    cp -a "$BACKUP" objs/bin/mtproto-proxy
    chown mtproxy:mtproxy objs/bin/mtproto-proxy
    systemctl restart MTProxy.service || true
    logger -t "$LOG_TAG" "Ошибка обновления до ${REMOTE:0:8} — выполнен откат"
else
    logger -t "$LOG_TAG" "Ошибка обновления до ${REMOTE:0:8}, бэкап недоступен"
fi
rm -f "$BACKUP"
exit 1
BINSCRIPT

chmod 700 "$CONFIG_DIR/update_binary.sh"
chown root:root "$CONFIG_DIR/update_binary.sh"

CRON_BIN_LINE="17 3 * * 0 $CONFIG_DIR/update_binary.sh"
( { crontab -l 2>/dev/null || true; } | { grep -v "update_config\|getProxyConfig\|update_binary" || true; } ; echo "$CRON_LINE" ; echo "$CRON_BIN_LINE" ) | crontab -
ok "Cron настроен: конфиг ежедневно в 04:00, бинарник еженедельно (вс 03:17)"

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

# ─── 12a. Сетевой тюнинг (опционально, --tune-net) ─────────
if [[ "$TUNE_NET" == "1" ]]; then
    info "Применяю сетевой тюнинг (BBR, буферы, backlog)..."
    cat > /etc/sysctl.d/90-mtproxy.conf <<EOF
# MTProxy: пропускная способность и устойчивость
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.somaxconn=4096
net.ipv4.tcp_max_syn_backlog=8192
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
EOF
    sysctl --system > /dev/null 2>&1 || warn "Не все параметры sysctl применились"
    ok "Сетевой тюнинг применён (/etc/sysctl.d/90-mtproxy.conf)"
fi

# ─── 12b. Ограничение объёма журнала ───────────────────────
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/90-mtproxy.conf <<EOF
[Journal]
SystemMaxUse=200M
EOF
systemctl restart systemd-journald > /dev/null 2>&1 || true

# ─── 13. Определение внешнего IP-адреса сервера ────────────
info "Определяю внешний IP-адрес..."
SERVER_IP=$(detect_external_ip)

if [[ "$SERVER_IP" == "YOUR_SERVER_IP" ]]; then
    warn "Не удалось определить внешний IP. Подставьте адрес вручную в ссылку ниже."
else
    ok "Внешний IP: $SERVER_IP"
fi

# --- Финальный отчет о развертывании ---
MAIN_LINK="tg://proxy?server=${SERVER_IP}&port=${PROXY_PORT}&secret=${EE_SECRET}"

echo ""
echo "----------------------------------------------------------------------"
echo "Развертывание MTProxy успешно завершено"
echo "----------------------------------------------------------------------"
echo ""
printf "%-25s %s\n" "Внешний IP:" "$SERVER_IP"
printf "%-25s %s\n" "Порт:" "$PROXY_PORT"
printf "%-25s %s\n" "Домен Fake TLS:" "$FAKE_TLS_DOMAIN"
printf "%-25s %s\n" "Пользователей:" "$USER_COUNT"
echo ""
echo "Ссылки для подключения (по пользователям):"
for secret_file in "$SECRETS_DIR"/*.secret; do
    user_name=$(basename "$secret_file" .secret)
    user_secret=$(cat "$secret_file")
    user_ee="ee${user_secret}${DOMAIN_HEX}"
    echo "  [$user_name] tg://proxy?server=${SERVER_IP}&port=${PROXY_PORT}&secret=${user_ee}"
done
echo ""
echo "Альтернативный формат (default):"
echo "https://t.me/proxy?server=${SERVER_IP}&port=${PROXY_PORT}&secret=${EE_SECRET}"
if [[ -n "$IPV6_ADDR" ]]; then
    echo ""
    echo "IPv6-ссылка (default):"
    echo "tg://proxy?server=${IPV6_ADDR}&port=${PROXY_PORT}&secret=${EE_SECRET}"
fi
echo ""

# QR-код основной ссылки (если qrencode доступен)
if command -v qrencode &>/dev/null; then
    qrencode -t ANSIUTF8 "$MAIN_LINK" 2>/dev/null || true
    echo ""
fi

echo "----------------------------------------------------------------------"
echo "Управление пользователями:"
echo "  mtproxy-user.sh add <имя>   - Создать пользователя и получить ссылку"
echo "  mtproxy-user.sh del <имя>   - Отозвать доступ"
echo "  mtproxy-user.sh list        - Список пользователей"
echo "  mtproxy-user.sh link <имя>  - Показать ссылку пользователя"
echo ""
echo "Команды управления:"
echo "  systemctl status MTProxy          - Статус службы"
echo "  systemctl restart MTProxy         - Перезапуск"
echo "  journalctl -u MTProxy -f          - Просмотр журнала"
echo "  journalctl -t mtproxy-watchdog    - Журнал watchdog"
echo "  curl localhost:$STATS_PORT/stats  - Диагностическая статистика"
echo ""
echo "Метаданные безопасности:"
echo "  Хранилище секретов: $SECRETS_DIR (по секрету на пользователя)"
echo "  Контекст:           Пользователь 'mtproxy' + systemd hardening"
echo "  Ограничение:        $RATE_LIMIT (burst $RATE_BURST)"
echo "  Протокол:           Fake TLS (домен: $FAKE_TLS_DOMAIN)"
echo "  Watchdog:           проверка каждые 2 минуты (systemd timer)"
echo ""
echo "Регистрация прокси: https://t.me/MTProxybot"
echo ""
