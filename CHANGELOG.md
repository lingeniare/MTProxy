# Changelog

## [1.3.0] - 2026-08-11

### New Features

*   **Multi-user secret management**: Per-user secrets in `/etc/mtproxy/secrets.d/` with `mtproxy-user.sh` utility (add / del / list / link). Revoking one user's access doesn't affect others.
*   **Fake TLS domain auto-selection**: Installer picks a plausible domain from a built-in list (Microsoft, Discord CDN, Cloudflare, etc.), verifying DNS resolution and TLS 1.3 support. Custom list via `--domain-list`.
*   **Port flexibility**: `--port auto` (random), `--port 443` (HTTPS camouflage), or explicit port number. Default is random to avoid fingerprinting.
*   **IPv6 support**: `--ipv6` flag enables `-6` mode and outputs an IPv6 connection link.
*   **Network tuning**: `--tune-net` applies sysctl tuning (BBR congestion control, buffer sizes, backlog).
*   **Watchdog**: systemd timer checks service health every 2 minutes and auto-restarts on failure (with 3-strike threshold for stats endpoint).
*   **Binary auto-update**: Weekly cron job pulls upstream changes, rebuilds, and restarts — with automatic rollback on build or startup failure.
*   **Configuration persistence**: Settings saved to `/etc/mtproxy/env` for seamless re-installs and use by `mtproxy-user.sh`.
*   **QR code**: Connection link displayed as QR code if `qrencode` is available.
*   **Journald limit**: Log volume capped at 200M via journald drop-in.

### Improvements

*   **Uninstall**: Now removes watchdog timer/service, `mtproxy-user.sh`, sysctl drop-in, journald drop-in, and watchdog state file.
*   **Rate-limiting resilience**: Installation continues with a warning if `iptables` modules (hashlimit/conntrack) are unavailable, instead of crashing.
*   **NAT detection**: Auto-detects internal vs external IP for cloud VPS (AWS, Hetzner, etc.) and adds `--nat-info`.
*   **Restart-storm protection**: `StartLimitIntervalSec=60` + `StartLimitBurst=5` in systemd unit.
*   **Documentation**: README rewritten in English (Russian preserved as `README.ru.md`). CONTRIBUTING.md and SECURITY.md translated to English.

---

## [1.2.0] - 2026-02-22

### Исправления

*   **Критическая ошибка установки**: Порог валидации файла `proxy-multi.conf` был установлен в 1024 байта, тогда как реальный размер файла от серверов Telegram составляет ~500-900 байт. Установка завершалась ошибкой «повреждён или слишком мал». Порог понижен до 64 байт с выводом фактического размера при ошибке.
*   **Конфликт systemd и setuid()**: Одновременное использование директивы `User=mtproxy` в systemd-юните и флага `-u mtproxy` в mtproto-proxy приводило к ошибке: процесс запускался от имени `mtproxy` и не мог выполнить `setuid()`. Директива `User=` удалена — сброс привилегий выполняется самим mtproto-proxy.
*   **Владелец файлов после обновления**: Скрипт `update_config.sh`, запущенный через cron от root, создавал файлы, недоступные для чтения пользователю `mtproxy`. Добавлен принудительный `chown` после каждого обновления конфигурации.

### Новые возможности

*   **Автоматическое определение NAT**: Для облачных VPS (AWS, Hetzner и др.) скрипт определяет внутренний и внешний IP и автоматически добавляет параметр `--nat-info`.
*   **Корректная установка xxd**: Обработка различий в именах пакетов между Ubuntu 22.04 (`vim-common`) и 23.10+ (`xxd`).
*   **Диагностика при ошибке запуска**: При невозможности запустить службу в терминал выводятся последние 20 строк журнала `journalctl`.
*   **Устойчивость rate-limiting**: При недоступности модулей iptables (hashlimit, conntrack) установка продолжается с предупреждением вместо аварийного завершения.

### Инфраструктурные изменения

*   Переход с `After=network.target` на `After=network-online.target` для корректного запуска при загрузке.
*   Улучшена диагностика при ошибках валидации (вывод фактического размера файла).
*   Оптимизирована установка зависимостей: безусловная установка вместо поэлементной проверки через dpkg.

---

## [1.1.0] - 2026-02-21

### Безопасность и обфускация протокола
*   Реализована поддержка Fake TLS с параметром `--domain` и секретами формата `ee`.
*   Переход от учетной записи `nobody` к выделенному пользователю `mtproxy`.
*   Изоляция секретов в директории `/etc/mtproxy/` с правами доступа `0600`.
*   Ограничение частоты соединений через `iptables hashlimit`.

### Отказоустойчивость
*   Скрипт обновления конфигурации с валидацией и откатом.
*   Сохранение правил межсетевого экрана через `netfilter-persistent`.
*   Каскадное определение внешнего IP через 8 независимых сервисов.
*   Добавлен параметр `--http-stats` для доступа к диагностической статистике.
*   Проверка и установка cron.

---

## [1.0.0] - 2026-02-11
### Первоначальный релиз
*   Автоматизированное развертывание MTProxy из исходного кода.
*   Интеграция с systemd и настройка межсетевого экрана.
