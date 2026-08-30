<p align="center">
  <a href="README.en.md">English</a> &nbsp;|&nbsp; <b>Русский</b>
</p>

<p align="center">
  <img src="cover.webp" alt="MTProxy — обход блокировок Telegram" width="100%" />
</p>

<h1 align="center">Сценарий развертывания MTProxy</h1>

<p align="center">
  Автоматизированная установка MTProxy на <b>Ubuntu 22.04 / 24.04 LTS</b> с Fake TLS обфускацией,<br/>
  мультисекретами пользователей, watchdog и защитой от DPI
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square" alt="License: MIT"/></a>
  <a href="https://ubuntu.com/"><img src="https://img.shields.io/badge/Platform-Ubuntu%2022.04%20%2F%2024.04-E95420.svg?style=flat-square&logo=ubuntu&logoColor=white" alt="Platform"/></a>
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/Version-1.3.1-success.svg?style=flat-square" alt="Version"/></a>
  <img src="https://img.shields.io/badge/FakeTLS-TLS%201.3-7A5CFA.svg?style=flat-square" alt="FakeTLS"/>
  <img src="https://img.shields.io/badge/DPI-resistant-00B37E.svg?style=flat-square" alt="DPI"/>
</p>

<p align="center"><b>Спонсоры проекта</b></p>

<table>
<tr>
<td align="center" valign="top" width="50%">

<h3>💬 Чат ВЕГА</h3>

Самый многофункциональный AI-чат в мире<br/>с бесплатным <b>Автопилотом</b> — все модели AI,<br/>генерация фото, видео, музыки и сайтов. Персонализированный чат под вас.

<br/><br/>
<a href="https://vega.chat"><img src="https://img.shields.io/badge/Изучить_ВЕГА-7A5CFA?style=for-the-badge&logo=sparkles&logoColor=white" alt="Изучить ВЕГА"/></a>

</td>
<td align="center" valign="top" width="50%">

<h3>🔌 API VEGA</h3>

Все endpoint <b>OpenRouter</b> в России + каталог<br/><b>MCP, SKILL, приложений</b> и <b>SKILL API VEGA</b><br/>для создания своих AI-приложений без ограничений.

<br/><br/>
<a href="https://api.vega.chat"><img src="https://img.shields.io/badge/Перейти_к_API-00B37E?style=for-the-badge&logo=rocket&logoColor=white" alt="Перейти к API"/></a>

</td>
</tr>
</table>

---

## 📑 Оглавление

- [🚀 Быстрый старт](#-быстрый-старт)
- [⚙️ Что выполняет сценарий](#️-что-выполняет-сценарий)
- [🕵️ Почему не `www.google.com`?](#️-почему-не-wwwgooglecom)
- [👥 Управление пользователями](#-управление-пользователями)
- [🛡️ Архитектура безопасности](#️-архитектура-безопасности)
- [🔧 Дополнительные параметры](#-дополнительные-параметры)
- [🧩 Workaround для PID > 65535](#-workaround-для-pid--65535)
- [🖥️ Администрирование](#️-администрирование)
- [🔄 Обновление скрипта](#-обновление-скрипта)
- [🗑️ Деинсталляция](#️-деинсталляция)

---

## 🚀 Быстрый старт

```bash
git clone https://github.com/lingeniare/MTProxy.git && cd MTProxy && sudo bash install_mtproxy.sh
```

> После завершения скрипт выведет готовую ссылку `tg://proxy?...` и **QR-код**.<br/>Откройте ссылку на телефоне — Telegram подхватит прокси автоматически.

---

## ⚙️ Что выполняет сценарий

| # | Действие |
|---|----------|
| 1 | Устанавливает системные зависимости (включая `cron`, если отсутствует) |
| 2 | Настраивает синхронизацию времени (NTP) — сдвиг часов ломает MTProto-рукопожатие |
| 3 | Создает изолированного системного пользователя `mtproxy` |
| 4 | Компилирует MTProxy из [официального репозитория Telegram](https://github.com/TelegramMessenger/MTProxy) |
| 5 | Загружает и валидирует конфигурационные файлы Telegram |
| 6 | Подбирает правдоподобный домен для Fake TLS из 11 «нейтральных» (проверка DNS + TLS 1.3 с валидным сертификатом, с учётом JA4/ECH) и генерирует секреты |
| 7 | Автоматически определяет NAT-конфигурацию для облачных VPS |
| 8 | Регистрирует systemd-сервис через wrapper `/etc/mtproxy/run.sh` (секреты не попадают в unit) с автозапуском, расширенным hardening и ограничением restart-storm |
| 9 | Настраивает **watchdog**: проверка каждые 2 минуты с защитой `flock` и автоперезапуском при 3 неудачах подряд |
| 10 | Настраивает ограничение частоты соединений через `iptables` |
| 11 | Создает задания планировщика: ежедневное обновление конфигурации Telegram и еженедельное обновление бинарника (с `flock`, валидацией и откатом, бэкап в `$INSTALL_DIR`) |
| 12 | Открывает порт в межсетном экране и сохраняет правила на случай перезагрузки |

---

## 🕵️ Почему не `www.google.com`?

Fake TLS подделывает TLS-рукопожатие под указанный домен. Если домен — `google.com`, а IP сервера не принадлежит Google, DPI тривиально выявляет подмену по несовпадению **SNI ↔ владелец адреса** (проверка JA4/ECH) — следом идёт активное зондирование и блокировка.

Поэтому установщик выбирает домен из **11 «нейтральных» сервисов** (Microsoft, Discord CDN, Cloudflare, Bing, Adobe, Spotify, Dropbox и др.), проверяя `DNS + TLS 1.3` с валидным chain-of-trust (`curl --tlsv1.3 --fail`, fallback HEAD для CDN). Свой список можно задать через `--domain-list`.

> 💡 **Порт тоже маскировка.** TLS-трафик на нестандартном порту выделяется из фона. Флаг `--port 443` маскирует прокси под обычный HTTPS.

---

## 👥 Управление пользователями

> У каждого пользователя — собственный секрет `(/etc/mtproxy/secrets.d/<имя>.secret)`. Отзыв доступа одного не затрагивает остальных.

```bash
mtproxy-user.sh add alice     # создать пользователя и получить ссылку
mtproxy-user.sh link alice    # показать ссылку повторно
mtproxy-user.sh list          # список пользователей
mtproxy-user.sh del alice     # отозвать доступ
```

---

## 🛡️ Архитектура безопасности

| Механизм | Реализация |
|----------|------------|
| **Изоляция привилегий** | Выделенный системный пользователь `mtproxy` (без shell, без home) |
| **Защита секретов** | `/etc/mtproxy/secrets.d` (`0600`, `root:root`) + wrapper `/etc/mtproxy/run.sh` — секреты подставляются в рантайме, не видны через `systemctl cat` / `ps` |
| **Обфускация протокола** | Fake TLS с автовыбором из 11 доменов (DNS + TLS 1.3 + валидный сертификат, JA4/ECH) |
| **Противодействие DPI** | Rate-limiting `iptables hashlimit`; опция порта `443` |
| **Мультисекреты** | Отдельный секрет на пользователя (`secrets.d`), точечный отзыв доступа |
| **Hardening** | `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `LockPersonality`, `RestrictSUIDSGID`, `RemoveIPC`, `SystemCallArchitectures=native`, лимиты `TasksMax`/`MemoryMax` |
| **Watchdog** | systemd timer: проверка каждые 2 мин с `flock`, автоперезапуск после 3 неудач |
| **Время** | NTP-синхронизация (timesyncd/chrony) |
| **Устойчивость** | Сохранение правил через `netfilter-persistent` |
| **Автообновление** | Конфиг — ежедневно, бинарник — еженедельно (с `flock`, валидацией и откатом) |
| **NAT** | Автоматическое определение `--nat-info` для облачных окружений |

---

## 🔧 Дополнительные параметры

> Для большинства случаев параметры указывать не требуется. Значения по умолчанию оптимальны для небольших групп (до 5 человек).

| Аргумент | Описание | По умолчанию |
|----------|----------|--------------|
| `--domain`, `-D` | Домен для эмуляции TLS SNI | автовыбор из встроенного списка с валидацией |
| `--domain-list` | Свой список доменов через запятую для автовыбора | _(опционально)_ |
| `--port` | Порт: `auto`, `443` (маскировка под HTTPS) или номер | `auto` (случайный) |
| `--tag`, `-P` | Тег из [@MTProxybot](https://t.me/MTProxybot) | _(опционально)_ |
| `--rate-limit` | Лимит новых соединений на IP | `5/min` |
| `--rate-burst` | Допустимый всплеск | `10` |
| `--tune-net` | Сетевой тюнинг sysctl: BBR, буферы, backlog | выкл |
| `--ipv6` | Включить поддержку IPv6 (`-6`) и вывести IPv6-ссылку | выкл |

**Переменные окружения:**

| Переменная | Описание | По умолчанию |
|------------|----------|--------------|
| `FORCE_UNSHARE=auto\|1\|0` | Режим PID namespace workaround: `auto` включает `unshare`, если `pid_max > 65535` или `ns_last_pid > 65535`; `1` включает всегда; `0` отключает | `auto` |

---

## 🧩 Workaround для PID > 65535

На системах с большим `kernel.pid_max` (например `4194304`) MTProxy может падать при старте:

```text
mtproto-proxy: common/pid.c:42: init_common_PID: Assertion `!(p & 0xffff0000)' failed.
```

**Причина:** текущая версия `mtproto-proxy` ожидает PID в 16-битном диапазоне, а systemd может выдать PID > `65535`.

Скрипт автоматически включает workaround через PID namespace (совместимо с Ubuntu 24.04 / systemd 255):

```text
/usr/bin/unshare --pid --fork --mount-proc -- /opt/MTProxy/objs/bin/mtproto-proxy ...
```

Дополнительно в unit добавлены `StartLimitIntervalSec=60` и `StartLimitBurst=5` против restart-storm.

<details>
<summary><b>Как проверить, что workaround активен</b></summary>

1. `systemctl cat MTProxy` — в `ExecStart` должен быть `/etc/mtproxy/run.sh` (с префиксом `unshare`, если активен); секреты (`-S`) не показываются.
2. `journalctl -u MTProxy -f` — в логах PID обычно как `[1]`, `[2]`.
3. `systemctl status MTProxy` — `MainPID` будет у `unshare`/`run.sh`, дочерние `mtproto-proxy` работают в той же cgroup.

</details>

---

## 🖥️ Администрирование

```bash
systemctl status MTProxy          # статус службы
systemctl restart MTProxy         # перезапуск
journalctl -u MTProxy -f          # журнал в реальном времени
journalctl -t mtproxy-watchdog    # журнал watchdog
curl localhost:2398/stats         # диагностическая статистика
```

---

## 🔄 Обновление скрипта

```bash
cd MTProxy && git pull && sudo bash install_mtproxy.sh
```

Повторный запуск сохраняет порт, секрет и домен из текущей конфигурации. Ранее выданные ссылки останутся рабочими.

---

## 🗑️ Деинсталляция

```bash
sudo bash uninstall_mtproxy.sh
```

Удаляет сервис, watchdog, cron-задания, правила фаервола, пользователя и все файлы.

---

## ⚠️ Ограничения

MTProxy проксирует только **текстовые сообщения и медиафайлы**. Голосовые и видеозвонки **не поддерживаются**. Для звонков используйте [WireGuard](https://www.wireguard.com/) или [AmneziaWG](https://amnezia.org/) с раздельным туннелированием.

---

## 📋 Системные требования

- Ubuntu 22.04 LTS / 24.04 LTS
- Доступ с правами `root`
- Сетевое подключение к интернету

---

<p align="center">
  <b>❤️ Поддержать проект</b><br/>
  <a href="https://pay.cloudtips.ru/p/772a30a1"><img src="https://img.shields.io/badge/Поддержать_проект-FF5F5F?style=for-the-badge&logo=heart&logoColor=white" alt="Поддержать проект"/></a>
</p>

<p align="center">
  <a href="CONTRIBUTING.md">Вклад в проект</a> •
  <a href="SECURITY.md">Безопасность</a> •
  <a href="LICENSE">MIT License</a>
</p>

<p align="center">
  <sub>© 2026 <a href="https://getmyai.io">AI for people and business</a></sub>
</p>
