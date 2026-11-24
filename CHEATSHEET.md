# AdIdentity — шпаргалка по командам

Всё самое частое на одной странице. Подробности: `docs/troubleshooting.adoc`,
полный прогон стенда: `docs/test-plan.adoc`.

Лаборатория v2: Collector `10.0.1.100`, DC1 `10.0.1.110`, DC2 `10.0.1.99`,
OPNsense `10.0.1.254`, клиент `10.0.1.10`. Сдача multi-DC: `docs/collector.adoc`.

## Плагин (OPNsense, SSH под root)

```sh
configctl adidentity session-list    # сессии плагина: user, ip, groups, expires_at
configctl adidentity expire          # истечь просроченное + сверить pf-таблицы
configctl adidentity reproject       # перезалить таблицы из sessions.json
pfctl -t Managers -T show            # что реально лежит в alias
pfctl -ss | grep 10.0.1.10           # открытые соединения адреса
```

`expire` и `reproject` безопасно запускать руками в любой момент: они
идемпотентны и чинят расхождение в обе стороны.

Установка и обновление:

```sh
cd /root/AdIdentityDC && git pull && ./plugin/install.sh
./plugin/install.sh -n               # dry-run, ничего не трогает
./plugin/install.sh -u               # удалить файлы плагина (сессии и настройки остаются)
```

Где что лежит:

```sh
/var/db/adidentity/sessions.json            # сессии
/var/db/adidentity/managed_aliases.json     # какие alias плагин считает своими
/usr/local/etc/adidentity.conf              # настройки из UI
/usr/local/opnsense/scripts/adidentity/session_store.py
/usr/local/etc/rc.syshook.d/start/99-adidentity   # восстановление при загрузке
```

Проверить, что всё на месте:

```sh
grep -i adidentity /var/log/configd/latest.log | tail   # вызовы плагина (НЕ /var/log/system)
grep adidentity /var/cron/tabs/nobody                   # задача истечения, ставится кнопкой Apply
ls -l /usr/local/etc/rc.syshook.d/start/99-adidentity   # хук загрузки
python3 -m py_compile /usr/local/opnsense/scripts/adidentity/session_store.py
```

API (Bearer — только для `session/*`, кнопка Resync работает от сессии UI):

```sh
curl -s -H "Authorization: Bearer <ТОКЕН>" http://10.0.1.254/api/adidentity/session/list
curl -s -o /dev/null -w '%{http_code}\n' http://10.0.1.254/api/adidentity/session/list   # ждём 401
```

## Агент (DC, PowerShell от администратора)

```powershell
Get-Service AdIdentityAgent
Restart-Service AdIdentityAgent
Stop-Service AdIdentityAgent
# Role (Collector/Sensor/Standalone) — только в C:\AdIdentity\appsettings.json
# Установка службы: agent\scripts\Install-AdIdentityService.ps1 -Start
cd C:\AdIdentity; .\AdIdentity.Agent.Service.exe    # консоль: видно каждое событие
```

Смена shared token (везде одна строка → Apply в UI → Restart-Service на всех
хостах). Не коммитить реальный токен; в publish/examples только placeholder.

```powershell
$t = "<ТОКЕН>"
Invoke-RestMethod "http://127.0.0.1:8443/api/v1/health"   -Headers @{Authorization="Bearer $t"}
Invoke-RestMethod "http://127.0.0.1:8443/api/v1/sessions" -Headers @{Authorization="Bearer $t"} |
  ConvertTo-Json -Depth 5
```

Файлы состояния:

```
C:\AdIdentity\appsettings.json                  # настройки (перетирается при пересборке)
%ProgramData%\AdIdentity\sessions.json          # сессии агента
%ProgramData%\AdIdentity\login-memory.json      # подтверждённые логины для D23
```

События на DC:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768} -MaxEvents 5 |
  Format-List TimeCreated, Message
klist purge                                      # на клиенте: заставить запросить билеты заново
```

Группы и учётки:

```powershell
Get-ADPrincipalGroupMembership ivanov | Select-Object -ExpandProperty name
Add-ADGroupMember -Identity "Managers" -Members "ivanov"
```

Под службой агент пишет в журнал **Application**, источник `AdIdentity Agent`,
и только Warning и выше. Для наблюдения за работой удобнее консольный запуск
или `/api/v1/sessions`.

## Когда что-то не работает

Идти сверху вниз и чинить тот слой, где первое «нет»:

```sh
# 1. событие на DC есть?      Get-WinEvent ... Id=4768
# 2. сессия у агента?         GET /api/v1/sessions
# 3. сессия у плагина?        configctl adidentity session-list
# 4. адрес в pf-таблице?      pfctl -t Managers -T show
# 5. правило firewall по этому alias существует и стоит выше запрещающих?
```

Типовое:

| Симптом | Что делать |
|---|---|
| Сессия есть, адреса в таблице нет | `configctl adidentity reproject` |
| В таблице лишний адрес | `configctl adidentity expire` |
| Просроченное не уходит | Не нажали **Apply** — нет задачи в cron |
| После ребута таблица пуста | Проверить хук `99-adidentity` и `reproject` в логе configd |
| `groups=0` в логе агента | `BaseDn`, `MonitoredGroups` или членство в AD |
| Агент не стартует, `Refusing to push` | `AllowInsecureTransport: true` при `http://` |
| 401 с правильным токеном | IP DC нет в `Allowed source IPs` (или список битый) |
| Пустой ответ API плагина | Синтаксис Python: `python3 -m py_compile ...` |

## Важное, о чём легко забыть

- Поле **Content** у alias типа External всегда пустое — смотреть только `pfctl`.
- Срок жизни сессии задаёт **агент** (`SessionTtlSec`), поле TTL в UI плагина
  применяется лишь к сессиям без `expires_at`.
- **Apply** в UI обязателен после установки: он пишет `adidentity.conf` и
  регистрирует cron.
- Плагин **не создаёт правила firewall** — только алиасы.
- Вызовы плагина видны в `/var/log/configd/latest.log`, в `/var/log/system/` их нет.
