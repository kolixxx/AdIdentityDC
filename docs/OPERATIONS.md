# AdIdentity: руководство по обслуживанию

Для того, кто обслуживает уже установленную систему: как проверить, что всё работает, что перезапустить и что делать при типовых ошибках.

В командах замените значения в угловых скобках на свои: `<IP_коллектора>`, `<IP_OPNsense>`, `<ТОКЕН>`.

## Содержание

1. [Что это и как устроено](#1-что-это-и-как-устроено)
2. [Где что лежит](#2-где-что-лежит)
3. [Как проверить, что всё работает](#3-как-проверить-что-всё-работает)
4. [Как работает учёт](#4-как-работает-учёт)
5. [Типовые операции](#5-типовые-операции)
6. [Неисправности](#6-неисправности)
7. [Установка компонента заново](#7-установка-компонента-заново)
8. [Ограничения](#8-ограничения)

## 1. Что это и как устроено

Система наполняет алиасы OPNsense IP-адресами пользователей Active Directory. Админ пишет правила firewall с этими алиасами. Сама система правил не создаёт.

```
DC1, DC2 ... (Sensor) --события входа--> Коллектор :8443 --сессии--> OPNsense (плагин)
                                         Коллектор :8443 <--Resync-- OPNsense
```

| Компонент | Где работает | Что делает |
|---|---|---|
| Sensor | на каждом контроллере домена | Читает журнал Security (входы Kerberos) и отправляет события на коллектор. |
| Collector | на одном сервере в домене | Принимает события, узнаёт группы пользователя через LDAP, хранит сессии «пользователь — IP», отправляет их на OPNsense. |
| Плагин AdIdentity | OPNsense | Принимает сессии и заполняет алиасы: групповые и/или `u_<логин>`. |

Sensor и Collector — одна и та же программа. Роль задаётся строкой `"Role"` в файле настроек. Служба Windows в обоих случаях называется `AdIdentityAgent`.

Сетевые порты:

- DC → коллектор: TCP 8443 (http).
- Коллектор → OPNsense: 443 (https) или 80 (http), как открывается GUI.
- OPNsense → коллектор: TCP 8443 (кнопка Resync).

Все три стороны используют один общий токен (Shared token).

## 2. Где что лежит

### Windows (коллектор и DC)

| Что | Где |
|---|---|
| Программа | `C:\AdIdentity\` |
| Настройки | `C:\AdIdentity\appsettings.json` (содержит токен, никому не пересылать) |
| Сессии (только коллектор) | `C:\ProgramData\AdIdentity\sessions.json`, `login-memory.json` |
| Журнал ошибок | Просмотр событий → Журналы Windows → Приложение, источник `AdIdentity*`. Пишутся предупреждения и ошибки, отдельных лог-файлов нет. |
| Служба | `AdIdentityAgent`: запуск автоматический, перезапуск через минуту после сбоя |

### OPNsense

| Что | Где |
|---|---|
| Настройки плагина | GUI: Firewall → AdIdentity → Settings (или `https://<IP_OPNsense>/ui/adidentity`) |
| Алиасы | GUI: Firewall → Aliases, тип External (advanced), описание «AdIdentity managed» |
| Сессии | `/var/db/adidentity/` |
| Очистка истёкших сессий | задача cron «AdIdentity: expire timed-out sessions», раз в 2 минуты (System → Settings → Cron) |
| Восстановление алиасов при загрузке | `/usr/local/etc/rc.syshook.d/start/99-adidentity` |

## 3. Как проверить, что всё работает

Выполняйте по порядку. Остановитесь на первом шаге, который не прошёл, и переходите к разделу 6.

**Шаг 1. Службы запущены** (на коллекторе и каждом DC, PowerShell):

```powershell
Get-Service AdIdentityAgent
```

Ожидается `Running`.

**Шаг 2. Коллектор отвечает** (на коллекторе):

```powershell
$token = '<ТОКЕН>'
Invoke-RestMethod "http://127.0.0.1:8443/api/v1/health" -Headers @{ Authorization = "Bearer $token" }
```

Ожидается `status = ok`, `role = Collector`, `sessions` — число текущих сессий.

**Шаг 3. Сессии приходят с DC** (на коллекторе):

```powershell
$s = (Invoke-RestMethod "http://127.0.0.1:8443/api/v1/sessions" -Headers @{ Authorization = "Bearer $token" }).sessions
$s | Select-Object user, ip, dc, ts, @{n='groups';e={$_.groups.Count}} | ft
```

Должны быть сессии от каждого DC (колонка `dc`), `groups` больше нуля. Время `ts` — в UTC.

**Шаг 4. Сессии дошли до OPNsense** (SSH на OPNsense, пункт 8 Shell):

```sh
configctl adidentity session-list
```

Ожидается `"status": "ok"` и те же пользователи.

**Шаг 5. Алиас содержит IP** (на OPNsense):

```sh
pfctl -s Tables | grep u_
pfctl -t u_<логин> -T show
```

**Шаг 6. Нет свежих ошибок** (на коллекторе):

```powershell
Get-EventLog -LogName Application -After (Get-Date).AddHours(-1) -Source *AdIdentity* -ErrorAction SilentlyContinue | ft TimeGenerated, EntryType, Message -Wrap
```

Пусто — ошибок за последний час нет.

## 4. Как работает учёт

Это важно для понимания большинства «ошибок».

- Сессия появляется при входе пользователя в домен (событие Kerberos 4768; для RDP — 4624 тип 10). Событие 4769 (обращение к сервисам) сессию не создаёт, а только продлевает уже существующую.
- У одного пользователя один IP. При входе с другого IP запись переносится.
- Если на IP входит другой пользователь, IP переходит к нему и уходит из алиасов предыдущего.
- **Выход из системы не отслеживается.** Сессия живёт, пока пользователь активен, и удаляется через `Session TTL` (по умолчанию 43200 секунд = 12 часов) после последней активности.
- Компьютерные учётки (имя заканчивается на `$`) игнорируются.
- Коллектор раз в 2 минуты повторно отправляет сессии на OPNsense — так OPNsense догоняет после кратких сбоев связи.
- Имена групп и логинов, из которых делаются алиасы, должны быть латиницей. Кириллические отклоняются, алиас не создаётся.

## 5. Типовые операции

### Перезапустить службу (коллектор или DC)

```powershell
Restart-Service AdIdentityAgent
Get-Service AdIdentityAgent
```

Сессии коллектора сохраняются на диске и переживают перезапуск.

### Подтянуть всё с коллектора на OPNsense

GUI плагина → **Resync from Agent**. Галочка у кнопки — успешно.

Если на коллекторе 0 сессий, а на OPNsense есть, Resync откажется их стирать. Это защита: подождите, пока коллектор наберёт сессии после рестарта.

### Пересобрать содержимое алиасов из сохранённых сессий (OPNsense)

```sh
configctl adidentity reproject
```

В ответе `errors: []` — без ошибок.

### Изменить настройки коллектора или сенсора

1. Отредактировать `C:\AdIdentity\appsettings.json` (Блокнот от администратора).
2. `Restart-Service AdIdentityAgent`.
3. Если служба не стартует — см. раздел 6.1. Чаще всего это опечатка в JSON: лишняя или пропущенная запятая, кавычка.

Основные параметры коллектора:

| Параметр | Значение |
|---|---|
| `PluginBaseUrl` | адрес GUI OPNsense, как в браузере |
| `PluginIgnoreSslErrors` | `true`, если у OPNsense самоподписанный сертификат |
| `MonitoredGroups` | `[]` — все группы; `["VPN_Users","Sales"]` — только эти |
| `Ldap.Host`, `Ldap.BaseDn` | контроллер домена для LDAP и корень поиска |
| `Ldap.UserSearchBases` | `[]` — все пользователи; список OU — только из них (есть не во всех сборках) |
| `SessionTtlSec` | время жизни сессии без активности, секунды |

У сенсора важны только `CollectorBaseUrl` (`http://<IP_коллектора>:8443`) и `SharedToken`.

### Изменить режим алиасов (OPNsense)

GUI плагина → поменять поля → **Apply** → **Resync from Agent**.

- Только алиасы на пользователей: `Monitored groups` = несуществующая группа (например `none`), `Enable user aliases` включено.
- Алиасы по группам: `Monitored groups` = список групп (как в AD, латиницей).
- Пустое `Monitored groups` означает **все** группы всех пользователей (сотни алиасов). Так делать не нужно.

### Сменить токен

Один и тот же новый токен — во всех местах, иначе связь прервётся.

1. Сгенерировать:

   ```powershell
   $b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); -join ($b | % { $_.ToString('x2') })
   ```

2. Вписать в `SharedToken` на коллекторе и на каждом DC, выполнить `Restart-Service AdIdentityAgent` на каждом.
3. Вписать в **Shared token** плагина → **Apply**.
4. Проверить по разделу 3.

### Добавить новый контроллер домена

На новом DC повторить установку сенсора (раздел 7). На коллекторе добавить IP нового DC в правило Windows Firewall:

```powershell
$r = Get-NetFirewallRule -DisplayName "AdIdentity 8443" | Get-NetFirewallAddressFilter
Set-NetFirewallRule -DisplayName "AdIdentity 8443" -RemoteAddress (@($r.RemoteAddress) + '<IP_нового_DC>')
```

Без сенсора на каком-либо DC часть входов не будет видна: события Security между DC не реплицируются.

### Обновить программу (коллектор или DC)

1. `Stop-Service AdIdentityAgent`
2. Скопировать содержимое папки `agent` из нового комплекта поверх `C:\AdIdentity\`. В комплекте нет `appsettings.json`, рабочие настройки не затрутся.
3. `Start-Service AdIdentityAgent`, проверить по разделу 3.

### Переустановить или обновить плагин (OPNsense)

Скопировать папку `plugin` из комплекта (с компьютера администратора):

```powershell
scp -r plugin root@<IP_OPNsense>:/root/adidentity-plugin
```

Запустить установщик на OPNsense. Повторный запуск безопасен: настройки и сессии сохраняются.

```sh
sh /root/adidentity-plugin/install.sh
```

Удаление файлов плагина: `sh /root/adidentity-plugin/install.sh --uninstall`. Алиасы, правила и настройки остаются.

## 6. Неисправности

### 6.1 Служба не запускается

Запустить программу в консоли — ошибка будет видна на экране:

```powershell
Stop-Service AdIdentityAgent
C:\AdIdentity\AdIdentity.Agent.Service.exe
```

Ctrl+C — выход, затем `Start-Service AdIdentityAgent`.

| Сообщение или признак | Что сделать |
|---|---|
| ошибка разбора JSON | исправить `appsettings.json` (запятые, кавычки, скобки) |
| `http://` не разрешён (insecure transport) | в настройках `"AllowInsecureTransport": true`, если адрес начинается с `http://` |
| порт 8443 занят | найти процесс: `netstat -ano \| findstr :8443`, второй экземпляр программы закрыть |
| `Config not found` при установке службы | нет файла `C:\AdIdentity\appsettings.json` |

### 6.2 На коллекторе нет новых сессий

1. Службы на DC запущены (`Get-Service AdIdentityAgent` на каждом DC).
2. С DC доступен коллектор:

   ```powershell
   Test-NetConnection <IP_коллектора> -Port 8443
   ```

   `False` — проверить правило Windows Firewall на коллекторе (раздел 5, «Добавить новый контроллер домена») или сетевой доступ.

3. Аудит Kerberos на DC включён:

   ```powershell
   auditpol /get /subcategory:"{0CCE9242-69AE-11D9-BED3-505054503030},{0CCE9240-69AE-11D9-BED3-505054503030}"
   ```

   Обе строки должны быть `Success`. Если нет — включить командами из раздела 7. Если аудит снова сбрасывается, он задан групповой политикой, и включать его надо в ней.

4. Токен на DC совпадает с токеном коллектора.
5. Сенсор видит только входы после своего запуска. Сразу после установки сессий мало — это нормально.

### 6.3 На коллекторе сессии есть, на OPNsense нет

Смотреть журнал коллектора (раздел 3, шаг 6).

| Ошибка в журнале | Причина и действие |
|---|---|
| `Plugin upsert failed: 401` | не совпадает токен в плагине, или IP коллектора не указан в **Allowed source IPs**, или плагин выключен (**Enable**) |
| ошибка соединения или таймаут | с коллектора недоступен OPNsense: `Test-NetConnection <IP_OPNsense> -Port 443`; проверить `PluginBaseUrl` |
| ошибка сертификата (SSL) | в настройках коллектора `"PluginIgnoreSslErrors": true`, перезапустить службу |

После исправления нажать **Resync from Agent**.

### 6.4 Сессии на OPNsense есть, алиаса нет или он пустой

- Включено **Auto-create aliases**.
- Для групповых алиасов: группа указана в **Monitored groups** точно как в AD.
- Для алиасов пользователей: включено **Enable user aliases**.
- Имя группы или логин на кириллице — алиас не создаётся (раздел 4).
- Выполнить `configctl adidentity reproject` и посмотреть поле `errors`.
- Обновить страницу алиасов в GUI: новые алиасы появляются по мере входов.

### 6.5 Нет пункта меню AdIdentity в GUI

Открыть напрямую `https://<IP_OPNsense>/ui/adidentity`. Сбросить кэш меню:

```sh
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json
configctl webgui restart
```

Пользователь GUI должен быть в группе `admins`.

### 6.6 Resync не работает

- Коллектор доступен с OPNsense: в правиле Windows Firewall на коллекторе должен быть адрес, с которого приходит OPNsense (обычно его интерфейс в сети коллектора или шлюз этой сети).
- **Agent base URL** = `http://<IP_коллектора>:8443`, токен совпадает.
- Отказ «refusing empty agent resync» — на коллекторе 0 сессий (раздел 5, «Подтянуть всё с коллектора на OPNsense»).

### 6.7 В алиасе «чужой» или устаревший IP

- Выход из системы не отслеживается: IP остаётся за пользователем до TTL или до входа на этот IP другого человека (раздел 4).
- Терминальные серверы (много пользователей с одного IP): IP принадлежит последнему вошедшему. Такие серверы не подходят для правил по пользователям.
- Если IP машины сменился (DHCP), запись обновится при следующем входе пользователя.

### 6.8 Один пользователь виден дважды

Если NetBIOS-имя домена не совпадает с первой частью DNS-имени, один пользователь может записаться под двумя вариантами домена. Алиас пользователя строится по логину, поэтому обе записи попадают в один `u_<логин>`.

## 7. Установка компонента заново

Комплект распаковать в `C:\Distr\AdIdentity`, все команды — в PowerShell от администратора.

**1. Программа:**

```powershell
cd C:\Distr\AdIdentity
Get-ChildItem -Recurse | Unblock-File
New-Item -ItemType Directory C:\AdIdentity -Force | Out-Null
Copy-Item .\agent\* C:\AdIdentity -Recurse -Force
```

**2. Настройки:** шаблон из папки `config` (`appsettings.collector.json` или `appsettings.sensor.json`) скопировать в `C:\AdIdentity\appsettings.json` и заполнить (раздел 5).

**3. Только на DC — аудит:**

```powershell
auditpol /set /subcategory:"{0CCE9242-69AE-11D9-BED3-505054503030}" /success:enable
auditpol /set /subcategory:"{0CCE9240-69AE-11D9-BED3-505054503030}" /success:enable
```

**4. Только на коллекторе — порт** (IP всех DC, OPNsense и его адреса в сети коллектора):

```powershell
New-NetFirewallRule -DisplayName "AdIdentity 8443" -Direction Inbound -Protocol TCP -LocalPort 8443 -RemoteAddress <IP_DC1>,<IP_DC2>,<IP_OPNsense> -Action Allow
```

**5. Служба:**

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Install-AdIdentityService.ps1 -InstallDir C:\AdIdentity -Start
```

**6. Проверка** — раздел 3.

## 8. Ограничения

- Коллектор один. Пока он выключен, события входа не собираются (сенсоры их не копят). Алиасы на OPNsense остаются и истекают по TTL.
- Один пользователь — один IP.
- Выход из системы не отслеживается, только TTL.
- Имена для алиасов — только латиница.
- История «кто был на IP» не хранится: коллектор и OPNsense знают только текущее состояние.
