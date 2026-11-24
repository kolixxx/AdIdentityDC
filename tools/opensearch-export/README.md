# AdIdentity → OpenSearch export

Отдельный скрипт, основной продукт не меняет. Забирает с коллектора
`GET /api/v1/sessions` (тот же снимок, что берёт Resync плагина) и пишет в
OpenSearch **интервалы владения IP**: кто держал адрес, с какого и по какое
время. По ним NetFlow-записи сопоставляются с пользователями.

## Что лежит в индексе

Один документ = один интервал «учётка держала этот IP».

| Поле | Смысл |
|---|---|
| `ip` | адрес клиента (тип `ip`) |
| `account`, `user`, `domain`, `groups` | кто |
| `start` | логин / первое событие на DC (`ts` сессии) |
| `last_seen` | последний опрос, где сессия ещё была |
| `end` | закрытие интервала; `null`, пока `open: true` |
| `close_reason` | `ip_reassigned` (на IP вошёл другой — граница точная), `ip_changed`, `session_ended` (TTL) |
| `dc` | с какого DC узнали |

Точность: `end` при `session_ended` — время опроса после истечения TTL
(logout AD не сообщает). При `ip_reassigned` — время логина следующего
пользователя.

## Установка (на хосте коллектора)

```powershell
New-Item -ItemType Directory C:\AdIdentity\opensearch-export -Force
# скопировать сюда Export-AdIdentityToOpenSearch.ps1 и config.example.json
cd C:\AdIdentity\opensearch-export
Copy-Item config.example.json config.json
notepad config.json     # URL OpenSearch, логин/пароль, shared token коллектора

# секреты в файле — закрыть доступ всем, кроме SYSTEM и админов
icacls config.json /inheritance:r /grant:r "SYSTEM:F" "Administrators:F"

# один раз: типы полей (ip, date, keyword)
powershell -ExecutionPolicy Bypass -File .\Export-AdIdentityToOpenSearch.ps1 -InitIndex
# пробный опрос
powershell -ExecutionPolicy Bypass -File .\Export-AdIdentityToOpenSearch.ps1 -Once
```

Постоянная работа — задача планировщика от SYSTEM:

```powershell
$a = New-ScheduledTaskAction -Execute 'powershell.exe' `
  -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\AdIdentity\opensearch-export\Export-AdIdentityToOpenSearch.ps1"'
$tr = New-ScheduledTaskTrigger -AtStartup
$set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
  -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'AdIdentity OpenSearch Export' -Action $a -Trigger $tr `
  -Settings $set -User 'SYSTEM' -RunLevel Highest
Start-ScheduledTask 'AdIdentity OpenSearch Export'
```

Лог: `%ProgramData%\AdIdentity\opensearch-export.log`.
Состояние (открытые интервалы и очередь на отправку):
`%ProgramData%\AdIdentity\opensearch-export-state.json`.

Секреты можно не держать в файле: переменные окружения `ADIDENTITY_TOKEN`
и `OPENSEARCH_PASSWORD` имеют приоритет над `config.json`.

## Поведение при сбоях

* Коллектор недоступен — опрос пропускается, интервалы **не закрываются**.
* OpenSearch недоступен или отклонил документы — они остаются в очереди и
  уходят следующим опросом; повтор идемпотентен (`_id` стабильный).

## Кто держал IP в момент T

```json
GET adidentity-sessions/_search
{
  "query": {
    "bool": {
      "filter": [
        { "term":  { "ip": "10.0.1.10" } },
        { "range": { "start": { "lte": "2026-11-21T10:15:00Z" } } }
      ],
      "should": [
        { "range": { "end": { "gte": "2026-11-21T10:15:00Z" } } },
        { "bool": { "must_not": { "exists": { "field": "end" } } } }
      ],
      "minimum_should_match": 1
    }
  }
}
```

Для NetFlow то же условие: `flow.src_ip = ip` и время потока между `start`
и `end` (у открытого интервала — `last_seen` / текущее время).

## Проверено

Без живого OpenSearch: подставные снимки коллектора (вход, refresh, смена
пользователя на IP, истечение, коллектор недоступен) и подставной HTTP-сервер
вместо OpenSearch (`_index_template`, `_bulk`, Basic, UTF-8, очередь при
недоступности). На реальном OpenSearch ещё не запускался.
