#Requires -Version 5.1
<#
.SYNOPSIS
  Ship AdIdentity Collector sessions to OpenSearch as user <-> IP ownership intervals.

.DESCRIPTION
  Polls GET /api/v1/sessions on the Collector (the same snapshot the OPNsense plugin
  uses for Resync) and keeps one OpenSearch document per interval "this account held
  this IP": start, last_seen, end. NetFlow records can then be joined on
  ip + flow time between start and end (or last_seen while the interval is open).

  The Collector itself is not modified. If the Collector is unreachable, nothing is
  closed: a missing snapshot is not evidence that users left.

.PARAMETER ConfigPath
  JSON config, see config.example.json.

.PARAMETER Once
  Run a single poll and exit (otherwise loop every PollSeconds).

.PARAMETER InitIndex
  Create/replace the index template (field types: ip, date, keyword) and exit.

.PARAMETER DryRun
  Do not contact OpenSearch; print the _bulk body instead.

.PARAMETER SnapshotPath
  Test only: read the sessions JSON from a file instead of the Collector API.

.EXAMPLE
  .\Export-AdIdentityToOpenSearch.ps1 -InitIndex
  .\Export-AdIdentityToOpenSearch.ps1 -Once
  .\Export-AdIdentityToOpenSearch.ps1
#>
param(
    [string] $ConfigPath = (Join-Path $PSScriptRoot 'config.json'),
    [switch] $Once,
    [switch] $InitIndex,
    [switch] $DryRun,
    [string] $SnapshotPath
)

$ErrorActionPreference = 'Stop'

function Get-Setting($cfg, [string] $name, $default) {
    $prop = $cfg.PSObject.Properties[$name]
    if ($null -eq $prop -or $null -eq $prop.Value -or "$($prop.Value)" -eq '') {
        return $default
    }
    return $prop.Value
}

function Read-ExportConfig([string] $path) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Config not found: $path (copy config.example.json to config.json)"
    }
    $raw = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    $dataDir = Join-Path $env:ProgramData 'AdIdentity'

    $cfg = [pscustomobject]@{
        CollectorUrl         = ([string](Get-Setting $raw 'CollectorUrl' 'http://127.0.0.1:8443')).TrimEnd('/')
        CollectorToken       = [string](Get-Setting $raw 'CollectorToken' '')
        OpenSearchUrl        = ([string](Get-Setting $raw 'OpenSearchUrl' '')).TrimEnd('/')
        OpenSearchUser       = [string](Get-Setting $raw 'OpenSearchUser' '')
        OpenSearchPassword   = [string](Get-Setting $raw 'OpenSearchPassword' '')
        IndexName            = [string](Get-Setting $raw 'IndexName' 'adidentity-sessions')
        SkipCertificateCheck = [bool](Get-Setting $raw 'SkipCertificateCheck' $false)
        PollSeconds          = [int](Get-Setting $raw 'PollSeconds' 60)
        StateFile            = [string](Get-Setting $raw 'StateFile' (Join-Path $dataDir 'opensearch-export-state.json'))
        LogFile              = [string](Get-Setting $raw 'LogFile' (Join-Path $dataDir 'opensearch-export.log'))
    }

    # Secrets may come from the environment so config.json can stay secret-free.
    if ($env:ADIDENTITY_TOKEN) { $cfg.CollectorToken = $env:ADIDENTITY_TOKEN }
    if ($env:OPENSEARCH_PASSWORD) { $cfg.OpenSearchPassword = $env:OPENSEARCH_PASSWORD }

    if ($cfg.PollSeconds -lt 10) { $cfg.PollSeconds = 10 }
    return $cfg
}

function Write-Log([string] $level, [string] $message) {
    $line = '{0} [{1}] {2}' -f ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')), $level, $message
    Write-Host $line
    if ($script:Cfg -and $script:Cfg.LogFile) {
        try {
            $dir = Split-Path -Parent $script:Cfg.LogFile
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Add-Content -LiteralPath $script:Cfg.LogFile -Value $line -Encoding UTF8
        } catch {
            # Logging must never stop the export.
        }
    }
}

function ConvertTo-IsoUtc($value) {
    if ($null -eq $value) { return $null }
    if ($value -is [DateTime]) { return $value.ToUniversalTime().ToString('o') }
    return [string]$value
}

function Get-StableId([string] $text) {
    $sha = [System.Security.Cryptography.SHA1]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text))
        return ([BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-OpenSearchHeaders {
    $headers = @{}
    if ($script:Cfg.OpenSearchUser) {
        $pair = '{0}:{1}' -f $script:Cfg.OpenSearchUser, $script:Cfg.OpenSearchPassword
        $headers['Authorization'] = 'Basic ' + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($pair))
    }
    return $headers
}

function Invoke-OpenSearch([string] $method, [string] $path, [string] $body, [string] $contentType) {
    if (-not $script:Cfg.OpenSearchUrl) { throw 'OpenSearchUrl is not set in config' }
    $params = @{
        Method      = $method
        Uri         = $script:Cfg.OpenSearchUrl + $path
        Headers     = (Get-OpenSearchHeaders)
        TimeoutSec  = 30
        ErrorAction = 'Stop'
    }
    if ($null -ne $body) {
        # PS 5.1 encodes string bodies as ISO-8859-1; send UTF-8 bytes explicitly.
        $params['Body'] = [System.Text.Encoding]::UTF8.GetBytes($body)
        $params['ContentType'] = $contentType
    }
    return Invoke-RestMethod @params
}

function Initialize-IndexTemplate {
    $template = @{
        index_patterns = @("$($script:Cfg.IndexName)*")
        template       = @{
            mappings = @{
                properties = @{
                    '@timestamp'    = @{ type = 'date' }
                    start           = @{ type = 'date' }
                    end             = @{ type = 'date' }
                    last_seen       = @{ type = 'date' }
                    expires_at      = @{ type = 'date' }
                    ip              = @{ type = 'ip' }
                    user            = @{ type = 'keyword' }
                    domain          = @{ type = 'keyword' }
                    account         = @{ type = 'keyword' }
                    groups          = @{ type = 'keyword' }
                    dc              = @{ type = 'keyword' }
                    open            = @{ type = 'boolean' }
                    close_reason    = @{ type = 'keyword' }
                    collector_event = @{ type = 'keyword' }
                }
            }
        }
    } | ConvertTo-Json -Depth 10

    if ($DryRun) {
        Write-Host $template
        return
    }
    Invoke-OpenSearch 'PUT' "/_index_template/$($script:Cfg.IndexName)" $template 'application/json; charset=utf-8' | Out-Null
    Write-Log 'INFO' "Index template '$($script:Cfg.IndexName)' applied"
}

function Get-CollectorSessions {
    if ($SnapshotPath) {
        $resp = Get-Content -LiteralPath $SnapshotPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } else {
        if (-not $script:Cfg.CollectorToken) { throw 'CollectorToken is not set (config or ADIDENTITY_TOKEN)' }
        $resp = Invoke-RestMethod -Method Get `
            -Uri ($script:Cfg.CollectorUrl + '/api/v1/sessions') `
            -Headers @{ Authorization = "Bearer $($script:Cfg.CollectorToken)" } `
            -TimeoutSec 15 -ErrorAction Stop
    }
    if ($null -eq $resp -or $null -eq $resp.PSObject.Properties['sessions']) {
        throw 'Collector response has no "sessions" field'
    }
    return @($resp.sessions)
}

function Read-State {
    $state = @{ open = @{}; pending = @{} }
    $path = $script:Cfg.StateFile
    if (-not (Test-Path -LiteralPath $path)) { return $state }
    $raw = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($o in @($raw.open)) { if ($o) { $state.open[[string]$o.key] = $o } }
    foreach ($d in @($raw.pending)) { if ($d) { $state.pending[[string]$d.id] = $d } }
    return $state
}

function Save-State($state) {
    $path = $script:Cfg.StateFile
    $dir = Split-Path -Parent $path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $payload = [pscustomobject]@{
        open    = @($state.open.Values)
        pending = @($state.pending.Values)
    }
    $tmp = "$path.tmp"
    $payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $path -Force
}

function New-IntervalDoc($interval, [bool] $isOpen, $end, $reason) {
    return [pscustomobject]@{
        id     = $interval.id
        source = [pscustomobject]@{
            '@timestamp'    = $interval.start
            start           = $interval.start
            end             = $end
            last_seen       = $interval.last_seen
            expires_at      = $interval.expires_at
            open            = $isOpen
            close_reason    = $reason
            user            = $interval.user
            domain          = $interval.domain
            account         = '{0}\{1}' -f $interval.domain, $interval.user
            ip              = $interval.ip
            groups          = @($interval.groups)
            dc              = $interval.dc
            collector_event = $interval.event
        }
    }
}

function Get-BoundaryEnd($interval, $successorTs, [string] $now) {
    # The logon that took over the IP is the exact end of the previous holder;
    # fall back to poll time if that timestamp is missing or out of order.
    if (-not $successorTs) { return $now }
    try {
        $s = [DateTime]::Parse($successorTs, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
        $b = [DateTime]::Parse([string]$interval.start, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
        if ($s -ge $b) { return $successorTs }
    } catch {
    }
    return $now
}

function Invoke-Poll($state) {
    $sessions = Get-CollectorSessions
    $now = [DateTime]::UtcNow.ToString('o')

    $current = @{}
    foreach ($s in $sessions) {
        if (-not $s.user -or -not $s.ip) { continue }
        $key = ('{0}\{1}' -f $s.domain, $s.user).ToLowerInvariant()
        $current[$key] = $s
    }
    $byIp = @{}
    foreach ($s in $current.Values) { $byIp[[string]$s.ip] = $s }

    $opened = 0; $closed = 0
    $docs = New-Object System.Collections.Generic.List[object]

    foreach ($key in @($state.open.Keys)) {
        $interval = $state.open[$key]
        $reason = $null
        $end = $now
        if (-not $current.ContainsKey($key)) {
            # D1 on the Collector evicts the old holder when someone else logs on
            # from the same IP; otherwise the session aged out by TTL.
            if ($byIp.ContainsKey([string]$interval.ip)) {
                $reason = 'ip_reassigned'
                $end = Get-BoundaryEnd $interval (ConvertTo-IsoUtc $byIp[[string]$interval.ip].ts) $now
            } else {
                $reason = 'session_ended'
            }
        } elseif ([string]$current[$key].ip -ne [string]$interval.ip) {
            $reason = 'ip_changed'
            $end = Get-BoundaryEnd $interval (ConvertTo-IsoUtc $current[$key].ts) $now
        }
        if ($reason) {
            $docs.Add((New-IntervalDoc $interval $false $end $reason))
            $state.open.Remove($key)
            $closed++
        }
    }

    foreach ($key in $current.Keys) {
        $s = $current[$key]
        if ($state.open.ContainsKey($key)) {
            $interval = $state.open[$key]
        } else {
            $start = ConvertTo-IsoUtc $s.ts
            if (-not $start) { $start = $now }
            $interval = [pscustomobject]@{
                key        = $key
                id         = Get-StableId ('{0}|{1}|{2}' -f $key, $s.ip, $start)
                start      = $start
                user       = [string]$s.user
                domain     = [string]$s.domain
                ip         = [string]$s.ip
                groups     = @()
                dc         = $null
                event      = $null
                expires_at = $null
                last_seen  = $null
            }
            $state.open[$key] = $interval
            $opened++
        }
        $interval.groups = @($s.groups)
        $interval.dc = [string]$s.dc
        $interval.event = [string]$s.event
        $interval.expires_at = ConvertTo-IsoUtc $s.expires_at
        $interval.last_seen = $now
        $docs.Add((New-IntervalDoc $interval $true $null $null))
    }

    # Pending holds the latest version of every doc not yet accepted by OpenSearch;
    # the bulk "index" action replaces by _id, so resending is idempotent.
    foreach ($d in $docs) { $state.pending[[string]$d.id] = $d }
    Save-State $state

    Send-Pending $state
    Write-Log 'INFO' ("Poll ok: sessions={0} open={1} opened={2} closed={3}" -f $current.Count, $state.open.Count, $opened, $closed)
}

function Send-Pending($state) {
    if ($state.pending.Count -eq 0) { return }

    $sb = New-Object System.Text.StringBuilder
    foreach ($d in $state.pending.Values) {
        $action = @{ index = @{ _index = $script:Cfg.IndexName; _id = [string]$d.id } } | ConvertTo-Json -Compress -Depth 4
        [void]$sb.Append($action).Append("`n")
        [void]$sb.Append(($d.source | ConvertTo-Json -Compress -Depth 6)).Append("`n")
    }
    $body = $sb.ToString()

    if ($DryRun) {
        Write-Host '--- _bulk (dry run) ---'
        Write-Host $body
        $state.pending.Clear()
        Save-State $state
        return
    }

    try {
        $resp = Invoke-OpenSearch 'POST' '/_bulk' $body 'application/x-ndjson; charset=utf-8'
    } catch {
        Write-Log 'WARN' ("OpenSearch unreachable, {0} doc(s) kept for retry: {1}" -f $state.pending.Count, $_.Exception.Message)
        return
    }

    if ($resp.errors) {
        $failed = @($resp.items | ForEach-Object { $_.index } | Where-Object { $_.error })
        $first = ''
        if ($failed.Count -gt 0) { $first = ($failed[0].error | ConvertTo-Json -Compress -Depth 4) }
        Write-Log 'WARN' ("OpenSearch rejected {0} doc(s), kept for retry. First error: {1}" -f $failed.Count, $first)
        $ok = @($resp.items | ForEach-Object { $_.index } | Where-Object { -not $_.error } | ForEach-Object { [string]$_._id })
        foreach ($id in $ok) { $state.pending.Remove($id) }
    } else {
        $state.pending.Clear()
    }
    Save-State $state
}

$script:Cfg = Read-ExportConfig $ConfigPath

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
if ($script:Cfg.SkipCertificateCheck) {
    # Lab/self-signed OpenSearch only.
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}

if ($InitIndex) {
    Initialize-IndexTemplate
    return
}

$state = Read-State
Write-Log 'INFO' ("Export started: collector={0} opensearch={1} index={2} poll={3}s" -f `
    $script:Cfg.CollectorUrl, $script:Cfg.OpenSearchUrl, $script:Cfg.IndexName, $script:Cfg.PollSeconds)

while ($true) {
    try {
        Invoke-Poll $state
    } catch {
        # Collector down or bad response: skip this round, close nothing.
        Write-Log 'WARN' ("Poll skipped: {0}" -f $_.Exception.Message)
    }
    if ($Once) { break }
    Start-Sleep -Seconds $script:Cfg.PollSeconds
}
