/*
 * AdIdentity dashboard widget (OPNsense 24.7+ modular dashboard).
 *
 * Joins three sources by IP address in the browser:
 *   /api/adidentity/session/list     who holds which address, alias names
 *   /api/adidentity/session/traffic  bytes / connections of open pf states
 *   /api/diagnostics/firewall/log    logged packets, read incrementally by digest
 */

const STALE_WARN_SEC = 600;
const STALE_ALERT_SEC = 1800;
const USER_ROWS = 10;
const LOG_ROWS = 15;
const TRAFFIC_EVERY_TICKS = 3;

function esc(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

export default class AdIdentity extends BaseTableWidget {
    constructor(config) {
        super(config);
        this.tickTimeout = 10;
        this.tick = 0;
        this.busy = false;
        this.sessions = new Map();
        this.lastPush = null;
        this.sessionError = null;
        this.traffic = {};
        this.trafficError = null;
        this.logDigest = '';
        this.logSeen = new Set();
        this.logRows = [];
        this.logError = null;
    }

    getGridOptions() {
        return {
            sizeToContent: 650
        };
    }

    getMarkup() {
        const t = this.translations;
        const $container = $('<div class="adidentity-widget"></div>');
        $container.append('<div id="adidentity-status" style="padding: 0.5em 0.5em 1em 0.5em;"></div>');

        $container.append(`<div style="padding-left: 0.5em;"><b>${t.users}</b></div>`);
        $container.append(this.createTable('adidentity-users', {
            headerPosition: 'top',
            headers: [t.user, t.ip, t.aliases, t.connections, t.traffic, t.logon]
        }));
        $container.append('<div id="adidentity-users-note" style="padding: 0 0.5em;"></div>');

        $container.append(`<div style="padding: 1.5em 0.5em 0 0.5em;"><b>${t.log}</b></div>`);
        $container.append(this.createTable('adidentity-log', {
            headerPosition: 'top',
            headers: [t.time, t.user, t.source, t.destination, t.rule]
        }));
        $container.append('<div id="adidentity-log-note" style="padding: 0 0.5em;"></div>');
        return $container;
    }

    async onWidgetTick() {
        // setInterval does not wait for a slow tick; never run two at once.
        if (this.busy) {
            return;
        }
        this.busy = true;
        try {
            await this._loadSessions();
            if (this.tick % TRAFFIC_EVERY_TICKS === 0) {
                await this._loadTraffic();
            }
            await this._loadLog();
            this.tick++;
            this._render();
        } finally {
            this.busy = false;
        }
    }

    async _loadSessions() {
        try {
            const data = await this.ajaxCall('/api/adidentity/session/list');
            if (!data || data.status !== 'ok') {
                this.sessionError = (data && data.message) ? data.message : this.translations.unavailable;
                return;
            }
            const map = new Map();
            for (const s of (data.sessions || [])) {
                if (s && s.ip) {
                    map.set(String(s.ip), s);
                }
            }
            this.sessions = map;
            this.lastPush = data.last_push_at || null;
            this.sessionError = null;
        } catch (e) {
            this.sessionError = this.translations.unavailable;
        }
    }

    async _loadTraffic() {
        try {
            const data = await this.ajaxCall('/api/adidentity/session/traffic');
            if (data && data.status === 'ok') {
                this.traffic = data.items || {};
                this.trafficError = null;
            } else {
                this.trafficError = (data && data.message) ? data.message : this.translations.unavailable;
            }
        } catch (e) {
            this.trafficError = this.translations.unavailable;
        }
    }

    async _loadLog() {
        const params = this.logDigest ? {limit: 1000, digest: this.logDigest} : {limit: 500};
        let records;
        try {
            records = await this.ajaxCall('/api/diagnostics/firewall/log', params);
            this.logError = null;
        } catch (e) {
            this.logError = this.translations.nolog;
            return;
        }
        if (!Array.isArray(records) || records.length === 0) {
            return;
        }

        // Newest first; the record matching the digest is returned again.
        this.logDigest = records[0].__digest__ || this.logDigest;
        const fresh = [];
        for (const r of records) {
            const digest = r.__digest__;
            if (!digest || this.logSeen.has(digest)) {
                continue;
            }
            this.logSeen.add(digest);
            const owner = this.sessions.get(String(r.src)) || this.sessions.get(String(r.dst));
            if (owner) {
                fresh.push({record: r, owner: owner});
            }
        }
        if (this.logSeen.size > 5000) {
            this.logSeen = new Set(records.map(r => r.__digest__));
        }
        this.logRows = fresh.concat(this.logRows).slice(0, LOG_ROWS);
    }

    _ageSeconds(iso) {
        const ms = Date.parse(iso);
        return isNaN(ms) ? null : Math.max(0, Math.round((Date.now() - ms) / 1000));
    }

    _formatAge(seconds) {
        const t = this.translations;
        if (seconds === null) {
            return '';
        }
        if (seconds < 60) {
            return `${seconds} ${t.sec}`;
        }
        if (seconds < 3600) {
            return `${Math.floor(seconds / 60)} ${t.min}`;
        }
        return `${Math.floor(seconds / 3600)} ${t.hour} ${Math.floor((seconds % 3600) / 60)} ${t.min}`;
    }

    _userCell(s) {
        return `<span title="${esc(s.domain)}\\${esc(s.user)}">${esc(s.user)}</span>`;
    }

    _aliasBadges(s) {
        return (s.aliases || [])
            .map(a => `<span class="badge" style="margin: 1px;">${esc(a)}</span>`)
            .join(' ');
    }

    _logTime(r) {
        const ts = String(r.__timestamp__ || '');
        const m = ts.match(/(\d{2}:\d{2}:\d{2})/);
        return esc(m ? m[1] : ts);
    }

    _endpoint(addr, port) {
        return port ? `${esc(addr)}:${esc(port)}` : esc(addr);
    }

    _renderStatus() {
        const t = this.translations;
        const $status = $('#adidentity-status');
        if (this.sessionError) {
            $status.html(`<i class="fa fa-circle text-danger"></i> ${esc(this.sessionError)}`);
            return;
        }

        const count = this.sessions.size;
        const age = this.lastPush ? this._ageSeconds(this.lastPush) : null;
        let color = 'text-success';
        if (count === 0) {
            color = 'text-muted';
        } else if (age === null || age > STALE_ALERT_SEC) {
            color = 'text-danger';
        } else if (age > STALE_WARN_SEC) {
            color = 'text-warning';
        }
        const pushText = age === null ? t.never : `${this._formatAge(age)} ${t.ago}`;
        $status.html(`
            <i class="fa fa-circle ${color}"></i>
            ${t.sessions}: <b>${count}</b>
            &nbsp;&middot;&nbsp;
            ${t.lastpush}: <b>${esc(pushText)}</b>
        `);
    }

    _renderUsers() {
        const t = this.translations;
        const rows = Array.from(this.sessions.values()).map(s => {
            const tr = this.traffic[String(s.ip)] || {bytes: 0, states: 0};
            return {s: s, bytes: Number(tr.bytes) || 0, states: Number(tr.states) || 0};
        });
        rows.sort((a, b) => (b.bytes - a.bytes) || String(a.s.user).localeCompare(String(b.s.user)));

        super.updateTable('adidentity-users', rows.slice(0, USER_ROWS).map(row => [
            this._userCell(row.s),
            esc(row.s.ip),
            this._aliasBadges(row.s),
            String(row.states),
            this._formatBytes(row.bytes) || '0 B',
            esc(this._formatAge(this._ageSeconds(row.s.ts)))
        ]));

        let note = '';
        if (rows.length === 0) {
            note = t.nosessions;
        } else if (rows.length > USER_ROWS) {
            note = `${t.shown} ${USER_ROWS} / ${rows.length}`;
        }
        if (this.trafficError) {
            note += (note ? ' · ' : '') + `${t.notraffic}: ${this.trafficError}`;
        }
        $('#adidentity-users-note').html(note ? `<small class="text-muted">${esc(note)}</small>` : '');
    }

    _renderLog() {
        const t = this.translations;
        super.updateTable('adidentity-log', this.logRows.map(({record: r, owner: s}) => {
            const icon = r.action === 'block'
                ? '<i class="fa fa-minus-circle text-danger"></i>'
                : r.action === 'pass'
                    ? '<i class="fa fa-play text-success"></i>'
                    : '<i class="fa fa-exchange text-info"></i>';
            const rule = r.label ? esc(r.label) : (r.rulenr ? `@${esc(r.rulenr)}` : '');
            return [
                `${icon} ${this._logTime(r)}`,
                this._userCell(s),
                this._endpoint(r.src, r.srcport),
                `${this._endpoint(r.dst, r.dstport)} ${esc(r.protoname || '')}`,
                r.rid ? `<a href="/ui/diagnostics/firewall/log?rid=${encodeURIComponent(r.rid)}" target="_blank">${rule}</a>` : rule
            ];
        }));

        let note = '';
        if (this.logError) {
            note = this.logError;
        } else if (this.logRows.length === 0) {
            note = t.nologrows;
        }
        $('#adidentity-log-note').html(note ? `<small class="text-muted">${esc(note)}</small>` : '');
    }

    _render() {
        this._renderStatus();
        this._renderUsers();
        this._renderLog();
    }
}
