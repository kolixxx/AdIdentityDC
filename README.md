# AdIdentity (OPNsense plugin + Windows Agent)

Pilot project: map Active Directory logons to OPNsense **Aliases** so admins can write firewall rules by **AD group** (and optionally by user).

```
AD login event -> Agent (user+ip+groups) -> Plugin -> Aliases -> Firewall Rules (admin)
```

## Repository layout

```
docs/quickstart.adoc  install in one pass (start here)
docs/                 AsciiDoc (filled with settled facts over time)
plugin/               OPNsense plugin (OPNsense\AdIdentity)
agent/                Windows Agent (.NET 8 Worker / Windows Service)
.cursor/rules/        Project guidance for the agent
```

## Install

Start with **[docs/quickstart.adoc](docs/quickstart.adoc)** — one pass, in order,
with the exact commands and a config template.

```sh
# OPNsense, as root
git clone https://github.com/kolixxx/AdIdentityDC.git /root/AdIdentityDC
cd /root/AdIdentityDC && ./plugin/install.sh
```

The agent is deployed as the **published build** (`dotnet publish ... --self-contained`)
copied to the DC and registered as a Windows Service; see the quick start.

## Pilot contract

See [docs/reference.adoc](docs/reference.adoc) for locked API fields, endpoints, alias naming, and UI settings.

Key endpoints:

- Plugin: `POST /api/adidentity/session/upsert|remove` — `Authorization: Bearer <shared_token>`
- Plugin: `POST /api/adidentity/service/resync` — UI session or OPNsense API key (**not** the shared token)
- Agent: `GET /api/v1/health`, `GET /api/v1/sessions` — Bearer shared token

## Status

Lab-verified end to end on 1 DC + OPNsense: logon → session → pf alias table →
firewall rule, including TTL expiry, retry/resync, pf self-healing and
activity-based refresh.

- Plugin: upsert/remove, replace-all resync, periodic expiry, pf table reconcile
- Plugin: projects IPs into pf alias tables; auto-creates External aliases
- Agent: Security Event Log collector, LDAP group resolver (nested), file-backed
  session store, retry with backoff, periodic re-push
- Transport: certificate validation on by default; refuses to send the token
  over plain HTTP to a remote host unless explicitly allowed

## Known limits (v1)

- An IP keeps its rights until TTL expires even if a non-domain device took over
  the address (accepted risk, see [docs/overview.adoc](docs/overview.adoc))
- AD group/user names used as aliases must be ASCII
- Multiple DCs need a collector — [docs/multi-dc.adoc](docs/multi-dc.adoc)

Full plan, defects and decisions: [PROJECT_STATE.md](PROJECT_STATE.md).
