# AdIdentity (OPNsense plugin + Windows Agent)

Pilot project: map Active Directory logons to OPNsense **Aliases** so admins can write firewall rules by **AD group** (and optionally by user).

```
AD login event -> Agent (user+ip+groups) -> Plugin -> Aliases -> Firewall Rules (admin)
```

## Repository layout

```
docs/                 AsciiDoc (filled with settled facts over time)
plugin/               OPNsense plugin (OPNsense\AdIdentity)
agent/                Windows Agent (.NET 8 Worker / Windows Service)
.cursor/rules/        Project guidance for the agent
```

## Pilot contract

See [docs/reference.adoc](docs/reference.adoc) for locked API fields, endpoints, alias naming, and UI settings.

Key endpoints:

- Plugin: `POST /api/adidentity/session/upsert|remove`
- Plugin: `POST /api/adidentity/service/resync`
- Agent: `GET /api/v1/health`, `GET /api/v1/sessions`
- Auth: `Authorization: Bearer <shared_token>`

## Status

- Plugin: session upsert/remove + full replace-all resync from Agent
- Plugin: projects IPs into pf alias tables; optional auto-create External aliases
- Agent: Security Event Log collector + LDAP group resolver
- **MVP is ready for first lab integration test** (1 DC + OPNsense)

## Next

1. Packaging / install steps for OPNsense plugin + Windows Service
2. Real lab test: DC login → alias → firewall rule
3. Hardening (TLS verify, logging)
