#!/usr/local/bin/python3
"""AdIdentity session store + pf alias table updates.

Persists sessions under /var/db/adidentity/sessions.json and projects
active IPs into OPNsense pf tables via:
  configctl filter add table <alias> <ip>
  configctl filter delete table <alias> <ip>
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_DIR = Path("/var/db/adidentity")
SESSIONS_FILE = DB_DIR / "sessions.json"
LOCK_FILE = DB_DIR / "sessions.lock"
CONF_FILE = Path("/usr/local/etc/adidentity.conf")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_ts(value: str | None) -> datetime | None:
    """Parse ISO-8601 timestamps from Agent (.NET round-trip) or Plugin.

    .NET ``DateTime.ToString("o")`` can emit 7 fractional digits; some Python
    builds accept only up to 6. Truncate the fraction so expire never silently
    fails and leaves sessions forever.
    """
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    # 2026-09-03T23:51:22.8259158+00:00 -> keep at most 6 fraction digits
    text = re.sub(r"\.(\d{6})\d+", r".\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    # A hand-edited sessions.json may lack the offset; comparing a naive value
    # against an aware "now" would raise instead of expiring the session.
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def load_conf() -> dict[str, str]:
    conf: dict[str, str] = {}
    if not CONF_FILE.exists():
        return conf
    for line in CONF_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        conf[key.strip()] = val.strip()
    return conf


def monitored_groups(conf: dict[str, str]) -> set[str]:
    raw = conf.get("monitored_groups", "")
    return {p.strip() for p in re.split(r"[\n,;]+", raw) if p.strip()}


def normalize_alias_name(name: str, force_prefix: str | None = None) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", name.strip())
    cleaned = re.sub(r"_+", "_", cleaned).strip("_") or "unknown"
    if force_prefix and not cleaned.lower().startswith(force_prefix.lower()):
        cleaned = f"{force_prefix}{cleaned}"
    if not re.match(r"^[A-Za-z]", cleaned):
        cleaned = f"g_{cleaned}"
    return cleaned[:64]


def ensure_dirs() -> None:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    if not SESSIONS_FILE.exists():
        SESSIONS_FILE.write_text(json.dumps({"sessions": []}, indent=2) + "\n", encoding="utf-8")


def acquire_lock(timeout_sec: float = 5.0) -> int:
    ensure_dirs()
    start = time.time()
    while True:
        try:
            fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            return fd
        except FileExistsError:
            if time.time() - start > timeout_sec:
                raise TimeoutError("session store lock timeout")
            time.sleep(0.05)


def release_lock(fd: int) -> None:
    try:
        os.close(fd)
    finally:
        try:
            LOCK_FILE.unlink(missing_ok=True)
        except OSError:
            pass


def load_sessions() -> list[dict[str, Any]]:
    ensure_dirs()
    try:
        data = json.loads(SESSIONS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    sessions = data.get("sessions", [])
    return sessions if isinstance(sessions, list) else []


def save_sessions(sessions: list[dict[str, Any]]) -> None:
    ensure_dirs()
    payload = {"sessions": sessions, "updated_at": utc_now().isoformat()}
    raw = json.dumps(payload, indent=2) + "\n"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=str(DB_DIR), delete=False) as tmp:
        tmp.write(raw)
        tmp_path = tmp.name
    os.replace(tmp_path, SESSIONS_FILE)


def session_key(user: str, domain: str) -> str:
    return f"{domain}\\{user}".lower()


def drop_sessions_for_ip(
    sessions: list[dict[str, Any]], ip: str, keep_key: str | None = None
) -> list[dict[str, Any]]:
    """Release an address held by anyone else.

    A recycled DHCP lease would otherwise let the new user inherit the previous
    user's group aliases until the old session hits its TTL.
    """
    if not ip:
        return sessions
    kept = []
    for s in sessions:
        key = session_key(str(s.get("user", "")), str(s.get("domain", "")))
        if key != keep_key and str(s.get("ip", "")).strip() == ip:
            continue
        kept.append(s)
    return kept


def is_valid_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_loopback or ip.is_unspecified)
    except ValueError:
        return False


def expire_sessions(
    sessions: list[dict[str, Any]], ttl_sec: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    now = utc_now()
    keep: list[dict[str, Any]] = []
    expired: list[dict[str, Any]] = []
    for s in sessions:
        exp = parse_ts(s.get("expires_at"))
        if exp is None and ttl_sec > 0:
            ts = parse_ts(s.get("ts"))
            if ts is not None:
                exp = datetime.fromtimestamp(ts.timestamp() + ttl_sec, tz=timezone.utc)
        if exp is not None and exp <= now:
            expired.append(s)
        else:
            keep.append(s)
    return keep, expired


def configctl_filter(op: str, alias: str, ip: str) -> tuple[bool, str]:
    cmd = (
        ["configctl", "filter", "add", "table", alias, ip]
        if op == "add"
        else ["configctl", "filter", "delete", "table", alias, ip]
    )
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
        return proc.returncode == 0, (proc.stdout or proc.stderr or "").strip()
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def desired_alias_ips(sessions: list[dict[str, Any]], conf: dict[str, str]) -> dict[str, set[str]]:
    groups_allow = monitored_groups(conf)
    enable_user = conf.get("enable_user_aliases", "0") in ("1", "true", "True", "yes")
    prefix = conf.get("user_alias_prefix", "u_") or "u_"

    mapping: dict[str, set[str]] = {}
    for s in sessions:
        ip = str(s.get("ip", "")).strip()
        if not is_valid_ip(ip):
            continue
        for g in s.get("groups", []) or []:
            gname = str(g).strip()
            if not gname:
                continue
            if groups_allow and gname not in groups_allow:
                continue
            mapping.setdefault(normalize_alias_name(gname), set()).add(ip)
        if enable_user:
            user = str(s.get("user", "")).strip()
            if user:
                mapping.setdefault(normalize_alias_name(user, force_prefix=prefix), set()).add(ip)
    return mapping


def apply_alias_projection(
    old_sessions: list[dict[str, Any]],
    new_sessions: list[dict[str, Any]],
    conf: dict[str, str],
) -> dict[str, Any]:
    before = desired_alias_ips(old_sessions, conf)
    after = desired_alias_ips(new_sessions, conf)
    all_aliases = set(before) | set(after)
    added = removed = 0
    errors: list[str] = []

    for alias in sorted(all_aliases):
        old_ips = before.get(alias, set())
        new_ips = after.get(alias, set())
        for ip in sorted(new_ips - old_ips):
            ok, msg = configctl_filter("add", alias, ip)
            if ok:
                added += 1
            else:
                errors.append(f"add {alias} {ip}: {msg or 'failed (alias missing?)'}")
        for ip in sorted(old_ips - new_ips):
            ok, msg = configctl_filter("delete", alias, ip)
            if ok:
                removed += 1
            else:
                errors.append(f"delete {alias} {ip}: {msg or 'failed'}")

    return {
        "aliases_touched": sorted(all_aliases),
        "ips_added": added,
        "ips_removed": removed,
        "errors": errors,
    }


def normalize_incoming_session(item: dict[str, Any], conf: dict[str, str], ttl: int) -> dict[str, Any] | None:
    user = str(item.get("user", "")).strip()
    domain = str(item.get("domain", "")).strip()
    ip = str(item.get("ip", "")).strip()
    groups = item.get("groups", [])
    if not user or not domain or not ip or not is_valid_ip(ip) or not isinstance(groups, list):
        return None

    allow = monitored_groups(conf)
    if allow:
        groups = [g for g in groups if str(g).strip() in allow]

    ts = str(item.get("ts") or utc_now().isoformat())
    expires_at = item.get("expires_at")
    if not expires_at:
        base = parse_ts(ts) or utc_now()
        expires_at = datetime.fromtimestamp(base.timestamp() + ttl, tz=timezone.utc).isoformat()

    return {
        "user": user,
        "domain": domain,
        "ip": ip,
        "groups": [str(g) for g in groups],
        "event": str(item.get("event", "login") or "login"),
        "ts": ts,
        "dc": item.get("dc"),
        "expires_at": expires_at,
    }


def upsert_session(payload: dict[str, Any]) -> dict[str, Any]:
    conf = load_conf()
    ttl = int(conf.get("session_ttl_sec") or 28800)
    normalized = normalize_incoming_session(payload, conf, ttl)
    if normalized is None:
        return {"status": "failed", "message": "invalid session payload"}

    lock = acquire_lock()
    try:
        sessions = load_sessions()
        sessions, _ = expire_sessions(sessions, ttl)
        old = [dict(s) for s in sessions]
        key = session_key(normalized["user"], normalized["domain"])

        remaining: list[dict[str, Any]] = []
        replaced = None
        for s in sessions:
            if session_key(str(s.get("user", "")), str(s.get("domain", ""))) == key:
                replaced = s
            else:
                remaining.append(s)
        remaining = drop_sessions_for_ip(remaining, normalized["ip"], keep_key=key)
        remaining.append(normalized)
        save_sessions(remaining)
        return {
            "status": "ok",
            "action": "updated" if replaced else "created",
            "session": normalized,
            "projection": apply_alias_projection(old, remaining, conf),
        }
    finally:
        release_lock(lock)


def remove_session(payload: dict[str, Any]) -> dict[str, Any]:
    conf = load_conf()
    ttl = int(conf.get("session_ttl_sec") or 28800)
    user = str(payload.get("user", "")).strip()
    domain = str(payload.get("domain", "")).strip()
    ip = str(payload.get("ip", "")).strip()
    reason = str(payload.get("reason", "manual_remove")).strip()
    if not user or not domain or not ip:
        return {"status": "failed", "message": "user/domain/ip required"}

    lock = acquire_lock()
    try:
        sessions = load_sessions()
        sessions, _ = expire_sessions(sessions, ttl)
        old = [dict(s) for s in sessions]
        key = session_key(user, domain)
        remaining: list[dict[str, Any]] = []
        removed = None
        for s in sessions:
            if session_key(str(s.get("user", "")), str(s.get("domain", ""))) == key and str(s.get("ip", "")).strip() == ip:
                removed = s
            else:
                remaining.append(s)
        if removed is None:
            return {"status": "ok", "action": "noop", "message": "session not found", "reason": reason}
        save_sessions(remaining)
        return {
            "status": "ok",
            "action": "removed",
            "reason": reason,
            "session": removed,
            "projection": apply_alias_projection(old, remaining, conf),
        }
    finally:
        release_lock(lock)


def replace_all_sessions(payload: dict[str, Any]) -> dict[str, Any]:
    """Full snapshot replace used by Plugin <- Agent resync."""
    conf = load_conf()
    ttl = int(conf.get("session_ttl_sec") or 28800)
    incoming = payload.get("sessions", [])
    if not isinstance(incoming, list):
        return {"status": "failed", "message": "sessions must be a list"}

    normalized: list[dict[str, Any]] = []
    skipped = 0
    seen: set[str] = set()
    for item in incoming:
        if not isinstance(item, dict):
            skipped += 1
            continue
        row = normalize_incoming_session(item, conf, ttl)
        if row is None:
            skipped += 1
            continue
        key = session_key(row["user"], row["domain"])
        # last-write wins for duplicate users, and for duplicate addresses
        if key in seen:
            normalized = [s for s in normalized if session_key(s["user"], s["domain"]) != key]
        seen.add(key)
        normalized = drop_sessions_for_ip(normalized, row["ip"], keep_key=key)
        normalized.append(row)

    lock = acquire_lock()
    try:
        old = load_sessions()
        old, _ = expire_sessions(old, ttl)
        save_sessions(normalized)
        proj = apply_alias_projection(old, normalized, conf)
        return {
            "status": "ok",
            "action": "replace_all",
            "count": len(normalized),
            "skipped": skipped,
            "projection": proj,
        }
    finally:
        release_lock(lock)


def list_sessions_cmd() -> dict[str, Any]:
    conf = load_conf()
    ttl = int(conf.get("session_ttl_sec") or 28800)
    lock = acquire_lock()
    try:
        sessions = load_sessions()
        keep, expired = expire_sessions(sessions, ttl)
        if expired:
            apply_alias_projection(sessions, keep, conf)
            save_sessions(keep)
        return {"status": "ok", "sessions": keep, "count": len(keep)}
    finally:
        release_lock(lock)


def expire_cmd() -> dict[str, Any]:
    """Drop timed-out sessions and pull their addresses out of the pf tables.

    Nothing else on the firewall triggers expiry on its own: upsert/remove/list
    only run when the Agent pushes or someone queries the API. Without this on a
    timer, a user who logged off keeps matching group rules indefinitely.
    Intended to run from cron every 1-5 minutes.
    """
    conf = load_conf()
    ttl = int(conf.get("session_ttl_sec") or 28800)
    lock = acquire_lock()
    try:
        sessions = load_sessions()
        keep, expired = expire_sessions(sessions, ttl)
        if not expired:
            return {"status": "ok", "action": "expire", "count": len(keep), "expired": 0}

        proj = apply_alias_projection(sessions, keep, conf)
        save_sessions(keep)
        return {
            "status": "ok",
            "action": "expire",
            "count": len(keep),
            "expired": len(expired),
            "projection": proj,
        }
    finally:
        release_lock(lock)


def reproject_cmd() -> dict[str, Any]:
    """Rebuild pf table contents from the persisted sessions.

    pf table entries are runtime-only, so a firewall reboot leaves every alias
    empty while sessions.json still looks healthy. Group-based rules would then
    silently stop matching. Run this on service start.
    """
    conf = load_conf()
    ttl = int(conf.get("session_ttl_sec") or 28800)
    lock = acquire_lock()
    try:
        sessions = load_sessions()
        keep, expired = expire_sessions(sessions, ttl)
        if expired:
            save_sessions(keep)
        # Treat pf as empty: project every active IP rather than a diff.
        proj = apply_alias_projection([], keep, conf)
        return {
            "status": "ok",
            "action": "reproject",
            "count": len(keep),
            "expired": len(expired),
            "projection": proj,
        }
    finally:
        release_lock(lock)


def decode_payload(raw: str | None, b64: str | None) -> dict[str, Any]:
    if b64:
        return json.loads(base64.b64decode(b64.encode("ascii")).decode("utf-8"))
    if raw:
        return json.loads(raw)
    data = sys.stdin.read()
    if not data.strip():
        raise ValueError("empty payload")
    return json.loads(data)


def main() -> int:
    parser = argparse.ArgumentParser(description="AdIdentity session store")
    parser.add_argument("--ensure-dirs", action="store_true")
    parser.add_argument("--reproject", action="store_true")
    parser.add_argument("--expire", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--upsert", action="store_true")
    parser.add_argument("--remove", action="store_true")
    parser.add_argument("--replace-all", action="store_true")
    parser.add_argument("--payload")
    parser.add_argument("--payload-b64")
    args = parser.parse_args()

    try:
        if args.ensure_dirs:
            ensure_dirs()
            sys.stdout.write(json.dumps({"status": "ok"}))
            return 0
        if args.reproject:
            sys.stdout.write(json.dumps(reproject_cmd()))
            return 0
        if args.expire:
            sys.stdout.write(json.dumps(expire_cmd()))
            return 0
        if args.list:
            sys.stdout.write(json.dumps(list_sessions_cmd()))
            return 0
        if args.upsert:
            sys.stdout.write(json.dumps(upsert_session(decode_payload(args.payload, args.payload_b64))))
            return 0
        if args.remove:
            sys.stdout.write(json.dumps(remove_session(decode_payload(args.payload, args.payload_b64))))
            return 0
        if args.replace_all:
            sys.stdout.write(json.dumps(replace_all_sessions(decode_payload(args.payload, args.payload_b64))))
            return 0
        parser.print_help()
        return 1
    except Exception as exc:  # noqa: BLE001
        sys.stdout.write(json.dumps({"status": "failed", "message": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
