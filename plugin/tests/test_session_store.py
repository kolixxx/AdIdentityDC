#!/usr/local/bin/python3
"""Tests for the plugin-side session store and pf alias projection.

Run with the system interpreter, on a workstation or on the firewall itself:

    python3 plugin/tests/test_session_store.py

Deliberately free of pytest: OPNsense ships no test framework, and these rules
are worth checking on the box that actually runs them.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "src" / "opnsense" / "scripts" / "adidentity" / "session_store.py"
)


def load_module():
    spec = importlib.util.spec_from_file_location("session_store", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load_module()

# Module globals a test may redirect; restored after every test.
PATCHED = (
    "DB_DIR", "SESSIONS_FILE", "LOCK_FILE", "CONF_FILE",
    "configctl_filter", "pf_table_ips", "wait_for_table",
)


class FakeProc:
    """Stand-in for subprocess.CompletedProcess."""

    def __init__(self, returncode: int, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class Env:
    """Redirect the store to a temp directory and fake out pf.

    ``pf`` maps an alias to the addresses the table holds, or to None for a
    table pfctl cannot read - the state of an alias that does not exist yet.
    """

    def __init__(self, conf: str = "", sessions=None, pf=None, table_ready: bool = True):
        self.dir = Path(tempfile.mkdtemp(prefix="adidentity-tests-"))
        m.DB_DIR = self.dir
        m.SESSIONS_FILE = self.dir / "sessions.json"
        m.LOCK_FILE = self.dir / "sessions.lock"
        m.CONF_FILE = self.dir / "adidentity.conf"
        m.CONF_FILE.write_text(conf, encoding="utf-8")

        self.pf = {} if pf is None else dict(pf)
        self.calls: list[tuple[str, str, str]] = []
        m.configctl_filter = self._filter
        m.pf_table_ips = self._show
        m.wait_for_table = lambda alias, timeout_sec=0: table_ready

        if sessions is not None:
            m.save_sessions(sessions)

    def _filter(self, op, alias, ip):
        self.calls.append((op, alias, ip))
        held = self.pf.get(alias)
        if held is None:
            # pf refuses to touch a table it does not know.
            return False, "table does not exist"
        if op == "add":
            held.add(ip)
        else:
            held.discard(ip)
        return True, ""

    def _show(self, alias):
        held = self.pf.get(alias)
        return (False, set()) if held is None else (True, set(held))

    def stored(self):
        return json.loads(m.SESSIONS_FILE.read_text(encoding="utf-8"))["sessions"]

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def session(user, ip, groups, domain="INTERNAL", ttl_sec=900, ts=None):
    now = datetime.now(timezone.utc)
    stamp = ts or now
    return {
        "user": user,
        "domain": domain,
        "ip": ip,
        "groups": list(groups),
        "event": "login",
        "ts": stamp.isoformat(),
        "dc": "DC01",
        "expires_at": (now + timedelta(seconds=ttl_sec)).isoformat(),
    }


# --- timestamps ------------------------------------------------------------

def test_dotnet_seven_digit_fraction_is_parsed():
    # DateTime.ToString("o") emits 7 digits; several Python builds accept 6, and
    # a failed parse used to mean a session that never expired.
    parsed = m.parse_ts("2026-09-03T23:51:22.8259158+00:00")
    assert parsed is not None
    assert parsed.year == 2026 and parsed.second == 22


def test_zulu_suffix_is_parsed():
    parsed = m.parse_ts("2026-09-03T23:51:22Z")
    assert parsed is not None and parsed.tzinfo is not None


def test_a_timestamp_without_an_offset_is_read_as_utc():
    # A hand-edited sessions.json would otherwise raise on comparison instead
    # of expiring the session.
    parsed = m.parse_ts("2026-09-03T23:51:22")
    assert parsed is not None and parsed.utcoffset() == timedelta(0)


def test_unparseable_timestamps_are_reported_as_none():
    assert m.parse_ts("not a date") is None
    assert m.parse_ts("") is None
    assert m.parse_ts(None) is None


# --- alias names -----------------------------------------------------------

def test_a_space_in_a_group_name_becomes_an_underscore():
    assert m.normalize_alias_name("Domain Admins") == "Domain_Admins"


def test_punctuation_collapses_into_a_single_underscore():
    assert m.normalize_alias_name("Sales - EU / West") == "Sales_EU_West"


def test_an_alias_never_starts_with_a_digit():
    # pf table names must begin with a letter.
    assert m.normalize_alias_name("2nd Line Support").startswith("g_")


def test_a_non_latin_group_name_still_yields_a_usable_alias():
    alias = m.normalize_alias_name("Бухгалтерия")
    assert alias and alias[0].isascii() and alias[0].isalpha()


def test_a_user_alias_gets_the_configured_prefix_once():
    assert m.normalize_alias_name("ivanov", force_prefix="u_") == "u_ivanov"
    assert m.normalize_alias_name("u_ivanov", force_prefix="u_") == "u_ivanov"


def test_an_alias_name_is_capped():
    assert len(m.normalize_alias_name("G" * 200)) == 64


def test_monitored_groups_accept_commas_newlines_and_semicolons():
    conf = {"monitored_groups": "Managers, Developers\nAccounting;  \n"}
    assert m.monitored_groups(conf) == {"Managers", "Developers", "Accounting"}


def test_no_configured_groups_means_an_empty_filter():
    assert m.monitored_groups({}) == set()


# --- addresses -------------------------------------------------------------

def test_addresses_that_cannot_belong_to_a_workstation_are_rejected():
    for value in ("127.0.0.1", "::1", "0.0.0.0", "-", "LOCAL-WINDOWS-02", ""):
        assert not m.is_valid_ip(value), value


def test_real_addresses_are_accepted():
    assert m.is_valid_ip("10.0.1.10")
    assert m.is_valid_ip("fe80::1")


# --- one address, one user (D1) -------------------------------------------

def test_a_new_holder_releases_the_address_from_everyone_else():
    sessions = [session("ivanov", "10.0.1.10", ["Managers"])]
    kept = m.drop_sessions_for_ip(sessions, "10.0.1.10", keep_key="internal\\petrov")
    assert kept == []


def test_the_holder_named_by_keep_key_survives():
    sessions = [session("ivanov", "10.0.1.10", ["Managers"])]
    kept = m.drop_sessions_for_ip(sessions, "10.0.1.10", keep_key="internal\\ivanov")
    assert len(kept) == 1


def test_other_addresses_are_untouched():
    sessions = [session("ivanov", "10.0.1.11", ["Managers"])]
    assert len(m.drop_sessions_for_ip(sessions, "10.0.1.10")) == 1


def test_the_session_key_ignores_letter_case():
    assert m.session_key("Ivanov", "INTERNAL") == m.session_key("ivanov", "internal")


# --- expiry ----------------------------------------------------------------

def test_a_session_past_its_expiry_is_dropped():
    keep, expired = m.expire_sessions([session("ivanov", "10.0.1.10", ["Managers"], ttl_sec=-1)], 900)
    assert keep == [] and len(expired) == 1


def test_a_session_within_its_expiry_is_kept():
    keep, expired = m.expire_sessions([session("ivanov", "10.0.1.10", ["Managers"])], 900)
    assert len(keep) == 1 and expired == []


def test_a_session_without_an_expiry_falls_back_to_the_configured_ttl():
    # Sessions written by an older build carry no expires_at; without the
    # fallback they would live forever.
    row = session("ivanov", "10.0.1.10", ["Managers"], ts=datetime.now(timezone.utc) - timedelta(seconds=100))
    row.pop("expires_at")
    keep, expired = m.expire_sessions([row], 60)
    assert keep == [] and len(expired) == 1


def test_the_ttl_fallback_keeps_a_recent_session():
    row = session("ivanov", "10.0.1.10", ["Managers"])
    row.pop("expires_at")
    keep, _ = m.expire_sessions([row], 900)
    assert len(keep) == 1


def test_a_session_with_no_timestamps_at_all_is_kept():
    # Nothing to judge it by; dropping it would revoke access on a guess.
    keep, expired = m.expire_sessions([{"user": "ivanov", "domain": "INTERNAL", "ip": "10.0.1.10"}], 900)
    assert len(keep) == 1 and expired == []


# --- what belongs in which alias ------------------------------------------

def test_only_monitored_groups_become_aliases():
    conf = {"monitored_groups": "Managers"}
    mapping = m.desired_alias_ips([session("ivanov", "10.0.1.10", ["Managers", "Domain Users"])], conf)
    assert mapping == {"Managers": {"10.0.1.10"}}


def test_without_a_filter_every_group_becomes_an_alias():
    mapping = m.desired_alias_ips([session("ivanov", "10.0.1.10", ["Managers", "Domain Users"])], {})
    assert set(mapping) == {"Managers", "Domain_Users"}


def test_two_users_of_one_group_share_the_alias():
    conf = {"monitored_groups": "Managers"}
    mapping = m.desired_alias_ips(
        [session("ivanov", "10.0.1.10", ["Managers"]), session("petrov", "10.0.1.11", ["Managers"])],
        conf,
    )
    assert mapping["Managers"] == {"10.0.1.10", "10.0.1.11"}


def test_a_session_with_an_unusable_address_contributes_nothing():
    assert m.desired_alias_ips([session("ivanov", "-", ["Managers"])], {}) == {}


def test_user_aliases_appear_only_when_enabled():
    rows = [session("ivanov", "10.0.1.10", ["Managers"])]
    assert "u_ivanov" not in m.desired_alias_ips(rows, {})
    enabled = m.desired_alias_ips(rows, {"enable_user_aliases": "1"})
    assert enabled["u_ivanov"] == {"10.0.1.10"}


def test_the_user_alias_prefix_is_configurable():
    mapping = m.desired_alias_ips(
        [session("ivanov", "10.0.1.10", ["Managers"])],
        {"enable_user_aliases": "1", "user_alias_prefix": "usr_"},
    )
    assert "usr_ivanov" in mapping


# --- incoming payloads -----------------------------------------------------

def test_groups_outside_the_filter_are_stripped_on_arrival():
    row = m.normalize_incoming_session(
        {"user": "ivanov", "domain": "INTERNAL", "ip": "10.0.1.10", "groups": ["Managers", "Backup Operators"]},
        {"monitored_groups": "Managers"},
        900,
    )
    assert row is not None and row["groups"] == ["Managers"]


def test_a_payload_without_an_expiry_gets_one_from_the_ttl():
    row = m.normalize_incoming_session(
        {"user": "ivanov", "domain": "INTERNAL", "ip": "10.0.1.10", "groups": []}, {}, 28800
    )
    assert row is not None
    left = m.parse_ts(row["expires_at"]) - datetime.now(timezone.utc)
    assert timedelta(hours=7, minutes=59) < left <= timedelta(hours=8)


def test_an_agent_supplied_expiry_is_preserved():
    row = m.normalize_incoming_session(
        {
            "user": "ivanov", "domain": "INTERNAL", "ip": "10.0.1.10", "groups": [],
            "expires_at": "2026-09-05T20:59:00+00:00",
        },
        {},
        900,
    )
    assert row is not None and row["expires_at"] == "2026-09-05T20:59:00+00:00"


def test_incomplete_or_impossible_payloads_are_refused():
    for payload in (
        {"domain": "INTERNAL", "ip": "10.0.1.10", "groups": []},
        {"user": "ivanov", "ip": "10.0.1.10", "groups": []},
        {"user": "ivanov", "domain": "INTERNAL", "groups": []},
        {"user": "ivanov", "domain": "INTERNAL", "ip": "127.0.0.1", "groups": []},
        {"user": "ivanov", "domain": "INTERNAL", "ip": "10.0.1.10", "groups": "Managers"},
    ):
        assert m.normalize_incoming_session(payload, {}, 900) is None, payload


# --- projecting a change into pf ------------------------------------------

def test_a_new_session_adds_its_address_to_the_group_alias():
    env = Env(pf={"Managers": set()})
    try:
        result = m.apply_alias_projection([], [session("ivanov", "10.0.1.10", ["Managers"])], {})
        assert result["ips_added"] == 1 and result["errors"] == []
        assert env.pf["Managers"] == {"10.0.1.10"}
    finally:
        env.cleanup()


def test_a_departed_session_has_its_address_removed():
    env = Env(pf={"Managers": {"10.0.1.10"}})
    try:
        result = m.apply_alias_projection([session("ivanov", "10.0.1.10", ["Managers"])], [], {})
        assert result["ips_removed"] == 1
        assert env.pf["Managers"] == set()
    finally:
        env.cleanup()


def test_an_unchanged_session_touches_nothing():
    env = Env(pf={"Managers": {"10.0.1.10"}})
    try:
        rows = [session("ivanov", "10.0.1.10", ["Managers"])]
        result = m.apply_alias_projection(rows, rows, {})
        assert result["ips_added"] == 0 and result["ips_removed"] == 0
        assert env.calls == []
    finally:
        env.cleanup()


def test_a_group_change_moves_the_address_between_aliases():
    env = Env(pf={"Managers": {"10.0.1.10"}, "Developers": set()})
    try:
        result = m.apply_alias_projection(
            [session("ivanov", "10.0.1.10", ["Managers"])],
            [session("ivanov", "10.0.1.10", ["Developers"])],
            {},
        )
        assert (result["ips_added"], result["ips_removed"]) == (1, 1)
        assert env.pf["Managers"] == set() and env.pf["Developers"] == {"10.0.1.10"}
    finally:
        env.cleanup()


def test_an_address_is_deferred_rather_than_lost_when_pf_has_no_table_yet():
    # D10: an alias created moments ago is in config.xml before the filter
    # reload finishes. Reporting it lets the periodic reconcile retry.
    env = Env(pf={"Managers": None}, table_ready=False)
    try:
        result = m.apply_alias_projection([], [session("ivanov", "10.0.1.10", ["Managers"])], {})
        assert result["ips_added"] == 0
        assert any("not ready" in e for e in result["errors"])
        assert env.calls == []
    finally:
        env.cleanup()


# --- reconciling against live pf content (D21) ----------------------------

def test_an_address_deleted_behind_the_plugins_back_is_restored():
    # The lab case: pfctl -t Managers -T delete 10.0.1.10 while the user is
    # still logged on. A state diff cannot see this; the live comparison can.
    env = Env(pf={"Managers": set()})
    try:
        result = m.reconcile_pf_tables([session("ivanov", "10.0.1.10", ["Managers"])], {})
        assert result["ips_added"] == 1
        assert env.pf["Managers"] == {"10.0.1.10"}
    finally:
        env.cleanup()


def test_an_address_no_session_claims_is_cleaned_out():
    env = Env(pf={"Managers": {"10.0.1.10", "10.0.1.77"}})
    try:
        result = m.reconcile_pf_tables([session("ivanov", "10.0.1.10", ["Managers"])], {})
        assert result["ips_removed"] == 1
        assert env.pf["Managers"] == {"10.0.1.10"}
    finally:
        env.cleanup()


def test_a_reboot_flushed_table_is_refilled():
    env = Env(pf={"Managers": set(), "Developers": set()})
    try:
        rows = [session("ivanov", "10.0.1.10", ["Managers"]), session("petrov", "10.0.1.11", ["Developers"])]
        result = m.reconcile_pf_tables(rows, {})
        assert result["ips_added"] == 2
    finally:
        env.cleanup()


def test_a_monitored_group_with_no_sessions_left_is_emptied():
    # The alias holds no sessions any more, so it is absent from the desired
    # mapping; without seeding from the config its leftovers would survive.
    env = Env(pf={"Managers": {"10.0.1.10"}})
    try:
        result = m.reconcile_pf_tables([], {"monitored_groups": "Managers"})
        assert result["ips_removed"] == 1 and env.pf["Managers"] == set()
    finally:
        env.cleanup()


def test_an_unreadable_table_is_reported_and_never_emptied_on_a_guess():
    env = Env(pf={"Managers": None}, table_ready=False)
    try:
        result = m.reconcile_pf_tables([session("ivanov", "10.0.1.10", ["Managers"])], {})
        assert result["unreadable_tables"] == ["Managers"]
        assert result["ips_removed"] == 0
    finally:
        env.cleanup()


def test_pfctl_output_is_read_without_the_host_mask():
    # pfctl prints 10.0.1.10/32. Comparing that literally against the session
    # address would delete and re-add the same address on every pass.
    original = m.subprocess.run
    m.subprocess.run = lambda *a, **kw: FakeProc(0, "   10.0.1.10/32\n10.0.1.11\n\n")
    try:
        readable, ips = m.pf_table_ips("Managers")
        assert readable and ips == {"10.0.1.10", "10.0.1.11"}
    finally:
        m.subprocess.run = original


def test_a_table_pfctl_cannot_read_is_reported_as_unreadable():
    original = m.subprocess.run
    m.subprocess.run = lambda *a, **kw: FakeProc(1, "", "pfctl: Table does not exist.")
    try:
        readable, ips = m.pf_table_ips("Managers")
        assert not readable and ips == set()
    finally:
        m.subprocess.run = original


def test_a_failing_pfctl_does_not_raise():
    original = m.subprocess.run
    def boom(*a, **kw):
        raise OSError("pfctl missing")
    m.subprocess.run = boom
    try:
        assert m.pf_table_ips("Managers") == (False, set())
    finally:
        m.subprocess.run = original


# --- the store end to end -------------------------------------------------

def test_a_pushed_session_is_persisted_and_projected():
    env = Env(conf="monitored_groups=Managers\nsession_ttl_sec=900\n", pf={"Managers": set()})
    try:
        result = m.upsert_session(
            {"user": "ivanov", "domain": "INTERNAL", "ip": "10.0.1.10", "groups": ["Managers"]}
        )
        assert result["status"] == "ok" and result["action"] == "created"
        assert len(env.stored()) == 1
        assert env.pf["Managers"] == {"10.0.1.10"}
    finally:
        env.cleanup()


def test_a_second_push_for_the_same_user_updates_in_place():
    env = Env(conf="monitored_groups=Managers\n", pf={"Managers": set()})
    try:
        payload = {"user": "ivanov", "domain": "INTERNAL", "ip": "10.0.1.10", "groups": ["Managers"]}
        m.upsert_session(payload)
        result = m.upsert_session(payload)
        assert result["action"] == "updated" and len(env.stored()) == 1
    finally:
        env.cleanup()


def test_a_second_user_on_one_address_takes_over_the_aliases():
    # Acceptance criterion 9, as run in the lab with ivanov then petrov.
    env = Env(
        conf="monitored_groups=Managers,Developers\n",
        pf={"Managers": set(), "Developers": set()},
    )
    try:
        m.upsert_session({"user": "ivanov", "domain": "INTERNAL", "ip": "10.0.1.10", "groups": ["Managers"]})
        m.upsert_session({"user": "petrov", "domain": "INTERNAL", "ip": "10.0.1.10", "groups": ["Developers"]})

        stored = env.stored()
        assert len(stored) == 1 and stored[0]["user"] == "petrov"
        assert env.pf["Managers"] == set()
        assert env.pf["Developers"] == {"10.0.1.10"}
    finally:
        env.cleanup()


def test_a_user_moving_to_a_new_address_leaves_nothing_behind():
    env = Env(conf="monitored_groups=Managers\n", pf={"Managers": set()})
    try:
        m.upsert_session({"user": "ivanov", "domain": "INTERNAL", "ip": "10.0.1.10", "groups": ["Managers"]})
        m.upsert_session({"user": "ivanov", "domain": "INTERNAL", "ip": "10.0.1.20", "groups": ["Managers"]})
        assert env.pf["Managers"] == {"10.0.1.20"}
    finally:
        env.cleanup()


def test_a_malformed_push_is_refused_without_disturbing_the_store():
    env = Env(sessions=[session("ivanov", "10.0.1.10", ["Managers"])], pf={"Managers": {"10.0.1.10"}})
    try:
        result = m.upsert_session({"user": "", "domain": "INTERNAL", "ip": "10.0.1.10", "groups": []})
        assert result["status"] == "failed"
        assert len(env.stored()) == 1
    finally:
        env.cleanup()


def test_a_logoff_removes_the_session_and_the_address():
    env = Env(sessions=[session("ivanov", "10.0.1.10", ["Managers"])], pf={"Managers": {"10.0.1.10"}})
    try:
        result = m.remove_session(
            {"user": "ivanov", "domain": "INTERNAL", "ip": "10.0.1.10", "reason": "logoff"}
        )
        assert result["action"] == "removed"
        assert env.stored() == [] and env.pf["Managers"] == set()
    finally:
        env.cleanup()


def test_a_removal_naming_the_wrong_address_changes_nothing():
    env = Env(sessions=[session("ivanov", "10.0.1.10", ["Managers"])], pf={"Managers": {"10.0.1.10"}})
    try:
        result = m.remove_session({"user": "ivanov", "domain": "INTERNAL", "ip": "10.0.1.99"})
        assert result["action"] == "noop"
        assert len(env.stored()) == 1
    finally:
        env.cleanup()


def test_a_resync_replaces_the_whole_snapshot():
    env = Env(
        conf="monitored_groups=Managers,Developers\n",
        sessions=[session("ivanov", "10.0.1.10", ["Managers"])],
        pf={"Managers": {"10.0.1.10"}, "Developers": set()},
    )
    try:
        result = m.replace_all_sessions(
            {"sessions": [{"user": "petrov", "domain": "INTERNAL", "ip": "10.0.1.11", "groups": ["Developers"]}]}
        )
        assert result["count"] == 1
        assert env.pf["Managers"] == set() and env.pf["Developers"] == {"10.0.1.11"}
    finally:
        env.cleanup()


def test_a_resync_reports_the_rows_it_could_not_use():
    env = Env(pf={"Managers": set()})
    try:
        result = m.replace_all_sessions(
            {
                "sessions": [
                    {"user": "ivanov", "domain": "INTERNAL", "ip": "10.0.1.10", "groups": ["Managers"]},
                    {"user": "broken", "domain": "INTERNAL", "ip": "127.0.0.1", "groups": []},
                    "not even an object",
                ]
            }
        )
        assert result["count"] == 1 and result["skipped"] == 2
    finally:
        env.cleanup()


def test_a_resync_carrying_one_address_twice_keeps_the_last_holder():
    env = Env(conf="monitored_groups=Managers,Developers\n", pf={"Managers": set(), "Developers": set()})
    try:
        result = m.replace_all_sessions(
            {
                "sessions": [
                    {"user": "ivanov", "domain": "INTERNAL", "ip": "10.0.1.10", "groups": ["Managers"]},
                    {"user": "petrov", "domain": "INTERNAL", "ip": "10.0.1.10", "groups": ["Developers"]},
                ]
            }
        )
        assert result["count"] == 1
        assert env.pf["Developers"] == {"10.0.1.10"} and env.pf["Managers"] == set()
    finally:
        env.cleanup()


def test_the_expire_pass_drops_timed_out_sessions_and_repairs_pf():
    # D5 plus D21 in one pass: this is what cron runs every minute.
    env = Env(
        conf="monitored_groups=Managers\n",
        sessions=[
            session("ivanov", "10.0.1.10", ["Managers"], ttl_sec=-1),
            session("petrov", "10.0.1.11", ["Managers"]),
        ],
        pf={"Managers": {"10.0.1.10"}},
    )
    try:
        result = m.expire_cmd()
        assert result["expired"] == 1 and result["count"] == 1
        assert env.pf["Managers"] == {"10.0.1.11"}
    finally:
        env.cleanup()


def test_the_expire_pass_repairs_pf_even_when_nothing_expired():
    env = Env(
        conf="monitored_groups=Managers\n",
        sessions=[session("ivanov", "10.0.1.10", ["Managers"])],
        pf={"Managers": set()},
    )
    try:
        result = m.expire_cmd()
        assert result["expired"] == 0
        assert env.pf["Managers"] == {"10.0.1.10"}
    finally:
        env.cleanup()


def test_a_reboot_is_recovered_from_the_persisted_sessions():
    # pf tables are runtime-only, so every alias comes up empty while
    # sessions.json still looks healthy.
    env = Env(
        conf="monitored_groups=Managers\n",
        sessions=[session("ivanov", "10.0.1.10", ["Managers"])],
        pf={"Managers": set()},
    )
    try:
        result = m.reproject_cmd()
        assert result["count"] == 1
        assert env.pf["Managers"] == {"10.0.1.10"}
    finally:
        env.cleanup()


def test_listing_sessions_hides_the_expired_ones():
    env = Env(
        conf="monitored_groups=Managers\n",
        sessions=[
            session("ivanov", "10.0.1.10", ["Managers"], ttl_sec=-1),
            session("petrov", "10.0.1.11", ["Managers"]),
        ],
        pf={"Managers": {"10.0.1.10", "10.0.1.11"}},
    )
    try:
        result = m.list_sessions_cmd()
        assert result["count"] == 1
        assert env.pf["Managers"] == {"10.0.1.11"}
    finally:
        env.cleanup()


def test_a_corrupt_sessions_file_does_not_take_the_api_down():
    env = Env()
    try:
        m.SESSIONS_FILE.write_text("{ not json", encoding="utf-8")
        assert m.load_sessions() == []
    finally:
        env.cleanup()


def test_a_conf_file_with_comments_and_blank_lines_is_read():
    env = Env(conf="# comment\n\nmonitored_groups=Managers\n  session_ttl_sec = 900\nnonsense\n")
    try:
        conf = m.load_conf()
        assert conf["monitored_groups"] == "Managers"
        assert conf["session_ttl_sec"] == "900"
    finally:
        env.cleanup()


def main() -> int:
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    originals = {name: getattr(m, name) for name in PATCHED}

    failed = []
    for name, fn in tests:
        try:
            fn()
            print(f"ok   {name}")
        except Exception:
            failed.append(name)
            print(f"FAIL {name}")
            traceback.print_exc()
        finally:
            for key, value in originals.items():
                setattr(m, key, value)

    print(f"\n{len(tests) - len(failed)} passed, {len(failed)} failed")
    for name in failed:
        print(f"  failed: {name}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
