#!/bin/sh
#
# Install the AdIdentity plugin onto this OPNsense firewall from a repository
# checkout. Run it on the firewall itself, as root:
#
#     /root/AdIdentityDC/plugin/install.sh
#
# This is the supported path for the pilot. Building a real FreeBSD package
# needs the opnsense/plugins ports tree, which this repository is not part of
# (see PROJECT_STATE.md, D12); plugin/Makefile is kept only for that future.
#
# Copying by hand is what the lab did until now, and it went wrong twice: a
# Python file with a syntax error took the whole plugin down while the API
# answered with an empty body (D24), and a stale file on the box quietly
# differed from the repository. So this script checks syntax before it touches
# anything, and reloads what OPNsense caches afterwards.
#
# Safe to re-run. Sessions in /var/db/adidentity and settings in config.xml are
# never touched.

set -eu

SRC_ROOT=$(cd "$(dirname "$0")/src/opnsense" 2>/dev/null && pwd || true)
DEST_ROOT=/usr/local/opnsense
SCRIPT_DIR="$DEST_ROOT/scripts/adidentity"

DRY_RUN=0
DO_RELOAD=1

usage() {
    cat <<'EOF'
Usage: install.sh [options]

  -n, --dry-run     show what would be copied, change nothing
  -N, --no-reload   copy files but do not restart configd or touch pf
  -u, --uninstall   remove installed plugin files (keeps sessions and settings)
  -h, --help        this text
EOF
}

log()  { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        log "  would: $*"
    else
        "$@"
    fi
}

# --- arguments -------------------------------------------------------------

ACTION=install
while [ $# -gt 0 ]; do
    case "$1" in
        -n|--dry-run)   DRY_RUN=1 ;;
        -N|--no-reload) DO_RELOAD=0 ;;
        -u|--uninstall) ACTION=uninstall ;;
        -h|--help)      usage; exit 0 ;;
        *)              usage; die "unknown option: $1" ;;
    esac
    shift
done

[ -n "$SRC_ROOT" ] || die "cannot find src/opnsense next to this script"
[ -d "$SRC_ROOT/mvc" ] || die "$SRC_ROOT does not look like a plugin source tree"

if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    die "must run as root"
fi

# --- syntax checks, before anything is written -----------------------------

# A broken file here disables every API endpoint of the plugin, and OPNsense
# reports that as an empty response rather than an error (D24).
preflight() {
    failed=0

    for file in $(find "$SRC_ROOT" -name '*.py' | sort); do
        if ! python3 -m py_compile "$file" >/dev/null 2>&1; then
            warn "python syntax error: $file"
            python3 -m py_compile "$file" 2>&1 | sed 's/^/    /' >&2 || true
            failed=1
        fi
    done

    if command -v php >/dev/null 2>&1; then
        for file in $(find "$SRC_ROOT" -name '*.php' | sort); do
            if ! php -l "$file" >/dev/null 2>&1; then
                warn "php syntax error: $file"
                php -l "$file" 2>&1 | sed 's/^/    /' >&2 || true
                failed=1
            fi
        done

        for file in $(find "$SRC_ROOT" -name '*.xml' | sort); do
            # A malformed model or menu file leaves the UI blank with nothing
            # useful in the log.
            if ! php -r 'exit(@simplexml_load_file($argv[1]) === false ? 1 : 0);' "$file" >/dev/null 2>&1; then
                warn "malformed xml: $file"
                failed=1
            fi
        done
    else
        warn "php not found, skipping php and xml checks"
    fi

    # py_compile leaves bytecode next to the sources in the checkout.
    find "$SRC_ROOT" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

    [ "$failed" -eq 0 ] || die "source tree does not compile, nothing was installed"
    log "syntax checks passed"
}

# --- copying ---------------------------------------------------------------

source_files() {
    (cd "$SRC_ROOT" && find . -type f | sed 's|^\./||' | sort)
}

install_files() {
    for dir in $(source_files | xargs -n1 dirname | sort -u); do
        [ -d "$DEST_ROOT/$dir" ] || run install -d -o root -g wheel -m 755 "$DEST_ROOT/$dir"
    done

    count=0
    for src in $(source_files); do
        mode=644
        case "$src" in
            *.py) mode=755 ;;
        esac

        run install -o root -g wheel -m "$mode" "$SRC_ROOT/$src" "$DEST_ROOT/$src"
        count=$((count + 1))
        [ "$DRY_RUN" -eq 1 ] || log "  $DEST_ROOT/$src"
    done
    log "installed $count file(s)"
}

uninstall_files() {
    count=0
    for src in $(source_files); do
        dest="$DEST_ROOT/$src"
        if [ -f "$dest" ]; then
            run rm -f "$dest"
            count=$((count + 1))
        fi
    done

    for dir in \
        "$DEST_ROOT/scripts/adidentity" \
        "$DEST_ROOT/mvc/app/controllers/OPNsense/AdIdentity/Api" \
        "$DEST_ROOT/mvc/app/controllers/OPNsense/AdIdentity/forms" \
        "$DEST_ROOT/mvc/app/controllers/OPNsense/AdIdentity" \
        "$DEST_ROOT/mvc/app/library/OPNsense/AdIdentity" \
        "$DEST_ROOT/mvc/app/models/OPNsense/AdIdentity/ACL" \
        "$DEST_ROOT/mvc/app/models/OPNsense/AdIdentity/Menu" \
        "$DEST_ROOT/mvc/app/models/OPNsense/AdIdentity" \
        "$DEST_ROOT/mvc/app/views/OPNsense/AdIdentity" \
        "$DEST_ROOT/service/templates/OPNsense/AdIdentity"
    do
        [ -d "$dir" ] && run rmdir "$dir" 2>/dev/null || true
    done

    log "removed $count file(s)"
    log ""
    log "Left in place on purpose:"
    log "  /var/db/adidentity            sessions, so a reinstall keeps state"
    log "  /usr/local/etc/adidentity.conf generated from settings"
    log "  config.xml (OPNsense/AdIdentity) plugin settings and the shared token"
    log "  firewall aliases and rules      yours, not the plugin's to delete"
}

# --- what OPNsense caches --------------------------------------------------

reload_backend() {
    # configd reads actions.d and the model definitions at start, so a copied
    # file does nothing until it is restarted.
    log "restarting configd"
    run service configd restart
    run sleep 2

    run "$SCRIPT_DIR/session_store.py" --ensure-dirs >/dev/null 2>&1 || \
        warn "could not create /var/db/adidentity yet"

    # pf tables hold no state across a reload, so refill them from the
    # persisted sessions (D2). Fails harmlessly before first configuration.
    if [ "$DRY_RUN" -eq 0 ]; then
        out=$(configctl adidentity reproject 2>&1 || true)
        case "$out" in
            *'"status": "ok"'*|*'"status":"ok"'*)
                log "reproject: $out"
                ;;
            *)
                warn "reproject did not report ok: $out"
                warn "expected before the plugin is configured in the UI"
                ;;
        esac
    else
        log "  would: configctl adidentity reproject"
    fi
}

verify() {
    [ "$DRY_RUN" -eq 1 ] && return 0

    log ""
    log "Verifying:"
    for cmd in 'adidentity expire' 'adidentity session-list'; do
        # An empty answer here is the signature of a plugin whose Python or
        # actions definition is broken.
        out=$(configctl $cmd 2>&1 || true)
        if [ -z "$out" ]; then
            warn "configctl $cmd returned nothing - backend action or script broken"
        else
            log "  configctl $cmd -> $(printf '%s' "$out" | cut -c1-80)"
        fi
    done
}

# --- main ------------------------------------------------------------------

case "$ACTION" in
    uninstall)
        log "Uninstalling AdIdentity from $DEST_ROOT"
        uninstall_files
        if [ "$DO_RELOAD" -eq 1 ]; then
            log "restarting configd"
            run service configd restart
        fi
        ;;
    install)
        log "Installing AdIdentity"
        log "  from $SRC_ROOT"
        log "  to   $DEST_ROOT"
        log ""
        preflight
        install_files
        if [ "$DO_RELOAD" -eq 1 ]; then
            reload_backend
            verify
        else
            log "skipped configd restart, plugin still runs the previous code"
        fi
        log ""
        log "Next: open Services -> AdIdentity in the UI, set the shared token"
        log "and monitored groups, then press Apply."
        ;;
esac
