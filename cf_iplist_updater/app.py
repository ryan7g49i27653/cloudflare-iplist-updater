"""Orchestration: detect addresses, reconcile the Cloudflare list, report."""

import argparse
import fcntl
import ipaddress
import json
import logging
import logging.handlers
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, config, detect_web, reconcile, state, untrusted
from .addresses import cf_acceptable, is_public, parse_network, prefix_for, to_cf
from .cloudflare import CloudflareClient, CloudflareError
from .detect_fortigate import FortiGateClient, FortiGateError
from .healthcheck import Healthchecks

log = logging.getLogger("cf_iplist_updater")

EXIT_OK, EXIT_FAILED, EXIT_CONFIG, EXIT_LOCKED = 0, 1, 2, 75
DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "config.toml"


@dataclass
class Detection:
    desired: dict = field(default_factory=dict)  # {4: [net] | [] | None, 6: ...}
    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _warn(det, msg):
    log.warning(msg)
    det.warnings.append(msg)


def _error(det, msg):
    log.error(msg)
    det.errors.append(msg)


def detect_ipv4(cfg, fg, det):
    addr = None
    if fg:
        try:
            candidate = fg.wan_ipv4()
            if is_public(candidate):
                addr = candidate
                log.info("IPv4 %s (FortiGate %s)", addr, cfg.fortigate.wan_interface)
            else:
                _warn(det, f"FortiGate WAN IPv4 {candidate} is not public; using echo services")
        except FortiGateError as e:
            _warn(det, f"FortiGate IPv4 lookup failed, using echo services: {e}")
    if addr is None:
        addr = detect_web.detect(4, cfg.echo.ipv4_services, cfg.echo.quorum, cfg.echo.timeout)
        if addr:
            log.info("IPv4 %s (echo services)", addr)
    if addr is None:
        _error(det, "could not determine public IPv4 address")
        det.desired[4] = None
    else:
        det.desired[4] = [ipaddress.ip_network(addr)]


def last_known(st, version):
    try:
        return [parse_network(n) for n in (st.get("last_known") or {}).get(str(version)) or []]
    except ValueError:
        return []


def detect_ipv6(cfg, fg, st, det):
    det.desired[6] = None
    if fg:
        try:
            nets = fg.delegated_prefixes()
            for net in [n for n in nets if not cf_acceptable(n)]:
                _warn(det, f"skipping {net}: outside Cloudflare's accepted /12-/64 range")
            nets = [n for n in nets if cf_acceptable(n)]
            if nets:
                det.desired[6] = nets
                log.info("IPv6 %s (FortiGate delegated prefixes)", ", ".join(map(str, nets)))
                return
            _warn(det, "FortiGate shows no delegated IPv6 prefixes; using echo services")
        except FortiGateError as e:
            _warn(det, f"FortiGate IPv6 lookup failed, using echo services: {e}")

    addr = detect_web.detect(6, cfg.echo.ipv6_services, cfg.echo.quorum, cfg.echo.timeout)
    if addr is None:
        _error(det, "could not determine public IPv6 address")
        return
    previous = last_known(st, 6)
    if any(addr in n for n in previous):
        # Prefix unchanged; keep every last-known prefix (there may be several LANs).
        det.desired[6] = previous
        log.info("IPv6 %s (echo address %s is within last known prefixes)",
                 ", ".join(map(str, previous)), addr)
        return
    length = cfg.ipv6.fallback_prefix_length or (previous[0].prefixlen if previous else 0)
    if not length:
        _error(det, f"IPv6 address {addr} is in a new prefix and its length is unknown; "
                    "set [ipv6] fallback_prefix_length")
        return
    net = prefix_for(addr, length)
    if not cf_acceptable(net):
        _error(det, f"IPv6 prefix {net} is outside Cloudflare's accepted /12-/64 range")
        return
    det.desired[6] = [net]
    log.info("IPv6 %s (echo address %s masked to /%d)", net, addr, length)


def detect(cfg, st, fg=None):
    det = Detection()
    if cfg.general.ipv4:
        detect_ipv4(cfg, fg, det)
    else:
        det.desired[4] = []
    if cfg.general.ipv6:
        detect_ipv6(cfg, fg, st, det)
    else:
        det.desired[6] = []
    return det


def apply(cf, p, marker, dry_run):
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    adds = [{"ip": to_cf(net), "comment": f"{marker} IPv{net.version} added {stamp}"}
            for net in p.to_add]
    lines = [f"add {a['ip']}" for a in adds] + [f"remove {i['ip']}" for i in p.to_remove]
    for line in lines:
        log.info("%s%s", "[dry-run] " if dry_run else "", line)
    if dry_run:
        return lines
    # Add before removing so there's no window without a valid entry.
    if adds:
        cf.add_items(adds)
    if p.to_remove:
        cf.delete_items([i["id"] for i in p.to_remove])
    return lines


def run(cfg, dry_run=False):
    hc = Healthchecks("" if dry_run else cfg.healthchecks.ping_url, cfg.healthchecks.timeout)
    state_path = cfg.general.state_dir / "state.json"
    st = state.load(state_path)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    det = Detection()
    changes = []
    try:
        fg = FortiGateClient(cfg.fortigate) if cfg.fortigate.enabled else None
        det = detect(cfg, st, fg)
        cf = CloudflareClient(cfg.cloudflare)
        p = reconcile.plan(det.desired, cf.list_items(), cfg.cloudflare.comment_marker)
        changes = apply(cf, p, cfg.cloudflare.comment_marker, dry_run)
        if not p.changed:
            log.info("Cloudflare list already up to date")
    except CloudflareError as e:
        _error(det, f"Cloudflare: {e}")
    except Exception as e:  # noqa: BLE001 - always report to Healthchecks
        log.exception("unexpected error")
        det.errors.append(f"unexpected error: {untrusted.describe(e, 200)}")

    summary = "\n".join(
        [f"cf-iplist-updater {__version__}"]
        + [f"desired IPv{v}: {', '.join(to_cf(n) for n in nets) if nets else nets}"
           for v, nets in sorted(det.desired.items())]
        + [f"change: {c}" for c in changes]
        + [f"warning: {w}" for w in det.warnings]
        + [f"error: {e}" for e in det.errors])
    if dry_run:
        return EXIT_FAILED if det.errors else EXIT_OK

    st["last_run"] = now
    # Only families determined this run overwrite what was last known.
    known = st.setdefault("last_known", {})
    for version, nets in det.desired.items():
        if nets is not None:
            known[str(version)] = [to_cf(n) for n in nets]
    if changes:
        st["last_change"] = now
    previous = st.get("consecutive_failures")
    if not isinstance(previous, int) or isinstance(previous, bool) or previous < 0:
        previous = 0
    failures = previous + 1 if det.errors else 0
    st["consecutive_failures"] = failures
    try:
        state.save(state_path, st)
    except OSError as e:
        log.error("could not save state: %s", e)

    if not det.errors:
        hc.success(summary)
        return EXIT_OK
    threshold = cfg.healthchecks.failure_threshold
    if failures >= threshold:
        hc.fail(f"{failures} consecutive failed run(s)\n{summary}")
    else:
        # /log records the details without alerting; the check stays up until
        # the threshold is reached (or period + grace passes with no success).
        hc.log(f"failure {failures}/{threshold}\n{summary}")
    return EXIT_FAILED


def check(cfg):
    """Exercise every dependency without writing anything."""
    ok = True

    def report(name, fn):
        nonlocal ok
        try:
            print(f"  OK    {name}: {untrusted.describe(str(fn()), 300)}")
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"  FAIL  {name}: {untrusted.describe(str(e), 300)}")

    print("FortiGate:" if cfg.fortigate.enabled else "FortiGate: disabled")
    if cfg.fortigate.enabled:
        fg = FortiGateClient(cfg.fortigate)
        report("WAN IPv4", fg.wan_ipv4)
        if cfg.general.ipv6:
            report("delegated IPv6 prefixes",
                   lambda: ", ".join(map(str, fg.delegated_prefixes())) or "none found")

    def echo(version, services):
        addr = detect_web.detect(version, services, cfg.echo.quorum, cfg.echo.timeout)
        if addr is None:
            raise RuntimeError(f"no quorum ({cfg.echo.quorum}) among {len(services)} services")
        return addr

    print("Echo services:")
    if cfg.general.ipv4:
        report("IPv4", lambda: echo(4, cfg.echo.ipv4_services))
    if cfg.general.ipv6:
        report("IPv6", lambda: echo(6, cfg.echo.ipv6_services))

    print("Cloudflare:")
    cf = CloudflareClient(cfg.cloudflare)

    def list_info():
        info = cf.get_list()
        if info.get("kind") != "ip":
            raise RuntimeError(f"list {info.get('name')!r} is kind {info.get('kind')!r}, not 'ip'")
        return f"{info.get('name')!r}, {info.get('num_items')} item(s)"

    def managed():
        items = [i for i in cf.list_items()
                 if reconcile.is_managed(i, cfg.cloudflare.comment_marker)]
        return ", ".join(i["ip"] for i in items) or "none yet"

    report("list", list_info)
    report("managed items", managed)

    print("Healthchecks:" if cfg.healthchecks.ping_url else "Healthchecks: not configured")
    if cfg.healthchecks.ping_url:
        # /log records an event without changing the check's up/down state.
        report("ping /log", lambda: Healthchecks(cfg.healthchecks.ping_url).log("--check") or "sent")
    return EXIT_OK if ok else EXIT_FAILED


def dump_fortigate(cfg):
    if not cfg.fortigate.enabled:
        print("FortiGate is disabled in config", file=sys.stderr)
        return EXIT_CONFIG
    fg = FortiGateClient(cfg.fortigate)
    out = {}
    for name, fn in (("monitor/system/interface", fg.monitor_interface),
                     ("monitor/router/ipv6", fg.ipv6_routes)):
        try:
            out[name] = fn()
        except FortiGateError as e:
            out[name] = {"error": str(e)}
    print("# Contains real addresses/serials: redact before sharing.", file=sys.stderr)
    print(json.dumps(out, indent=2))
    return EXIT_OK


class EscapeFilter(logging.Filter):
    """Escape control and non-ASCII characters in every log message, so text that
    originated outside (error strings, response fragments) can't forge log lines
    or inject terminal escape sequences."""

    def filter(self, record):
        record.msg = untrusted.describe(record.getMessage(), 2000)
        record.args = None
        return True


def setup_logging(cfg, verbose):
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")

    escape = EscapeFilter()
    console = logging.StreamHandler()
    console.addFilter(escape)
    console.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    console.setLevel(logging.DEBUG if verbose else
                     logging.INFO if sys.stderr.isatty() else logging.WARNING)
    root.addHandler(console)

    try:
        cfg.general.log_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            cfg.general.log_dir / "cf-iplist-updater.log", maxBytes=1_000_000, backupCount=5)
        fh.setFormatter(fmt)
        fh.addFilter(escape)
        fh.setLevel(logging.DEBUG if verbose else logging.INFO)
        root.addHandler(fh)
    except OSError as e:
        log.warning("file logging disabled: %s", e)


def acquire_lock(cfg):
    cfg.general.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(cfg.general.state_dir / "run.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return None
    return fd


def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="cf-iplist-updater",
        description="Sync a Cloudflare IP List with this site's current public addresses.")
    ap.add_argument("--config", default=str(DEFAULT_CONFIG), help="path to config.toml")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true",
                      help="detect and show changes without writing or pinging Healthchecks")
    mode.add_argument("--check", action="store_true",
                      help="test FortiGate, echo services, Cloudflare and Healthchecks access")
    mode.add_argument("--dump-fortigate", action="store_true",
                      help="print raw FortiGate API responses used for detection")
    ap.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        cfg = config.load(args.config)
    except config.ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return EXIT_CONFIG

    setup_logging(cfg, args.verbose)
    if args.check:
        return check(cfg)
    if args.dump_fortigate:
        return dump_fortigate(cfg)

    lock = acquire_lock(cfg)
    if lock is None:
        log.warning("another run is in progress; exiting")
        return EXIT_LOCKED
    try:
        return run(cfg, dry_run=args.dry_run)
    finally:
        os.close(lock)
