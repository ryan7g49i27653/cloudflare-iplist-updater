# cloudflare-iplist-updater

Keeps a [Cloudflare IP List](https://developers.cloudflare.com/waf/tools/lists/custom-lists/#ip-lists)
in sync with a site's dynamic public addresses, so IP-restricted Cloudflare
rules keep working when the ISP hands out a new IPv4 lease or IPv6 delegated
prefix. Runs from cron, uses only the Python standard library (3.11+), and
reports to [Healthchecks.io](https://healthchecks.io).

## How it works

Each run:

1. **IPv4** is read from the FortiGate's WAN interface
   (`GET /api/v2/monitor/system/interface`). If the FortiGate is unreachable or
   reports a non-public address, IP echo services are used instead. At least
   `quorum` of them must agree.
2. **IPv6 delegated prefixes** are read from the FortiGate's IPv6 routing table
   (`GET /api/v2/monitor/router/ipv6`). The REST API doesn't expose the
   delegated prefix directly; only the CLI shows it, under `config ipv6` → `get`.
   But each LAN interface using it has a connected route for its subnet. Every
   global connected route on a non-WAN interface (or on `lan_interfaces`) is
   allowlisted, so several LANs or IAIDs are covered.

   If the FortiGate is unreachable, the server's public IPv6 address comes from
   echo services instead. If it's still inside a last-known prefix, the
   last-known set is kept. Otherwise it's masked to the last-known prefix length
   or to `fallback_prefix_length`.
3. **Reconcile**: the live list is read every run. Only items whose comment
   contains `comment_marker` are managed: missing entries are added, stale ones
   removed (adds first, so there's never a gap). Manually added items are
   never touched.
4. **Report**: success pings Healthchecks. Failures are sent to `/log` (no alert)
   until `failure_threshold` consecutive failures, then `/fail` (alert).
   Healthchecks also alerts if no successful ping arrives within period + grace,
   which covers cron or the server being down.

### Safety rules

- If an address family can't be determined, that family's entries are left
  alone, so a transient outage never strips the allowlist. The run still
  counts as failed.
- Only globally routable addresses are accepted (no RFC 1918, CGNAT or ULA).
- IPv6 prefixes must fit Cloudflare's accepted /12–/64 range.

## Setup

### Cloudflare
1. Create an IP List: *Manage Account → Configurations → Lists* (type **IP**).
   The list ID is in its URL.
2. Create an API token: *My Profile → API Tokens → Custom token*, permission
   **Account → Account Filter Lists → Edit**, scoped to that one account.
   Optionally restrict it to your client IPs.

### FortiGate (FortiOS 7.x)
1. Create a REST API admin: *System → Administrators → Create New → REST API Admin*.
   - Use an admin profile with **Read** (not Read/Write) access to **System** and
     **Network**. A narrower profile gets HTTP 403 from the monitor endpoints.
   - Set **Trusted Hosts** to this server's LAN address only.
2. In `config.toml`, use the hostname on the FortiGate's certificate so TLS
   verification works.
3. To see exactly what the script reads:
   `python3 -m cf_iplist_updater --dump-fortigate` (redact before sharing).

#### FortiGate TLS
FortiGates often serve their Let's Encrypt certificate **without the
intermediate**. Browsers cope with that; curl and Python fail with *unable to
get local issuer certificate*. To check what the FortiGate sends:

```bash
openssl s_client -connect fw.example.net:443 -servername fw.example.net -showcerts </dev/null 2>/dev/null | grep -E '^ *[0-9]+ s:|^ +i:'
```

If only `0 s:` is listed, there are two ways to fix it.

**Preferred: fix it on the FortiGate.** Import the missing CA certificates under
*System → Certificates → Import → CA Certificate* so the full chain is served.

**Or: give the app the missing certificates.** `ca_file` is *added* to the
system trust store. For Let's Encrypt's current "Gen Y" ECDSA chain (leaf issued
by `YE1`–`YE3`), the missing pieces are the intermediate and Root YE
cross-signed by ISRG Root X2. Ubuntu already trusts ISRG Root X2. The
`/etc/ssl/certs` line appends ISRG Root X2 itself, so curl's `--cacert`, which
replaces the system store, can use the same file:

```bash
cd /usr/local/scripts/cloudflare-iplist-updater
{ curl -fsS https://letsencrypt.org/certs/gen-y/int-ye2.pem \
       https://letsencrypt.org/certs/gen-y/root-ye-by-x2.pem
  cat /etc/ssl/certs/ISRG_Root_X2.pem; } | sudo tee fortigate-ca.pem >/dev/null
```

Then set `ca_file = "fortigate-ca.pem"` in `[fortigate]`. Use the intermediate
matching your certificate's issuer (`YE1`/`YE2`/`YE3`, or `YR1`–`YR3` for RSA);
see <https://letsencrypt.org/certificates/>.

Let's Encrypt rotates among sibling intermediates, so a renewal can switch your
issuer, for example from YE2 to YE1. That breaks the app-side fix until you
update the file. Fixing the chain on the FortiGate avoids that.

### Healthchecks.io
Create a check:
- **Period** 15 minutes
- **Grace** about 45 minutes
- An integration of your choice (mobile app, Pushover, Discord, SMS, …)

Put its ping URL in `config.toml`.

### Server
```bash
sudo git clone git@github.com:<you>/cloudflare-iplist-updater.git /usr/local/scripts/cloudflare-iplist-updater
cd /usr/local/scripts/cloudflare-iplist-updater
sudo deploy/install.sh               # service user, state/logs dirs, config.toml, cron.d
sudoedit config.toml
sudo -u cfipupdater python3 -m cf_iplist_updater --check
sudo -u cfipupdater python3 -m cf_iplist_updater --dry-run
sudo -u cfipupdater python3 -m cf_iplist_updater
```
Cron (`/etc/cron.d/cloudflare-iplist-updater`) runs it every 15 minutes.

**Logs:**
- `logs/cf-iplist-updater.log` (rotated)
- `state/state.json` holds the last result, the cached prefix length and the failure count.

**Updating:** run `git pull` in the app directory. Your config, state and logs are gitignored.

## Usage

```
python3 -m cf_iplist_updater [--config PATH] [--dry-run | --check | --dump-fortigate] [-v]
```

| Option | Effect |
| --- | --- |
| *(none)* | Detect, reconcile, ping Healthchecks |
| `--dry-run` | Detect and print planned changes; no writes, no pings |
| `--check` | Test FortiGate, echo services, Cloudflare list access and Healthchecks (`/log` only) |
| `--dump-fortigate` | Print the raw FortiGate API responses used for detection |
| `-v` | Debug logging |

Exit codes:
- `0` OK
- `1` run failed
- `2` config error
- `75` another run is in progress

## Development

```bash
python3 -m unittest discover -s tests -t .
```

Tests and examples use documentation address ranges only
(`192.0.2.0/24`, `198.51.100.0/24`, `2001:db8::/32`).
