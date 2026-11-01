# cloudflare-iplist-updater

Keeps a [Cloudflare IP List](https://developers.cloudflare.com/waf/tools/lists/custom-lists/#ip-lists)
in sync with a site's dynamic public addresses, so IP-restricted Cloudflare
rules keep working when the ISP hands out a new IPv4 lease or IPv6 delegated
prefix. Runs from cron, uses only the Python standard library (3.11+), and
reports to [Healthchecks.io](https://healthchecks.io).

## How it works

Each run:

1. **IPv4** is read from the FortiGate's WAN interface
   (`GET /api/v2/monitor/system/interface`, with `include_vlan` and
   `include_aggregate` so VLAN and redundant/aggregate WANs are found). If the FortiGate is unreachable or
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
2. Create an API token (*Manage Account → Account API Tokens*, or
   *My Profile → API Tokens*) → *Custom token*, permission
   **Rules & Configuration → Account Rule Lists → Edit** (formerly "Account
   Filter Lists"), scoped to that one account. Search the permission groups
   for `list` to find it.
   **Don't** set Client IP Address Filtering: the token is used precisely when
   your IP has just changed, so an IP-restricted token would lock itself out.

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
  cat /etc/ssl/certs/ISRG_Root_X2.pem; } > fortigate-ca.pem
```
The file holds only public certificates. It must be readable by the account cron runs as.

Then set `ca_file = "fortigate-ca.pem"` in `[fortigate]`. Use the intermediate
matching your certificate's issuer (`YE1`/`YE2`/`YE3`, or `YR1`–`YR3` for RSA);
see <https://letsencrypt.org/certificates/>.

Let's Encrypt rotates among sibling intermediates, so a renewal can switch your
issuer, for example from YE2 to YE1. That breaks the app-side fix until you
update the file. Fixing the chain on the FortiGate avoids that.

### Healthchecks.io
Create a check:
- **Period:** 15 minutes, matching the cron schedule.
- **Grace:** about 30 minutes.
- **Integration:** enable at least one (mobile app, Pushover, Discord, SMS, …).
  Without one, the check turns red but nobody is told. Use the integration's
  **Test** button to confirm delivery.

Put its ping URL in `config.toml`.

There are two alert paths, and with these settings both fire about 45 minutes
after the last good run:

| Failure | Behaviour |
| --- | --- |
| The script runs but fails | Failures are sent to `/log`, which records the error without alerting. The `failure_threshold`-th consecutive failure (default 3) sends `/fail`, which alerts immediately. |
| The script doesn't run (server down, cron broken) | No pings arrive. Healthchecks alerts after period + grace. |

Keep grace ≈ (`failure_threshold` − 1) × 15 minutes so the two paths line up.
A new check stays quiet until its first ping. `--check` sends a `/log` event,
which doesn't count as a success.

### Server
The script needs no root privileges. Run it as an unprivileged account, and run
your manual tests **as the same account cron uses**. The script creates
`state/` and `logs/` on its first run, so if they end up owned by a different
user, every scheduled run fails.

Clone it into a directory of your choice. This README uses
`/usr/local/scripts/cloudflare-iplist-updater`:

```bash
sudo git clone https://github.com/<owner>/cloudflare-iplist-updater.git /usr/local/scripts/cloudflare-iplist-updater
cd /usr/local/scripts/cloudflare-iplist-updater
```

Then choose one of the following.

#### Option A: dedicated service user (recommended)
`deploy/install.sh` is a short, idempotent helper. It:
- creates a `cfipupdater` system user with no login shell and no home directory;
- creates `state/` and `logs/` owned by that user (mode 0700);
- copies `config.example.toml` to `config.toml` (mode 0600, owned by that user);
- installs `/etc/cron.d/cloudflare-iplist-updater`.

Code stays owned by whoever cloned it, so the service user can't modify it.
Override the user name with `SERVICE_USER=name`.

```bash
sudo deploy/install.sh
sudoedit config.toml
```
Prefix the test commands below with `sudo -u cfipupdater`.

#### Option B: an existing account, without the installer
For an existing account (e.g. your own), the account must own the directory:

```bash
sudo chown -R "$USER": /usr/local/scripts/cloudflare-iplist-updater
cp config.example.toml config.toml && chmod 600 config.toml
$EDITOR config.toml
crontab -e
```

Add this crontab line:
```
7-59/15 * * * * cd /usr/local/scripts/cloudflare-iplist-updater && /usr/bin/python3 -m cf_iplist_updater >/dev/null 2>&1
```
Run the test commands below without a prefix.

### Configure
Edit `config.toml`; every key is documented in `config.example.toml`. At minimum:

- **`[cloudflare]`:** `api_token`, `account_id`, `list_id`. The list ID is also
  returned by `GET /accounts/<account_id>/rules/lists`.
- **`[fortigate]`:** `host` (the name on its certificate), `port`, `api_token`,
  `wan_interface`, and `ca_file` if needed (see [FortiGate TLS](#fortigate-tls)).
- **`[healthchecks]`:** `ping_url`.

`config.toml` must be mode 0600; the script refuses to read it otherwise.

### Test the deployment
Run these from the app directory, as the account cron uses. Each is safe to repeat.

1. **Check connectivity.** Nothing is changed.
   ```bash
   python3 -m cf_iplist_updater --check
   ```
   Every line should read `OK`: the FortiGate WAN IPv4 and delegated IPv6
   prefixes, both echo families, the Cloudflare list (kind `ip`), the managed
   items, and the Healthchecks `/log` ping. Each `FAIL` line names the
   dependency at fault.

2. **Preview the changes.** Nothing is written and Healthchecks isn't pinged.
   ```bash
   python3 -m cf_iplist_updater --dry-run -v
   ```
   On a first run, expect `[dry-run] add …` lines for your IPv4 address and
   each delegated prefix.

3. **Do a real run.** This is exactly what cron runs.
   ```bash
   python3 -m cf_iplist_updater -v; echo "exit=$?"
   ```
   Expect `exit=0`. The new list entries have comments starting with
   `managed-by:cf-iplist-updater`, and existing manual entries are untouched.
   The Healthchecks check turns green. A second run should log
   `Cloudflare list already up to date`.

4. After the next scheduled run (:07, :22, :37 or :52), confirm it in the
   Healthchecks event log or in `logs/cf-iplist-updater.log`.

### Files
| Path | Contents |
| --- | --- |
| `config.toml` | Your settings and secrets (gitignored, 0600) |
| `fortigate-ca.pem` | Optional CA bundle (gitignored) |
| `logs/cf-iplist-updater.log` | Run log, rotated at 1 MB × 5 |
| `state/state.json` | Last-known addresses per family, last change, consecutive-failure count |
| `state/run.lock` | Prevents overlapping runs |

**Updating:** run `git pull` in the app directory. Your config, CA bundle, state
and logs are gitignored.

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

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `unable to get local issuer certificate` (FortiGate) | The FortiGate doesn't send its intermediate certificate; see [FortiGate TLS](#fortigate-tls) |
| FortiGate `HTTP 403` | The API admin profile lacks Read access to System/Network, or this server isn't in the admin's Trusted Hosts |
| `interface '…' not in monitor response` | Wrong `wan_interface` name (it's case-sensitive) |
| Cloudflare `[10000] Authentication error` | Token is missing **Account Rule Lists → Edit**, is scoped to another account, or is IP-restricted |
| Cloudflare `[7003] Could not route…` | Wrong `account_id` or `list_id` |
| Works manually, fails from cron | Manual runs and cron use different accounts, so `state/`, `logs/` or `config.toml` are owned by the other one. `chown` them to the cron account |
| `config error: … mode -rw-r--r--` | Run `chmod 600 config.toml` |
| IPv6 comes from echo services instead of the FortiGate | No global connected IPv6 route on a non-WAN interface; check `--dump-fortigate` and `lan_interfaces` |

## Development

```bash
python3 -m unittest discover -s tests -t .
```

Tests and examples use documentation address ranges only
(`192.0.2.0/24`, `198.51.100.0/24`, `2001:db8::/32`).
