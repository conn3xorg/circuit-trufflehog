# circuit-trufflehog

A Conn3x circuit that installs TruffleHog on your hosts and, if you give it paths, looks through them for secrets on a timer. Each host gets a pinned TruffleHog, checked against its checksum. Point it at `/etc`, `/srv` or wherever your apps keep their config, and every morning there's a list on the host of the API keys, tokens, passwords in URLs and private keys sitting in plain files, with the file and line for each.

It only looks. Nothing is moved, rotated or deleted, and the scan runs in a systemd sandbox that makes the whole host read-only to it apart from its results directory.

## Usage

```hcl
module "trufflehog" {
  source = "github.com/conn3xorg/circuit-trufflehog?ref=v0.1.0"

  hosts                = { web = "203.0.113.10", db = "203.0.113.11" }
  ssh_private_key_file = "~/.ssh/id_ed25519"

  targets       = ["/etc", "/home", "/root", "/opt", "/srv"]
  exclude_paths = ["^/etc/ssh/ssh_host_.*_key$"]
  schedule      = "daily"
  run_now       = true
}
```

Then run `conn3x init` and `conn3x apply`. With `run_now`, the apply scans each host once. A second `conn3x plan` says `No changes.`

The results are on each host under `/var/lib/conn3x-trufflehog/latest`:

```sh
ssh root@203.0.113.10 cat /var/lib/conn3x-trufflehog/latest/summary.txt
ssh root@203.0.113.10 cat /var/lib/conn3x-trufflehog/latest/findings.json
```

`summary.txt` has a line for each detector and whether the secret was confirmed to work, with a count:

```
PrivateKey unverified 2
SlackWebhook unverified 1
URI verified 1
```

`verified` means TruffleHog tried the secret against the service it belongs to and it worked. That one wants rotating today.

Leave `targets` out and you get TruffleHog installed at `/usr/local/bin/trufflehog` with no timer, for running by hand or from your own jobs.

To try it on a throwaway container first, see [examples/local](examples/local).

## Choosing what to scan

`targets` is a list of absolute paths, scanned together into one report. `/` isn't allowed: `/proc` and `/sys` aren't files, and there's rarely anything in `/usr` worth the hours. Name the directories where people and programs leave config, such as `/etc`, `/home`, `/root`, `/opt`, `/srv` and `/var/www`. Every target has to exist, or the scan fails rather than report a clean host it never read.

`exclude_paths` takes regular expressions, in Go's syntax, matched against each file's absolute path:

```hcl
exclude_paths = [
  "^/etc/ssh/ssh_host_.*_key$", # the host's own SSH keys
  "^/srv/backups/",
  "\\.log$",
]
```

The host's SSH keys are worth leaving out if you scan `/etc`. They're private keys, so TruffleHog reports them on every host, every day, and a list you've learned to skim is a list that hides the one new key. `/var/lib/conn3x-trufflehog` is always left out, since the findings in it would be found again.

### Verification

With `verify` on, as TruffleHog has it by default, each secret found is sent to the service it belongs to, to see whether it works: an AWS key to AWS, a Slack webhook to Slack. That's what tells a live key from a dead one. It also means the scan reaches the internet, and that the secret leaves the host, to the place that issued it.

Set `verify = false` to keep everything on the host. Every finding is then `unverified`, which means only that it matched a detector's pattern.

`results` picks what gets reported. `["verified"]` lists only secrets confirmed to work, which is quiet, and misses every secret for a service TruffleHog can't check. The default reports all three kinds.

## What it does

Before the circuit runs, the `conn3x_host` data source reads each host's architecture and distribution over SSH. Then, on each host:

1. Installs `curl`, `tar` and `gzip`.
2. Downloads the release tarball to `/opt/trufflehog`, checks it against `checksums`, unpacks it to `/opt/trufflehog/<version>` and links `/usr/local/bin/trufflehog` to it.

With `targets`, it also:

3. Writes the exclusions to `/etc/conn3x-trufflehog/exclude`, and `/usr/local/sbin/conn3x-trufflehog`, the script that runs a scan.
4. Writes the sandbox as a drop-in, `/etc/systemd/system/conn3x-trufflehog.service.d/sandbox.conf`, and a systemd timer, `conn3x-trufflehog.timer`, that runs the script on `schedule`. The timer is `Persistent`, so a scan missed while the host was off runs soon after it's back.
5. With `run_now`, scans.

Each scan writes a directory named for its start time in UTC under `/var/lib/conn3x-trufflehog`, and points `latest` at it:

| File | What it is |
| --- | --- |
| `findings.json` | One JSON object per line, per finding: the detector, the file and line, whether it was verified, and the secret itself. |
| `summary.txt` | A count of findings for each detector and verification result. |
| `trufflehog.log` | What `trufflehog` logged, including files it couldn't read. |

The newest `keep` scans are kept, and older ones are deleted. `/var/lib/conn3x-trufflehog` is readable by root only, because `findings.json` holds every secret it lists. Copy it off a host with the same care as the secrets.

TruffleHog exits 0 whatever it finds, so `conn3x-trufflehog.service` only fails when a scan itself failed, such as a target that doesn't exist. Then `latest` stays on the last good scan, and the end of `trufflehog.log` goes to the journal.

To scan now, outside the schedule:

```sh
systemctl start conn3x-trufflehog.service
```

### The sandbox

The scan runs as root because it has to read everything, so the service is held to reading:

- `ProtectSystem=strict` mounts the whole filesystem read-only for the service, except `/var/lib/conn3x-trufflehog`.
- `CapabilityBoundingSet=CAP_DAC_READ_SEARCH` leaves it the one capability for reading past file permissions.
- `NoNewPrivileges` and `PrivateTmp` are on, and it runs at `Nice=19` with idle IO priority. `PrivateTmp` means `/tmp` isn't scanned.

This applies when the scan runs through `conn3x-trufflehog.service`, as the timer and `run_now` do. Running `/usr/local/sbin/conn3x-trufflehog` by hand doesn't get it. In a container that wasn't given `CAP_DAC_READ_SEARCH`, as Podman's defaults don't, the scan can't read files only root may read, such as `/etc/shadow`, and logs them in `trufflehog.log`. On a real host it reads them.

### Updating TruffleHog

TruffleHog releases often. To move to a newer one, check its checksums file against the signature on the release, then pass the version and both checksums:

```sh
v=3.99.8
for f in checksums.txt checksums.txt.pem checksums.txt.sig; do
  curl -sSfLO "https://github.com/trufflesecurity/trufflehog/releases/download/v$v/trufflehog_${v}_$f"
done
cosign verify-blob "trufflehog_${v}_checksums.txt" \
  --certificate "trufflehog_${v}_checksums.txt.pem" --signature "trufflehog_${v}_checksums.txt.sig" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/trufflesecurity/trufflehog/'
grep -E 'linux_(amd64|arm64)\.tar\.gz$' "trufflehog_${v}_checksums.txt"
```

```hcl
trufflehog_version = "3.99.8"
checksums = {
  amd64 = "7c3b02f160f28929a467e29e20fba98746e0729f6e37c3c25761e4f8789abe08"
  arm64 = "a0382d83dd58c967af5dd0175cc732c62c836ab1d15dc9ae71b01a2d3f0911b2"
}
```

The scan runs with `--no-update`, so TruffleHog never replaces itself.

### What it doesn't do

- It doesn't rotate, move or delete anything, and it doesn't send the results anywhere. Copy them off, or point your own tooling at the JSON.
- It doesn't scan git history, container images or cloud buckets. TruffleHog can, by hand: `trufflehog git`, `trufflehog docker` and the rest are all in the binary it installs.
- It doesn't find every secret. A password with no pattern to it, in a file with no hint of what it is, looks like any other string.
- It doesn't keep old versions tidy. A new `trufflehog_version` leaves the previous one under `/opt/trufflehog`.
- It doesn't support other distributions or releases, and the plan stops on them. TruffleHog itself is one static binary, so the limit is only what's been tested here.
- Deleting the module, or emptying `targets`, stops and removes the timer, and leaves TruffleHog and the reports in place.

## Inputs

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `hosts` | any | Required | Hosts to configure, by name. Each value is an address, such as `"203.0.113.10"`, or a host object such as `{ address = "203.0.113.10", host_key = "ssh-ed25519 AAAA..." }`. A host object can also set `user`, `port`, `private_key_file` and `jump_hosts`. The two forms can be mixed. |
| `ssh_user` | string | `"root"` | User to log in as. |
| `ssh_port` | number | `22` | SSH port. |
| `ssh_private_key_file` | string | `null` | Path to a private key. When null, Conn3x uses the SSH agent. |
| `ssh_known_hosts_file` | string | `null` | known_hosts file to check host keys against. When null, `~/.ssh/known_hosts`. Not used for a host object with `host_key`. |
| `ssh_become` | bool | `false` | Run commands as root through sudo. Set it when `ssh_user` isn't root. |
| `trufflehog_version` | string | `"3.99.8"` | TruffleHog release to install. See [Updating TruffleHog](#updating-trufflehog). |
| `checksums` | map(string) | SHA-256s of 3.99.8 | SHA-256 of the release tarball, by `amd64` and `arm64`. Change it with `trufflehog_version`. |
| `targets` | list(string) | `[]` | Absolute paths to scan on a timer, into one report. Empty installs TruffleHog with no scan. |
| `exclude_paths` | list(string) | `[]` | Regular expressions for files to leave out, matched against each file's absolute path. |
| `verify` | bool | `true` | Check each secret against the service it belongs to. See [Verification](#verification). |
| `results` | list(string) | `["verified", "unknown", "unverified"]` | Which findings to report. |
| `schedule` | string | `"daily"` | When the scan timer runs, as a systemd `OnCalendar` expression such as `"daily"` or `"Sun 03:00"`. |
| `keep` | number | `7` | Number of scans to keep on each host. |
| `run_now` | bool | `false` | Scan during the apply: the first time, and again when the scan's settings change. |

## Outputs

| Name | Description |
| --- | --- |
| `results_dir` | `/var/lib/conn3x-trufflehog`, which holds one directory per scan. Null with no `targets`. |
| `summary` | Counts by detector from the latest scan, `/var/lib/conn3x-trufflehog/latest/summary.txt`. Null with no `targets`. |
| `findings` | The latest scan's findings, `/var/lib/conn3x-trufflehog/latest/findings.json`. Null with no `targets`. |

## Requirements

Requires Conn3x v0.7.0 or later and systemd on each host, on x86_64 or aarch64. Hosts need to reach GitHub for the release, and, with `verify` on, the services whose secrets they find.

## Tested on

Ubuntu 24.04, Debian 13, Rocky Linux 10 and Fedora 45, with TruffleHog 3.99.8. [examples/local](examples/local) was applied to each in a container on arm64, and CI does the same on amd64: it checks that the second plan has no changes, plants the placeholder Slack webhook from Slack's documentation under `/opt`, scans `/etc`, `/home`, `/root`, `/opt` and `/srv` through `conn3x-trufflehog.service` with `verify` off, and checks that the findings name the webhook and its file, leave out the excluded SSH host keys, and that the scan changed no files outside its results directory, the logs and systemd's state. It then restarts the container, checks the timer is back, and scans again. With no `targets`, the apply installed TruffleHog alone and the second plan had no changes.

On an Ubuntu 24.04 droplet and a Rocky Linux 10 droplet with SELinux enforcing, both `s-1vcpu-1gb`, the circuit was applied with `run_now` and the same check passed. There the scan read `/etc/shadow` and the other root-only files without a single permission error, through the one capability the sandbox leaves it. A scan of those five directories took about 15 seconds of CPU and peaked at 700 MB of memory. The Rocky droplet's own findings were a private key, the self-signed certificate Cockpit makes when something first connects to port 9090, and a pattern match in `/etc/bluetooth/main.conf` that isn't a secret at all. After a reboot the timer was active, the plan had no changes and another scan ran.

## License

MPL-2.0. See [LICENSE](LICENSE). TruffleHog is AGPL-3.0, and this circuit downloads it unchanged from its GitHub release.
