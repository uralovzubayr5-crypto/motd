# MOTD

A lightweight SSH behaviour digest for small servers: flags impossible-travel logins,
brand-new authorized keys, and sudo bursts — delivered as one line (or a short email)
per day instead of a log-hunting session.

Built by [Zubayr Uralov](https://github.com/uralovzubayr5-crypto).

## Why

Small servers do not get a SIEM. But three things catch most real incidents:

1. logins from two countries inside an hour (impossible travel)
2. a new `authorized_keys` entry nobody admits to adding
3. a burst of failed sudo attempts right before something changed

MOTD keeps a tiny SQLite baseline per account and scores those three every day.

## Install

```sh
git clone https://github.com/uralovzubayr5-crypto/motd
cd motd
sudo install -m 0755 motd/audit.py /usr/local/bin/motd-audit
sudo install -d /var/lib/motd
sudo install -m 0644 systemd/motd-audit.{service,timer} /etc/systemd/system/
sudo systemctl enable --now motd-audit.timer
```

## Samples

```
$ motd-audit
brute force: 84 failures for root from 203.0.113.44
new key accepted: deploy (SHA256:q9Vk…)
sudo burst: 11 failed sudo attempts by ci-runner in 3 minutes

$ motd-audit   # quiet day
quiet day
```

## How it works

- `auth.log` → failed passwords, accepted keys, sudo failures (regex baseline)
- SQLite (`/var/lib/motd/baseline.sqlite`) → first-seen per key, per IP country, daily digests
- daily systemd timer → one digest a day; `--mail` to pipe through `sendmail`

## Config

| env var | default | meaning |
|---|---|---|
| `MOTD_DB` | `/var/lib/motd/baseline.sqlite` | SQLite file |
| `MOTD_AUTH` | `/var/log/auth.log` | auth log path (ignored if journald mode) |
| `MOTD_FAIL_THRESHOLD` | `10` | failures per user+IP before it is reported |

## License

MIT
