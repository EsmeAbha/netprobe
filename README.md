# netprobe

**"The site is slow / down." Where exactly?** netprobe breaks each request into **DNS → TCP connect → TLS handshake → time to first byte**, says which phase failed in plain English, and warns before TLS certificates expire. It runs as a one-off CLI or as a Prometheus exporter.

Go standard library only, with no third-party dependencies.

```text
$ netprobe check https://github.com https://expired.badssl.com https://wrong.host.badssl.com tcp://github.com:8443 dns://does-not-exist.invalid -timeout 5s
TARGET                         RESULT         DNS ms  CONNECT ms  TLS ms  TTFB ms  TOTAL ms  STATUS  CERT DAYS  DETAIL
https://github.com             OK             16.1    52.4        82.3    55.9     208.2     200     34         20.205.243.166:443
https://expired.badssl.com     FAIL(tls)      367.5   264.8       -       -        1061.4    -       -          TLS: certificate expired or not yet valid
https://wrong.host.badssl.com  FAIL(tls)      211.5   268.3       -       -        927.8     -       -          TLS: certificate is not valid for this hostname: ...
tcp://github.com:8443          FAIL(connect)  16.6    4983.8      -       -        5000.4    -       -          timeout: dial tcp 20.205.243.166:8443: i/o timeout
dns://does-not-exist.invalid   FAIL(dns)      15.6    -           -       -        15.6      -       -          DNS: no such host (NXDOMAIN): does-not-exist.invalid
```
(Real output, trimmed. The exit code is 1 when anything fails, so it works in cron jobs and CI.)

## Targets

| Form | Measures |
|---|---|
| `https://host/path`, `http://...` | DNS, connect, TLS, TTFB, total · HTTP status · certificate. Redirects are reported, not followed. |
| `tls://host:port` | DNS, connect, TLS handshake + certificate for **any** TLS service (SMTPS, Postgres with TLS, LDAPS) |
| `tcp://host:port` | DNS + connect: "is the port reachable from here?" |
| `dns://host` | Resolution time and addresses |

## Use

```bash
go install github.com/EsmeAbha/netprobe/cmd/netprobe@latest
netprobe check https://example.com tcp://db.internal:5432
netprobe check -json -f targets.txt                  # one target per line, # comments
netprobe serve -listen :9115 -f targets.txt          # Prometheus exporter
```
Flags: `-timeout 10s`, `-insecure` (skip verification but still report the certificate), `-cert-warn-days 14`.

### As a Prometheus exporter
Every scrape probes all targets in parallel, the same model as blackbox_exporter, so results are never staler than the scrape interval.

| Metric | |
|---|---|
| `netprobe_up{target,kind,failed_phase}` | 1 = success. `failed_phase` says where it broke. |
| `netprobe_phase_seconds{target,phase}` | dns / connect / tls / ttfb / total |
| `netprobe_http_status_code{target}` | |
| `netprobe_tls_cert_expiry_days{target,subject}` | |

`deploy/alerts.yaml` holds alert rules: probe failing (page), flapping (ticket), certificate expiring in under 14 days (ticket) and under 3 days (page), and slow TTFB. `deploy/kubernetes.yaml` runs it in a cluster as a non-root, read-only container with a ConfigMap of targets. CI validates both.

## Reading the phases: a debugging guide

| Slow or failing phase | Usually means | Next step |
|---|---|---|
| **DNS** slow | Resolver is far away, overloaded, or the record has a tiny TTL so nothing is cached | `dig +trace host`; check `/etc/resolv.conf`; in Kubernetes, check CoreDNS and `ndots` |
| **DNS** NXDOMAIN | Typo, record deleted, wrong search domain, split-horizon DNS | Compare `dig @8.8.8.8 host` with the internal resolver |
| **Connect** timeout | Packets dropped: firewall or security group, wrong route, host down | Security group / NACL / `iptables`; `traceroute -T -p PORT` |
| **Connect** refused | Host reachable, but nothing is listening on that port | `ss -tlnp` on the server; is the service bound to 127.0.0.1 only? |
| **Connect** slow but OK | Network distance (RTT) or SYN backlog under load | Compare with ping RTT; check `netstat -s` for listen drops |
| **TLS** failure | Expired certificate, wrong hostname (SAN), missing intermediate, clock skew | `openssl s_client -connect host:443 -servername host -showcerts` |
| **TLS** slow | Several round trips + RSA handshakes; OCSP; overloaded TLS terminator | Enable TLS 1.3 and session resumption; check LB CPU |
| **TTFB** slow | The **application** is slow: everything below it is fine | App metrics, database queries, upstream calls |

## Engineering notes

- **Fresh connection every probe** (`DisableKeepAlives`). Otherwise later probes reuse a connection and DNS, connect and TLS look like zero.
- **A phase is recorded only when it succeeds**, so the first missing phase is where the failure happened.
- **Errors are translated** (NXDOMAIN, refused, timeout, unknown CA, hostname mismatch, expired) so an on-call engineer at 3 a.m. doesn't have to decode Go error strings.
- **Tests run real servers:** plain HTTP, TLS with a trusted CA, an untrusted CA, a certificate generated to expire in 3 days, refused ports, timeouts, NXDOMAIN. CI runs `-race`, `govulncheck`, cross-compiles for Linux, macOS and Windows, checks the alert rules with `promtool`, and smoke-tests the container image.
- **Container:** distroless static image, non-root, read-only filesystem, graceful shutdown on SIGTERM.
