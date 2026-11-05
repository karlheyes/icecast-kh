# Post-KH22 upstream review

Review date: 5 November 2026. This review covers the local `master` snapshot
`ea3554b5167f6780a8be77f1715f90ed02005665` relative to KH22
`bb4173850be18466adc3c8b12a3b08d4b4ba1a55`. It does not claim that this snapshot
is the current tip of upstream GitHub.

The review preceded p3. That build includes the file-serving, TLS reload, and
Safari redirect fixes; see [validation.md](validation.md) for its results.

## Integration follow-up: p4

The p4 candidate integrates all ten reviewed commits through a history-preserving
merge with the fork's `master` at `ea3554b`. Commit `f23606b` retains p3 before
integration. The original findings below describe the earlier candidate.

P4 keeps the upstream CORS fixes and configured Server identity. The wildcard
origin now stays `*`, which suppresses the default credentials header instead of
reflecting an arbitrary origin. A fixed origin can be configured using the existing
`http-headers` block. `Vary: Origin` also covers redirects. Regression tests cover
admin, stream, redirect, and OPTIONS responses with default and explicit origins.

The upstream queue implementation is retained unchanged. A new comparative
120-second test runs eight fast listeners alongside four throttled listeners,
reconnects the slow listeners twice, then restarts the source. It checks queue
size, RSS, slow-listener eviction, fast-listener continuity, and audio decoding.
See the p4 section of [validation.md](validation.md) for measured results and
remaining limits. This short synthetic test does not establish production scale
or long-running behavior.

The stability branch started at KH22 to match the source revision in the
AzuraCast 0.24.0 recipe. That was a controlled comparison baseline; it does not
mean the later upstream changes are unnecessary or unsafe.

## Recommendation

Include the file-serving crash, TLS reload, and Safari URL fixes in the next
candidate. The configured Server header fix is also useful and passed its probe.
Include the CORS changes only with an explicit origin/credentials policy.
Evaluate queue pruning under slow-listener load before accepting it for release.

A merge can preserve upstream history, but the combined build needs its own
release identity and validation. The isolated comparison below passed the existing
regressions; the security and load conditions remain open. No merge or production
installation was performed, and the p2 release files were not replaced.

## Commit decisions

There are ten commits in the range: nine ordinary commits and one merge commit.
The merge brings in two CORS commits already listed below; it is not another fix.

| Commit    | Change                      | Recommendation             |
| --------- | --------------------------- | -------------------------- |
| `a8cfaae` | URL-auth file-serving crash | Include                    |
| `a676957` | Rename listener counter     | Keep with upstream history |
| `2416300` | Audio queue pruning         | Require load validation    |
| `36e21cb` | CORS credentials value      | Require origin policy      |
| `2224139` | CORS Authorization header   | Useful for web clients     |
| `c7aeda5` | TLS after failed reload     | Include                    |
| `a73a00e` | Merge of CORS PR #436       | No separate fix            |
| `f8efd57` | CORS on redirects           | Include with cache check   |
| `aae8fee` | Configured Server header    | Include                    |
| `ea3554b` | Safari long-query redirect  | Include                    |

## Confirmed benefits

### File-serving crash: a8cfaae

After listener URL authentication, the client can have no worker. Serving an MP3
file from a mount with `limit-rate` dereferences `client->worker` when initializing
the transfer timer. The p2 probe closed the connection and the server exited with
SIGSEGV (`-11`). The combined build returned HTTP 200 with audio bytes and exited
normally on SIGTERM. Using `time(NULL)` removes that dereference. This is a
separate path from the three fixes already included in p2.

### TLS reload: c7aeda5

The certificate reload function first clears `ssl_ok`. If loading a replacement
certificate fails, it keeps the old SSL context but previously left TLS disabled.
The probe starts TLS, removes its synthetic certificate, and sends SIGHUP. In p2,
the next TLS handshake timed out. The combined build returned HTTP 200 over TLS
using the previous certificate. The fix restores `ssl_ok` when retaining a valid
existing context; it does not make an invalid initial certificate usable.

### Safari redirect: ea3554b

The 512-byte query buffer can truncate both authentication/consent parameters and
the appended `_ic2` marker. A retry without that marker is redirected again.
This matches [upstream issue #440](https://github.com/karlheyes/icecast-kh/issues/440).
With a Safari User-Agent and query values of 700 and 3300 characters, p2 lost the
original value and `_ic2`. The combined build preserved both. The short-query
control also passed. These are HTTP probes, not a Safari browser playback test.

The replacement stack buffer is sized from the received query. The normal HTTP
request reader caps its entire input buffer at 4096 bytes, so this path does not
accept an unbounded query from that reader. HTTPS proxy scheme detection remains
a separate issue; this commit does not add `X-Forwarded-Proto` support.

### Server identity: aae8fee

With `<server-id>review-server</server-id>`, p2 returned `Server: Icecast` and the
combined build returned `Server: review-server`. The new value is copied while
holding the configuration lock and freed with the HTTP response state. It is
independent of a mount's authentication realm. This restores the behavior
described in [issue #439](https://github.com/karlheyes/icecast-kh/issues/439).

## Findings before release

### 1. Credentialed CORS needs an explicit origin policy

`36e21cb` correctly changes `Access-Control-Allow-Credentials` from `True` to
`true`; the value is case-sensitive in the
[Fetch standard](https://fetch.spec.whatwg.org/#http-access-control-allow-credentials).
However, `_send_cors_hdr` already replaces the default `*` origin with whatever
Origin the request supplies. The corrected value therefore enables credentialed
cross-origin reads for arbitrary origins under the default header policy.

The probe sent a synthetic admin credential and
`Origin: https://untrusted.invalid` to `/admin/stats`. The combined build returned
200 with that origin and `Access-Control-Allow-Credentials: true`. Without the
credential it still returned 401. This is not an authentication bypass: exposure
depends on a browser sending usable credentials, such as cached HTTP credentials.
Browser credential behavior and an end-to-end browser exploit were not tested.

Before enabling these changes on an authenticated browser-facing server, pin
allowed origins using the existing `http-headers` configuration, or disable
credentialed cross-origin access. A fixed origin of `https://player.invalid` was
tested: a request with the untrusted origin received the fixed allowed origin,
so the origins no longer match. Apply and verify the policy on all relevant
mounts and admin responses; reverse-proxy headers also need to agree with it.
Do not use the invalid `True` spelling as a security control.

`2224139` separately permits `Authorization` in preflight responses. This helps
web clients send credentials they possess; it does not authenticate them or
remove server-side password checks. Browser preflight was not exercised.

### 2. Origin-dependent redirects lack Vary: Origin

`f8efd57` adds CORS headers to 3xx responses, but leaves the default `Vary` header
restricted to 2xx. The Safari redirect probe confirmed a reflected origin with
no `Vary` header. A shared cache storing this redirect can reuse one origin's
response for another, causing browser CORS rejection. Cache behavior was not
tested. When retaining reflected origins, extend `Vary: Origin` to redirects,
or ensure the proxy does not cache these responses. A fixed allowed origin
removes this particular origin-dependent variation.

### 3. Queue pruning changes behavior and lacks a load regression

Despite the "cleanup" title and equivalence claim in its message, `2416300`
changes three decisions in `source.c`:

- Pruning now waits for a completed shrink sampling interval; the old code could
  prune when no sampling interval was active.
- A target below the minimum now becomes the minimum, whereas the old code chose
  the queue limit whenever listeners were present.
- Listeners at or beyond the queue limit no longer contribute their position to
  the sampled oldest buffer.

This can change queue memory, retention, and treatment of slow listeners. It may
be beneficial, but ordinary playback does not establish its behavior during long
broadcasts. The existing relay, reconnect, SOURCE, and fallback tests passed.
Before release, compare queue size, process memory, listener disconnects, and
audio continuity with fast and deliberately slow listeners over multiple pruning
intervals and reconnects. No production listener count was assumed or tested.

`a676957` consistently renames `termination_count` to `listener_check` across the
source structure, admin moves, and relay code. It has no separate user-visible
benefit; preserving it avoids unnecessary divergence when merging upstream.

## Verification and evidence

The temporary candidate was made by applying `git diff bb41738 master` to an
archive of stability commit `b4bd0df429ec2660e211fcbe7f4032d8268a4239`. The patch
applied cleanly. No repository branch was merged. The English-message commit has
the same file tree as the original p2 commit `cd173ad`.

The candidate was built from local `icecast-kh:kh22-p2` dependencies with
`./configure CFLAGS='-O2 -g'`, `make clean`, `make -j2`, `make check`, and
`make install`. Docker build used `--network none --pull=false`. Its version
suffix was `review-master`, not a new p2 release.

Runtime containers used loopback networking only, no published ports or host
mounts, user `nobody`, a read-only root, temporary `/tmp`, 256 MiB RAM, one CPU,
96 PIDs, disabled core dumps, and no Linux capabilities. Audio, credentials,
origins, and TLS certificates were synthetic.

All four existing patched suites passed with `EXPECT_FIXED=1`: `relay`, `source`,
`xslt`, and `auth`. The additional comparative probes covered the benefits and
headers described above. Local evidence is retained under
`artifacts/master-review/`: the build log, probe script, comparison logs, suite
logs, source patch, Dockerfile, and candidate image ID. This directory is ignored
by Git and is not part of a fresh clone.

The earlier baseline crash suites were not rerun. Browser playback/preflight,
proxy/cache integration, a long-running slow-listener load test, sanitizers,
and installation in AzuraCast remain unverified. FLV PRs #347/#461 are outside
this ten-commit comparison and remain unmerged.
