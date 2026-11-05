# Icecast 2.4.0-kh22 validation

## Build p4: full master integration

On 5 November 2026, `bash tests/check.sh` completed with exit code 0. Clean
configure/build and `make check` succeeded. Baseline KH22 reproduced the expected
failures; all seven p4 suites passed: relay, XSLT, SOURCE/fallback, source URL-auth,
the three p3 upstream regressions, CORS, and queue load. Commit `f23606b` retains
the separately checked p3 baseline. The integration preserves every commit from
the fork's `master` at `ea3554b5167f6780a8be77f1715f90ed02005665`.

Archive `artifacts/icecast-2.4.0-kh22-p4-linux-x86_64.tar.gz`, SHA-256:

```text
c9bd65e7e54d49a0ecc6a9e6f3200c0cc98aa1d96b4a1aabb9be9a971b2835b8
```

Binary SHA-256:

```text
b6c6741bd89c4998f99f250bf180b632641fc0724ae832fbd65a279749e28acd
```

### CORS and Server header

The new test reproduced reflected origins with credentials on the earlier
`review-master` image. P4 passed 40 HTTP cases covering admin, stream, Safari
redirect, and OPTIONS responses with no origin, the configured origin, an
untrusted origin, and `null`. Default responses with an Origin return wildcard
access without the credentials header. Explicit global and mount origins remain
fixed and permit credentials only for a matching browser origin. Unauthenticated
admin requests still return 401. Redirects include `Vary: Origin`; OPTIONS returns
204 with Authorization permitted, and successful responses honor `server-id`.
These are HTTP contract checks, not a browser or cache integration test.

### Queue comparison

The same 120-second workload ran on p3 and p4: eight readers consumed the stream
continuously while four throttled sockets read at most 128 bytes per second.
Slow readers reconnected at 40 and 80 seconds. The test used a 262144-byte queue
setting, 32768-byte minimum, 4096-byte burst and socket send buffer, synthetic
MP3, and the existing source pump. It restarted the source and decoded a fresh
listener's audio afterward. The upstream queue implementation is unchanged.

| Build        | Peak queue, B | RSS growth, KiB | Slow drops |
| ------------ | ------------- | --------------- | ---------- |
| p3           | 240740        | 128             | 12         |
| p4           | 376154        | 0               | 12         |
| p4/AzuraCast | 275847        | 0               | 12         |

Queue and RSS measurements exclude the first ten seconds of warm-up. All runs
kept the queue below the test's 524288-byte bound; the configured size is not an
instantaneous hard cap. RSS variation stayed below the 16384-KiB bound. Every
fast reader received more than 4.5 MB without disconnecting; the maximum sampled
read gap was below three seconds. The slow readers exercised actual eviction,
and source restart succeeded. These results establish bounded behavior for this
workload; they do not establish a memory improvement or production capacity.

### AzuraCast 0.24.0 compatibility

A temporary image based on the same official digest used for p3 replaced only
`/usr/local/bin/icecast`. The binary reported p4, matched the SHA-256 above, and
resolved all dynamic libraries. All seven suites passed inside this image,
including CORS and the complete queue workload. Containers had loopback networking
only, no published ports or station data, a read-only root, temporary `/tmp`,
256 MiB RAM, one CPU, 96 PIDs, and no Linux capabilities.

P4 did not repeat p3's full demo-station setup, AutoDJ/web-proxy/player-page test.
Browser playback, real station configurations, other AzuraCast versions and
architectures, and long-running production load remain unverified. No production
installation was changed. The p3 demo-station result is recorded separately below.

### Evidence and static checks

The final build and runtime logs, source hashes, environment, image ID, archive,
and binary checksums are in ignored `artifacts/`. The extra comparison and
AzuraCast evidence is in `artifacts/integration-p4/`; p3's latest logs and archive
were retained in `artifacts/p3-latest/` before p4 overwrote the current-run logs.
These ignored files are local evidence and are not included in a fresh clone.

`uvx --from mypy mypy --strict --python-version 3.13 tests/regression.py`,
`bash -n tests/check.sh`, and `git diff --check` passed. Changed project Markdown
passes Prettier and markdownlint. Repository-wide Markdown lint separately finds
111 pre-existing issues in the unchanged `.context/last.md` history export;
the export is preserved as required by the context-restoration procedure.

## Build p3

On 5 November 2026, `bash tests/check.sh` completed with exit code 0. The tests
reproduced the three newly addressed defects on both the p2 image and baseline
KH22. On p3, URL-authenticated rate-limited file playback returned HTTP 200 and
decoded as MP3; TLS remained available after a failed certificate reload; and
Safari redirects retained short, 700-character, and 3300-character query values.
All previous relay, XSLT, SOURCE, fallback, and source-auth regressions passed.

Archive `artifacts/icecast-2.4.0-kh22-p3-linux-x86_64.tar.gz`, SHA-256:

```text
5e411bc4038bfc622bf65129813c3860365529718bde4f3a03a99ba7e9d8aa11
```

SHA-256 of the binary inside the image:

```text
634e4d3f67aeb4c4159af40678c55dbe4bcf336a7fdee7d68a1222a804ba3f93
```

The full p3 check was repeated before committing the integration baseline. The
binary SHA-256 stayed unchanged; repackaging changed the archive checksum.
The original p3 archive and checksums are retained in `artifacts/p3-records/`.
The latest p3 run's logs and checksums are in `artifacts/p3-latest/`. Earlier p2
logs and checksums were preserved in `artifacts/p2-records/`. The tests use synthetic
clients and do not establish real Safari playback.

### AzuraCast 0.24.0 test

The official `ghcr.io/azuracast/azuracast:0.24.0` image was pinned to digest
`sha256:2a4aa1e0b2fdc93170ef1dbc51ae2ea036053f0a74931692b23d0d7c072e5c06`.
A temporary derived image replaced only `/usr/local/bin/icecast` with the p3
binary, retaining AzuraCast's web and admin templates. `ldd` resolved all its
dependencies and the binary reported `Icecast 2.4.0-kh22-p3`. All five isolated
Icecast regression suites passed in this image using AzuraCast's libraries.

A second temporary container ran AzuraCast's services with `--network none`,
no published ports or host mounts, and a fresh database. Its setup and demo
fixtures created a station; supervisor started both its AutoDJ and Icecast p3.
The installed p3 binary's SHA-256 matched the archive. The station delivered
8192 bytes of decodable MP3 both on its Icecast port and through the AzuraCast
web proxy. The station's public player page returned HTTP 200. After stopping
the demo AutoDJ, the station returned decodable fallback MP3. Source and admin
requests with invalid credentials returned 401; valid credentials returned 200.
The AutoDJ was restarted and proxy playback was rechecked before the disposable
container was stopped. Sanitized logs and the station probe are in the ignored
`artifacts/azuracast-0.24.0/` directory.

The test checked the page and its audio endpoint over HTTP, not a browser UI or
real Safari. It used synthetic demo data and did not touch an existing AzuraCast
installation. Other versions, architectures, reverse proxies, real stations,
and long-running broadcast load remain unverified.

## Build p2

On 5 November 2026, `bash tests/check.sh` completed with exit code 0.
For both XML and XSL variants of `listclients` with source URL authentication,
KH22 returned 403 for an authorized request, while p2 returned 200. Rejected
requests returned 401 in both builds. Previous regression scenarios also passed.

Archive `artifacts/icecast-2.4.0-kh22-p2-linux-x86_64.tar.gz`, SHA-256:

```text
719c343863068b8e54a603a9e343c700b11a5dacd0b88950b6e88e7402392cef
```

SHA-256 of the binary inside the image:

```text
2076916b44899a28ce14847b90ac97362cc8495255d1b67ff2bd94336d9f7fa3
```

The earlier p2 logs and checksums are preserved in `artifacts/p2-records/`.
The [regression-results.json](regression-results.json) snapshot and the section
below describe the earlier p1 run.

In a separate check, an HTTP 200 MP3/FLV response began with the `FLV` header,
while AAC/FLV began with tag data without that header. This is consistent with
[issue #459](https://github.com/karlheyes/icecast-kh/issues/459), but the fix in
[PR #461](https://github.com/karlheyes/icecast-kh/pull/461) has not been reviewed
or included in p2. Player behavior was not checked separately.

## Build p1

Date: **5 November 2026**. Local test environment: Linux x86_64, Debian 12,
Python 3.13.16, GCC 12.2.0. Baseline for both comparisons:
`bb4173850be18466adc3c8b12a3b08d4b4ba1a55` (KH22).

## Method

Full run: `bash tests/check.sh`. Baseline and patched KH22 were built using the
same Dockerfile, `make clean`, the same build dependencies, and `-O2 -g`.
A baseline check passes only when the target scenario produces the expected
SIGSEGV and the control scenarios survive.

Each runtime container is isolated: loopback only (`--network none`), no published
ports or host volumes, running as `nobody`, with a read-only root and `/tmp` on
tmpfs. Limits: 256 MiB, one CPU, 96 PIDs, core dumps disabled, and capabilities
removed. Configs, passwords, IP/User-Agent values, and audio are synthetic.
Production servers and AzuraCast configuration were not used.

## Recorded results

The full run completed with exit code 0. Machine-readable snapshot:
[regression-results.json](regression-results.json).

| Scenario                      | KH22           | p1             |
| ----------------------------- | -------------- | -------------- |
| `listclients` without relay   | 100 × HTTP 400 | 100 × HTTP 400 |
| `stats` while relay connects  | 100 × HTTP 200 | 100 × HTTP 200 |
| Relay/admin during connection | SIGSEGV        | 100 × HTTP 400 |
| Relay/admin during reconnect  | Not run        | 100 × HTTP 400 |
| Ordinary XSLT, success        | HTTP 200       | HTTP 200       |
| Ordinary XSLT, errors         | HTTP 404       | HTTP 404       |
| URL-auth XSLT                 | SIGSEGV        | HTTP 200/404   |

Baseline KH22 crashes on the first relay/admin request. With p1, audio decodes,
metadata changes, and stats are available after each relay connection. SOURCE
MP3/AAC audio, metadata, counters, and IP/User-Agent were checked; fallback was
checked through listener migration and audio decoding on a new request. Baseline
control processes and all p1 processes exited with code 0 after SIGTERM.

Each surviving XSLT scenario additionally executes 60 requests at concurrency 6,
alternating the template under test with a valid template. `/admin/stats.xsl`
then succeeds. Error cases cover a missing file, malformed XML, and
`xsl:message terminate="yes"`. The p1 total is 488 public XSLT requests and eight
admin XSLT requests.

The checks passed: `mypy --strict --python-version 3.13 tests/regression.py`,
`bash -n tests/check.sh`, Markdown formatter/linter, and `git diff --check`.
At the time of the p1 run, SHA-256 checksums of the C sources, test, and Dockerfile
in the tested image matched the working tree.

Test environment libraries: glibc 2.36, libxml2 2.9.14, libxslt 1.1.35,
libcurl 7.88.1, OpenSSL 3.0.22. Exact Debian revisions and `ldd` output were
recorded in the local `artifacts/build-environment.txt` for that run.

Install archive: `artifacts/icecast-2.4.0-kh22-p1-linux-x86_64.tar.gz`.
SHA-256:

```text
2cad10ead73bb7112c18d4aae37c4b7721f497a0a13efc64e3ad2dea6569b7a6
```

Binary inside the archive: `usr/local/bin/icecast`. SHA-256:

```text
4d85b570754710ee41b93174d885a1ad73f210aaa3b5c38926fac316e6a646a2
```

Local test image `icecast-kh:kh22-p1`:

```text
sha256:041c32dc27744c84b3dbfd6173681655d17413a68338716beb3e3ec5d583658f
```

The archive checksum was rechecked after extraction from the container. Full logs
of both builds, five test suites, and checksums were saved locally in `artifacts/`
and excluded from Git. Later runs overwrite these logs; archive checksums may
also differ between builds.

## Lifecycle review

The admin handler reads the worker while holding the source lock. If the source
client or worker is absent, the lock is released and a normal HTTP 400 response
is sent. This path no longer calls `client_change_worker()` with NULL. Relay
recovery is also tested to detect a lock left held.

For XSLT, both entry points (`stats_transform_xslt` and `admin_send_response`),
URL auth (`queue_auth_client` → `add_authenticated_listener`), `xslt_client`,
`xslt_update`, `client_add_incoming`, response preparation, XML/cache cleanup,
and the handoff to fserve were reviewed.

URL auth removes the client from its worker. The code proposed by
[RexViber in issue #478](https://github.com/karlheyes/icecast-kh/issues/478)
changes the clock when the worker is NULL but does not hand the request to another
handler. This build therefore calls `client_add_incoming` after setting `xslt_ops`;
after a successful handoff the current thread no longer accesses the client. If
a worker is already assigned, the handler is called directly as before.

A successful transformation clears `aux_data` in the existing `_apply_sheet`,
frees the original XML, and passes the response to fserve. On error paths,
`xslt_update` and `xslt_client` now also clear `aux_data` before sending 404;
`xsl_req_clear` frees the XML, filename, and remaining cache references. Repeated
successful requests after errors check that the queue continues to work.

## Test environment notes

- An earlier temporary "guard" did not contain the fix in its machine code:
  `make` skipped `admin.c` when timestamps matched and reported clock skew. It
  crashed on the same first request as the baseline. New clean builds are used;
  the old temporary image and only its cache records were removed.
- The global listener counter updates periodically. The test keeps the listener
  connected and waits for the update instead of checking immediately.
- KH22 replaces `retry-delay` values below 3 seconds with 60 seconds. The fixture
  sets it to 3, and reconnect has a separate wait window.
- The metadata change test exposed a separate edge case: KH22 discards the last
  byte of an ICY block. If a string fills the block without NUL padding, the
  terminating `;` is lost and the title is not updated. The fixture leaves NUL
  padding; this parser defect is outside the two p1 fixes and remains unfixed.
- `make check` ran; upstream registers no automated tests through
  `TESTS`/`check_PROGRAMS`. The HTTP scenarios provide evidence for the fixes.

## Limitations

The p1 validation covers two defects and the synthetic smoke scenarios listed
above. Long-running broadcast load tests, sanitizers, other architectures,
integration into the AzuraCast image, and server installation were not performed.
ABI compatibility must be confirmed in the target image before installation.
Bit-for-bit reproducibility has not been established: Debian packages are not
pinned to a snapshot, and the install archive contains build timestamps.
