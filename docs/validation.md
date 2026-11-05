# Icecast 2.4.0-kh22 validation

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

The logs and checksums in `artifacts/` correspond to the most recent run, p2.
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
