# Icecast-KH22: stability fixes

English | [Русский](README.ru.md)

Custom build **2.4.0-kh22-p2** based on
[Icecast-KH22](https://github.com/karlheyes/icecast-kh/tree/bb4173850be18466adc3c8b12a3b08d4b4ba1a55).
Upstream history, authorship, and the **GPL-2.0** license are preserved:
[COPYING](COPYING), [AUTHORS](AUTHORS), and the [original README](README).

## Fixes

- A mount-specific admin request to a connecting relay returns HTTP 400
  `Source is not available` if the source has no worker yet. The source lock is
  released before the response is prepared. Admin commands and detailed stats
  are available again after the relay connects.
- XSLT after URL authentication uses an independent clock when no worker is
  assigned and queues the request for processing. Template errors return HTTP 404;
  the `aux_data` reference to the XSLT request is cleared before the response.
- `listclients` and `listclients.xsl` are handled as admin requests after
  successful source URL authentication. This fix is based on
  [upstream PR #431](https://github.com/karlheyes/icecast-kh/pull/431).

The NULL-worker check and use of `timing_get_time()` are based on
[RexViber's proposal in upstream issue #478](https://github.com/karlheyes/icecast-kh/issues/478).
This build also queues the request on a worker: changing the clock alone does not
ensure delivery of the response after URL authentication.

## Baseline and compatibility

The baseline is commit `bb4173850be18466adc3c8b12a3b08d4b4ba1a55`, tag
`icecast-2.4.0-kh22`, used by the Icecast recipe in AzuraCast 0.24.0.
The fork was originally cloned from `master` at `ea3554b`; ten commits affecting
nine files separate that commit from KH22. They include changes to CORS, source
queues, TLS/reload, and Safari redirects. They are excluded from this focused
build; the original `master` is preserved. Work is on `fixes/kh22-stability`.

SOURCE, MP3/AAC, relay, metadata, fallback, XML stats, and the listener list with
IP/User-Agent are retained and exercised by isolated tests. These tests do not
confirm installation in a working AzuraCast instance. Its Compose setup, configs,
stations, and servers have not been changed. Dynamic library compatibility must
be checked in the target image before installation.

## Build and verification

Bash, Git, and Docker Engine with access to the Docker socket are required.
Network access is needed only to download the base image and build dependencies.

```bash
bash tests/check.sh
```

The script builds baseline KH22 and the patched version from clean sources, then
checks for the expected baseline SIGSEGVs and successful responses in the patched
version. Runtime containers run as `nobody`, with `--network none`, no published
ports or host volumes, a read-only root, temporary `/tmp`, limits of 256 MiB RAM,
one CPU and 96 PIDs, and no core dumps or Linux capabilities. The HTTP upstream
and URL-auth service run only on the container's loopback interface. Audio is a
synthetic sine wave; the installed ffmpeg generates MP3/AAC samples.

The tests cover:

- 100 admin requests while a relay connects, control requests without a relay,
  and the global `/admin/stats` endpoint;
- relay connection and reconnection, audio decoding, metadata, the global count,
  and detailed listener lists with IP/User-Agent;
- ordinary and URL-auth XSLT with valid, missing, malformed, and terminating
  templates; 60 repeated requests at concurrency 6, successful requests after
  errors, and admin XSLT;
- SOURCE MP3/AAC, metadata, listener stats, fallback, and SIGTERM;
- `listclients` with accepted and rejected source URL authentication.

`artifacts/` contains both build and test logs, the install archive, SHA-256
checksums of the archive and binary, the image ID, and a diff of the fixes. This
directory is excluded from Git. Results of a specific run are recorded in
[docs/validation.md](docs/validation.md).

To build separately without running the regression tests:

```bash
docker build -f tests/Dockerfile -t icecast-kh:kh22-p2 .
```

The install archive contains the `usr/local/` tree, including the binary,
standard web/admin templates, a sample config, and the license. It is an artifact
for testing and later integration; unpacking it over a live environment is not part
of this procedure. The test image also contains a compiler and ffmpeg and is
intended for the test environment.

For a native build with the dependencies listed in the original README:

```bash
./configure
make clean
make -j2
make check
./src/icecast -v
```

The `version` file sets the `p2` suffix. Change the release suffix before a new
release after modifying the code. For container builds it can be overridden with
`--build-arg RELEASE=...`. A clean build is required: an earlier research build
skipped recompilation of `admin.c` due to matching timestamps.

The Python base image digest is pinned in `tests/Dockerfile`; Debian package
versions are not pinned to a snapshot repository. The commands can be rerun, but
bit-for-bit reproducibility is not claimed. This build fixes three defects; it is
not a complete security audit of Icecast-KH.
