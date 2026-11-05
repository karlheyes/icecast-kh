FROM python:3.13-slim-bookworm@sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641 AS dependencies
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential pkg-config libxslt1-dev libvorbis-dev libssl-dev libcurl4-openssl-dev patch ffmpeg && rm -rf /var/lib/apt/lists/*

FROM dependencies AS build
ARG RELEASE=p1
WORKDIR /build/icecast
COPY . .
# A clean build avoids timestamp-dependent reuse of unpatched object files.
RUN printf '%s\n' "$RELEASE" > version \
    && ./configure CFLAGS='-O2 -g' \
    && make clean && make -j2 && make check \
    && make install DESTDIR=/artifact \
    && cp -a /artifact/usr/local/. /usr/local/ \
    && mkdir -p /artifact/usr/local/share/doc/icecast \
    && cp COPYING AUTHORS /artifact/usr/local/share/doc/icecast/ \
    && tar -C /artifact -czf /icecast-2.4.0-kh22-$RELEASE-linux-$(uname -m).tar.gz usr \
    && sha256sum /icecast-*.tar.gz /usr/local/bin/icecast > /SHA256SUMS \
    && /usr/local/bin/icecast -v
WORKDIR /tmp
USER nobody
ENTRYPOINT ["python3", "/build/icecast/tests/regression.py"]
