#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

baseline=bb4173850be18466adc3c8b12a3b08d4b4ba1a55
release=kh22-p2
mkdir -p artifacts
context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT
git archive "$baseline" | tar -x -C "$context"
cp -r tests "$context/tests"
cp .dockerignore "$context/.dockerignore"

docker build --progress plain -f tests/Dockerfile -t "icecast-kh:$release" . \
    2>&1 | tee artifacts/build-fixed.log
docker build --progress plain -f "$context/tests/Dockerfile" \
    --build-arg RELEASE=baseline -t icecast-kh:kh22-baseline "$context" \
    2>&1 | tee artifacts/build-baseline.log

# These containers have only loopback; no host ports, mounts, or station data.
isolated=(--rm --network none --memory 256m --cpus 1 --pids-limit 96
    --ulimit core=0 --cap-drop ALL --security-opt no-new-privileges
    --read-only --tmpfs /tmp:rw,nosuid,noexec,size=128m)
for mode in relay xslt auth; do
    docker run "${isolated[@]}" icecast-kh:kh22-baseline "$mode" \
        2>&1 | tee "artifacts/baseline-$mode.log"
done
for mode in relay xslt source auth; do
    docker run "${isolated[@]}" -e EXPECT_FIXED=1 "icecast-kh:$release" "$mode" \
        2>&1 | tee "artifacts/fixed-$mode.log"
done

architecture=$(docker run "${isolated[@]}" --entrypoint uname "icecast-kh:$release" -m)
archive="icecast-2.4.0-$release-linux-$architecture.tar.gz"
docker run "${isolated[@]}" --entrypoint cat "icecast-kh:$release" "/$archive" \
    > "artifacts/$archive"
docker run "${isolated[@]}" --entrypoint cat "icecast-kh:$release" /SHA256SUMS \
    > artifacts/SHA256SUMS.container
(cd artifacts && sha256sum "$archive" > SHA256SUMS)
docker image inspect "icecast-kh:$release" --format '{{.Id}}' > artifacts/image-id.txt
docker run "${isolated[@]}" --entrypoint /bin/sh "icecast-kh:$release" -c \
    'uname -m; cat /etc/os-release; gcc --version; python3 --version;
    dpkg-query -W libc6 libxml2 libxslt1.1 libcurl4 libssl3 libvorbis0a;
    /usr/local/bin/icecast -v; ldd /usr/local/bin/icecast' > artifacts/build-environment.txt
sha256sum src/admin.c src/auth.c src/xslt.c tests/regression.py tests/Dockerfile \
    > artifacts/source-SHA256SUMS
git diff "$baseline" -- src/admin.c src/auth.c src/xslt.c > artifacts/fixes.diff
printf '\nPASS: baseline crashes reproduced; patched regressions passed. See artifacts/.\n'
