"""Isolated KH22 regressions; run inside the test container, never against a station."""

import base64
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from http.client import HTTPConnection, HTTPResponse, RemoteDisconnected
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from queue import Queue
from typing import ClassVar
from urllib.parse import parse_qs, urlsplit

BINARY = os.environ.get("TEST_ICECAST_BINARY", "/usr/local/bin/icecast")
FIXED = os.environ.get("EXPECT_FIXED") == "1"
PASSWORD = "synthetic-test-only"
ADMIN = "Basic " + base64.b64encode(f"admin:{PASSWORD}".encode()).decode()
GOOD_XSL = """<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text"/><xsl:template match="/">xslt-ok</xsl:template></xsl:stylesheet>"""
FAIL_XSL = GOOD_XSL.replace(
    "xslt-ok", '<xsl:message terminate="yes">test</xsl:message>'
)


def report(case: str, **values: object) -> None:
    print(json.dumps({"case": case, **values}), flush=True)


@contextmanager
def icecast(root: Path, extra: str = "") -> Iterator[subprocess.Popen[bytes]]:
    root.mkdir()
    (root / "web").mkdir()
    config = f"""<icecast><location>synthetic</location><admin>test@localhost</admin>
    <hostname>localhost</hostname><workers>2</workers>
    <limits><clients>100</clients><sources>5</sources><burst-size>4096</burst-size></limits>
    <authentication><source-password>{PASSWORD}</source-password>
    <relay-password>{PASSWORD}</relay-password><admin-user>admin</admin-user>
    <admin-password>{PASSWORD}</admin-password></authentication>
    <listen-socket><port>18080</port><bind-address>127.0.0.1</bind-address></listen-socket>
    {extra}<fileserve>1</fileserve><paths><basedir>/usr/local/share/icecast</basedir>
    <logdir>{root}</logdir><webroot>{root}/web</webroot>
    <adminroot>/usr/local/share/icecast/admin</adminroot></paths>
    <logging><accesslog>access.log</accesslog><errorlog>error.log</errorlog>
    <loglevel>4</loglevel></logging><security><chroot>0</chroot></security></icecast>"""
    (root / "config.xml").write_text(config)
    with (root / "stdout.log").open("wb") as output:
        proc = subprocess.Popen(
            [BINARY, "-c", str(root / "config.xml")],
            stdout=output,
            stderr=output,
            stdin=subprocess.DEVNULL,
        )
        try:
            for _ in range(100):
                assert proc.poll() is None, (root / "stdout.log").read_text()
                try:
                    with socket.create_connection(("127.0.0.1", 18080), 0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError("Icecast did not start")
            yield proc
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    raise AssertionError("SIGTERM hung") from None


@contextmanager
def response(path: str, admin: bool = False) -> Iterator[HTTPResponse]:
    conn = HTTPConnection("127.0.0.1", 18080, timeout=4)
    try:
        headers = {"User-Agent": "kh-regression-listener", "Connection": "close"}
        if admin:
            headers["Authorization"] = ADMIN
        conn.request("GET", path, headers=headers)
        with conn.getresponse() as result:
            yield result
    finally:
        conn.close()


def get(path: str, admin: bool = False) -> tuple[int, bytes]:
    with response(path, admin) as result:
        return result.status, result.read()


def xml(path: str = "/admin/stats") -> ET.Element:
    status, body = get(path, True)
    assert status == 200, (status, body)
    return ET.fromstring(body)


def wait_title(mount: str, title: str) -> None:
    for _ in range(100):
        if xml().findtext(f"./source[@mount='{mount}']/title") == title:
            return
        time.sleep(0.05)
    raise AssertionError(f"Metadata missing on {mount}: {title}")


def decode(data: bytes, fmt: str) -> None:
    result = subprocess.run(
        [
            "ffmpeg",
            "-v",
            "error",
            "-threads",
            "1",
            "-f",
            fmt,
            "-i",
            "pipe:0",
            "-t",
            "0.1",
            "-f",
            "null",
            "-",
        ],
        input=data,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr.decode()


def check_listener(mount: str, fmt: str) -> None:
    with response(mount) as result:
        assert result.status == 200, result.status
        data = result.read(8192)
        assert len(data) == 8192, len(data)
        clients = xml("/admin/listclients?mount=" + mount)
        listener = clients.find(".//listener")
        assert listener is not None, ET.tostring(clients)
        assert listener.findtext("IP") == "127.0.0.1", ET.tostring(listener)
        assert listener.findtext("UserAgent") == "kh-regression-listener", ET.tostring(
            listener
        )
        assert int(clients.findtext(".//source/listeners", "0")) >= 1, ET.tostring(
            clients
        )
        for _ in range(100):
            stats = xml()
            if (int(stats.findtext(f"./source[@mount='{mount}']/listeners", "0")) >= 1
                    and int(stats.findtext("listeners", "0")) >= 1):
                break
            time.sleep(0.05)
        else:
            raise AssertionError("Listener counters did not update")
        decode(data, fmt)


class Service(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


@contextmanager
def service(handler: type[BaseHTTPRequestHandler]) -> Iterator[None]:
    with Service(("127.0.0.1", 18081), handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield
        finally:
            server.shutdown()
            thread.join(timeout=5)


class Auth(BaseHTTPRequestHandler):
    calls: ClassVar[Queue[bytes]] = Queue()

    def do_POST(self) -> None:
        self.calls.put(self.rfile.read(int(self.headers["Content-Length"])))
        self.send_response(200)
        self.send_header("icecast-auth-user", "1")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


def xslt_tests(base: Path) -> None:
    with service(Auth):
        for authenticated in (False, True):
            for kind, sheet in (
                ("good", GOOD_XSL),
                ("missing", None),
                ("broken", "<broken>"),
                ("apply-error", FAIL_XSL),
            ):
                name = f"xslt-{authenticated}-{kind}"
                auth = (
                    """<mount><mount-name>/*.xsl</mount-name><authentication type="url">
                <option name="listener_add" value="http://127.0.0.1:18081/auth"/>
                </authentication></mount>"""
                    if authenticated
                    else ""
                )
                root = base / name
                while not Auth.calls.empty():
                    Auth.calls.get_nowait()
                with icecast(root, auth) as proc:
                    if sheet is not None:
                        (root / "web" / "test.xsl").write_text(sheet)
                    (root / "web" / "good.xsl").write_text(GOOD_XSL)
                    try:
                        status, body = get("/test.xsl")
                    except (RemoteDisconnected, ConnectionResetError):
                        assert not FIXED and authenticated, "Unexpected disconnect"
                        assert proc.wait(timeout=5) == -signal.SIGSEGV
                        assert b"action=listener_add" in Auth.calls.get(timeout=1)
                        report(name, signal="SIGSEGV", expected=True)
                        continue
                    assert FIXED or not authenticated, (
                        "Baseline did not reproduce XSLT crash"
                    )
                    assert status == (200 if kind == "good" else 404), (status, body)
                    if kind == "good":
                        assert body == b"xslt-ok", body
                    if authenticated:
                        assert b"action=listener_add" in Auth.calls.get(timeout=1)

                    def repeat(index: int) -> None:
                        # More than 40 requests exercise queue/cache reuse after errors.
                        path = "/good.xsl" if index % 2 else "/test.xsl"
                        expected = 200 if index % 2 or kind == "good" else 404
                        code, content = get(path)
                        assert code == expected, (path, code, content)
                        if code == 200:
                            assert content == b"xslt-ok", content

                    with ThreadPoolExecutor(max_workers=6) as pool:
                        list(pool.map(repeat, range(60)))
                    assert get("/admin/stats.xsl", True)[0] == 200
                    assert proc.poll() is None
                    report(name, status=status, repeated=60, alive=True)
                assert proc.returncode == 0, proc.returncode


RELAY = """<relay><server>127.0.0.1</server><port>18081</port><mount>/upstream</mount>
<local-mount>/relay</local-mount><timeout>10</timeout><retry-delay>3</retry-delay>
<relay-shoutcast-metadata>1</relay-shoutcast-metadata></relay>"""


def relay_tests(base: Path, audio: bytes) -> None:
    gate = threading.Event()
    stop = threading.Event()
    accepted: Queue[int] = Queue()
    generation = 0

    class Upstream(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            current = generation
            accepted.put(current)
            while not gate.wait(0.05):
                if stop.is_set():
                    return
            self.send_response(200)
            self.send_header("Content-Type", "audio/mpeg")
            self.send_header("icy-metaint", "4096")
            self.end_headers()
            title = f"StreamTitle='synthetic-relay-{current}';".encode()
            # KH22 overwrites the final ICY byte with NUL.
            assert len(title) < 48
            block = bytes([3]) + title.ljust(48, b"\0")
            data = audio * (4096 // len(audio) + 2)
            offset = 0
            try:
                while not stop.is_set() and current == generation:
                    chunk = (data + data)[offset : offset + 4096]
                    self.wfile.write(chunk + block)
                    self.wfile.flush()
                    offset = (offset + 4096) % len(data)
                    stop.wait(0.1)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, format: str, *args: object) -> None:
            pass

    try:
        with service(Upstream):
            for name, extra, endpoint in (
                ("no-relay-listclients", "", "/admin/listclients?mount=/relay"),
                ("connecting-relay-stats", RELAY, "/admin/stats"),
                (
                    "connecting-relay-listclients",
                    RELAY,
                    "/admin/listclients?mount=/relay",
                ),
            ):
                with icecast(base / name, extra) as proc:
                    if extra:
                        accepted.get(timeout=5)
                    codes: list[int] = []
                    for _ in range(100):
                        try:
                            code, body = get(endpoint, True)
                        except (RemoteDisconnected, ConnectionResetError):
                            assert not FIXED and name == "connecting-relay-listclients"
                            assert proc.wait(timeout=5) == -signal.SIGSEGV
                            break
                        assert code in (200, 400, 404), (code, body)
                        if FIXED and name == "connecting-relay-listclients":
                            assert code == 400 and b"Source is not available" in body
                        codes.append(code)
                        time.sleep(0.01)
                    if name != "connecting-relay-listclients" or FIXED:
                        assert len(codes) == 100 and proc.poll() is None
                    else:
                        assert proc.returncode == -signal.SIGSEGV
                    report(
                        name,
                        responses=len(codes),
                        codes=sorted(set(codes)),
                        exit_code=proc.poll(),
                    )
                    if FIXED and name == "connecting-relay-listclients":
                        gate.set()
                        wait_title("/relay", "synthetic-relay-0")
                        check_listener("/relay", "mp3")
                        gate.clear()
                        generation += 1
                        accepted.get(timeout=15)
                        for _ in range(100):
                            assert get(endpoint, True)[0] == 400
                        gate.set()
                        wait_title("/relay", f"synthetic-relay-{generation}")
                        check_listener("/relay", "mp3")
                        report(
                            "relay-reconnect",
                            polls=100,
                            audio=True,
                            metadata=True,
                            listeners=True,
                        )
                if proc.returncode != -signal.SIGSEGV:
                    assert proc.returncode == 0, proc.returncode
    finally:
        stop.set()
        gate.set()


@contextmanager
def source(mount: str, audio: bytes, content_type: str) -> Iterator[None]:
    stop = threading.Event()
    with socket.create_connection(("127.0.0.1", 18080), timeout=4) as conn:
        auth = base64.b64encode(f"source:{PASSWORD}".encode()).decode()
        conn.sendall(
            (
                f"SOURCE {mount} HTTP/1.0\r\nAuthorization: Basic {auth}\r\n"
                f"Content-Type: {content_type}\r\nIce-Name: synthetic-source\r\n\r\n"
            ).encode()
        )
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = conn.recv(1)
            assert chunk, header
            header += chunk
        assert b"200" in header.split(b"\r\n")[0], header

        def pump() -> None:
            try:
                while not stop.is_set():
                    for offset in range(0, len(audio), 1024):
                        if stop.is_set():
                            return
                        conn.sendall(audio[offset : offset + 1024])
                        stop.wait(0.025)
            except (BrokenPipeError, ConnectionResetError):
                pass

        thread = threading.Thread(target=pump)
        thread.start()
        try:
            yield
        finally:
            stop.set()
            thread.join(timeout=5)
            assert not thread.is_alive(), "Source thread hung"


def auth_tests(base: Path, audio: bytes) -> None:
    class StreamAuth(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            params = parse_qs(body.decode())
            self.send_response(200)
            if params.get("pass") == [PASSWORD]:
                self.send_header("icecast-auth-user", "1")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            pass

    config = """<mount><mount-name>/live</mount-name><authentication type="url">
    <option name="stream_auth" value="http://127.0.0.1:18081/auth"/>
    </authentication></mount>"""
    with service(StreamAuth), icecast(base / "auth", config) as proc:
        with source("/live", audio, "audio/mpeg"):
            for password, expected in ((PASSWORD, 200 if FIXED else 403), ("wrong", 401)):
                for endpoint in ("listclients", "listclients.xsl"):
                    conn = HTTPConnection("127.0.0.1", 18080, timeout=5)
                    credentials = base64.b64encode(f"source:{password}".encode()).decode()
                    try:
                        conn.request("GET", f"/admin/{endpoint}?mount=/live", headers={
                            "Authorization": "Basic " + credentials, "Connection": "close"
                        })
                        with conn.getresponse() as result:
                            body = result.read()
                            assert result.status == expected, (endpoint, result.status, body)
                            if expected == 200 and endpoint == "listclients":
                                assert ET.fromstring(body).find(".//source") is not None
                    finally:
                        conn.close()
            assert proc.poll() is None
            report("stream-auth-listclients", allowed=200 if FIXED else 403, denied=401)
    assert proc.returncode == 0


def source_tests(base: Path, mp3: bytes, aac: bytes) -> None:
    fallback = """<mount><mount-name>/primary</mount-name>
    <fallback-mount>/backup</fallback-mount><fallback-override>1</fallback-override></mount>"""
    with icecast(base / "source", fallback) as proc:
        for mount, data, mime, fmt in (
            ("/mp3", mp3, "audio/mpeg", "mp3"),
            ("/aac", aac, "audio/aac", "aac"),
        ):
            with source(mount, data, mime):
                status, body = get(
                    f"/admin/metadata?mount={mount}&mode=updinfo&song=synthetic", True
                )
                assert status == 200, (status, body)
                wait_title(mount, "synthetic")
                check_listener(mount, fmt)
                report("source-" + fmt, audio=True, metadata=True, listeners=True)
        with source("/backup", mp3, "audio/mpeg"):
            with ExitStack() as primary:
                primary.enter_context(source("/primary", mp3, "audio/mpeg"))
                with response("/primary") as listener:
                    assert listener.status == 200
                    decode(listener.read(8192), "mp3")
                    primary.close()
                    for _ in range(100):
                        if (
                            int(
                                xml().findtext(
                                    "./source[@mount='/backup']/listeners", "0"
                                )
                            )
                            >= 1
                        ):
                            break
                        time.sleep(0.05)
                    else:
                        raise AssertionError("Listener did not migrate to fallback")
                    decode(listener.read(8192), "mp3")
            # A fresh request resolves the configured fallback after source loss.
            with response("/primary") as listener:
                assert listener.status == 200
                decode(listener.read(8192), "mp3")
            report("fallback", audio=True)
        assert proc.poll() is None
    assert proc.returncode == 0
    report("SIGTERM", exit_code=proc.returncode)


def upstream_tests(base: Path, audio: bytes) -> None:
    with icecast(base / "safari") as proc, source("/live", audio, "audio/mpeg"):
        for length in (0, 700, 3300):
            value = "x" * length
            path = "/live" + ("?token=" + value if value else "")
            conn = HTTPConnection("127.0.0.1", 18080, timeout=4)
            try:
                conn.request("GET", path, headers={
                    "User-Agent": "Safari/605.1.15", "Connection": "close"
                })
                with conn.getresponse() as result:
                    assert result.status == 302
                    location = result.getheader("Location")
                    assert location is not None
                    params = parse_qs(urlsplit(location).query)
                    intact = (not value or params.get("token") == [value]) and "_ic2" in params
                    assert intact == (FIXED or length == 0), (length, params)
            finally:
                conn.close()
            report("safari-redirect", query_length=length, intact=intact)
        assert proc.poll() is None
    assert proc.returncode == 0

    cert, key = base / "cert.pem", base / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj",
        "/CN=localhost", "-days", "1", "-keyout", str(key), "-out", str(cert),
    ], check=True, capture_output=True, timeout=15)
    tls_config = f"""<listen-socket><port>18443</port><bind-address>127.0.0.1</bind-address>
    <ssl>1</ssl></listen-socket><paths><ssl-certificate>{cert}</ssl-certificate>
    <ssl-private-key>{key}</ssl-private-key></paths>"""

    def tls_request() -> bytes:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", 18443), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname="localhost") as conn:
                conn.sendall(
                    f"GET /admin/stats HTTP/1.0\r\nAuthorization: {ADMIN}\r\n\r\n".encode()
                )
                return conn.recv(4096).split(b"\r\n")[0]

    with icecast(base / "tls", tls_config) as proc:
        assert b"200" in tls_request()
        cert.unlink()
        proc.send_signal(signal.SIGHUP)
        for _ in range(100):
            if "SSL not reloaded" in (base / "tls/error.log").read_text():
                break
            time.sleep(0.05)
        else:
            raise AssertionError("TLS reload did not complete")
        try:
            status = tls_request()
        except (OSError, TimeoutError):
            assert not FIXED, "TLS stopped after failed reload"
            report("tls-failed-reload", connected=False)
        else:
            assert FIXED and b"200" in status, status
            report("tls-failed-reload", connected=True)
        assert proc.poll() is None
    assert proc.returncode == 0

    mount = """<mount><mount-name>/protected.mp3</mount-name><limit-rate>128000</limit-rate>
    <authentication type="url"><option name="listener_add"
    value="http://127.0.0.1:18081/auth"/></authentication></mount>"""
    while not Auth.calls.empty():
        Auth.calls.get_nowait()
    with service(Auth), icecast(base / "file", mount) as proc:
        (base / "file/web/protected.mp3").write_bytes(audio)
        try:
            with response("/protected.mp3") as result:
                assert FIXED and result.status == 200, result.status
                decode(result.read(8192), "mp3")
        except (RemoteDisconnected, ConnectionResetError):
            assert not FIXED, "Unexpected file-serving disconnect"
            assert proc.wait(timeout=5) == -signal.SIGSEGV
            report("url-auth-throttled-file", signal="SIGSEGV")
        else:
            assert proc.poll() is None
            report("url-auth-throttled-file", status=200, audio=True)
        assert b"action=listener_add" in Auth.calls.get(timeout=1)
    assert proc.returncode == (0 if FIXED else -signal.SIGSEGV)


def main() -> None:
    # Every run has fresh logs/configs; all network peers are container loopback.
    with tempfile.TemporaryDirectory(prefix="kh-regression-") as directory:
        base = Path(directory)
        try:
            mode = sys.argv[1]
            if mode == "xslt":
                xslt_tests(base)
            else:
                audio: dict[str, bytes] = {}
                for fmt, codec in (("mp3", "libmp3lame"), ("adts", "aac")):
                    audio[fmt] = subprocess.check_output(
                        [
                            "ffmpeg",
                            "-v",
                            "error",
                            "-filter_threads",
                            "1",
                            "-f",
                            "lavfi",
                            "-i",
                            "sine=frequency=440:sample_rate=44100",
                            "-t",
                            "1",
                            "-threads",
                            "1",
                            "-c:a",
                            codec,
                            "-b:a",
                            "128k",
                            "-f",
                            fmt,
                            "pipe:1",
                        ],
                        timeout=15,
                    )
                if mode == "relay":
                    relay_tests(base, audio["mp3"])
                elif mode == "source":
                    source_tests(base, audio["mp3"], audio["adts"])
                elif mode == "auth":
                    auth_tests(base, audio["mp3"])
                elif mode == "upstream":
                    upstream_tests(base, audio["mp3"])
                else:
                    raise ValueError(mode)
        except BaseException:
            for log in base.glob("*/error.log"):
                print(
                    f"--- {log.parent.name} ---\n{log.read_text()[-16000:]}",
                    file=sys.stderr,
                )
            raise


if __name__ == "__main__":
    main()
