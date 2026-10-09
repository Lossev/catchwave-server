#!/usr/bin/env python3
"""CatchWave server: отдаёт музыку из одной папки только владельцу пароля.

Только стандартная библиотека Python 3.8+. Всё общение идёт по TLS.

Владелец задаёт пароль. Сам пароль по сети не передаётся: из него и отпечатка
сертификата выводится токен, а сервер доказывает знание пароля ответом на
/api/hello. Так приложение отличает настоящий сервер от подменённого, даже
когда видит его самоподписанный сертификат впервые.

API:
    GET /api/hello?nonce=   -> {"salt", "iterations", "proof"}, без токена
    Остальные запросы требуют заголовок `Authorization: Bearer <токен>`.
    GET /api/ping           -> {"ok": true, "name": "CatchWave", "version": "2"}
    GET /api/tracks         -> {"tracks": [{"path", "size", "modified"}]}
    GET /api/file/<path>    -> файл, поддерживает Range и If-Range (докачка)
"""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import ssl
import stat
import sys
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

VERSION = "2"
CHUNK = 256 * 1024
ITERATIONS = 200_000
MIN_PASSWORD_LENGTH = 8


def derive_key(password, salt, iterations):
    normalized = unicodedata.normalize("NFC", password).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", normalized, bytes.fromhex(salt), iterations)


def certificate_fingerprint(path):
    with open(path, "r", encoding="ascii") as handle:
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(handle.read().strip())).hexdigest()


def sign(key, *parts):
    return hmac.new(key, "|".join(parts).encode("utf-8"), "sha256").hexdigest()


def access_token(key, fingerprint):
    # Токен привязан к сертификату: при его замене старые токены перестают действовать.
    return sign(key, "catchwave-token", fingerprint)


def load_auth(path):
    with open(path, "r", encoding="ascii") as handle:
        salt, key, iterations = handle.read().strip().split(":")
    return salt, bytes.fromhex(key), int(iterations)

# Только форматы, которые iPhone умеет воспроизводить сам.
AUDIO_TYPES = {
    ".mp3": "audio/mpeg",
    ".m4a": "audio/mp4",
    ".aac": "audio/aac",
    ".wav": "audio/wav",
    ".aif": "audio/aiff",
    ".aiff": "audio/aiff",
    ".flac": "audio/flac",
    ".caf": "audio/x-caf",
}


def is_visible_audio(name):
    return not name.startswith(".") and os.path.splitext(name)[1].lower() in AUDIO_TYPES


def scan(root):
    tracks = []
    for directory, subdirectories, filenames in os.walk(root, followlinks=False):
        subdirectories[:] = sorted(d for d in subdirectories if not d.startswith("."))
        for name in sorted(filenames):
            if not is_visible_audio(name):
                continue
            full = os.path.join(directory, name)
            relative = os.path.relpath(full, root).replace(os.sep, "/")
            try:
                relative.encode("utf-8")
                info = os.stat(full, follow_symlinks=False)
            except (OSError, UnicodeEncodeError):
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            tracks.append({"path": relative, "size": info.st_size, "modified": int(info.st_mtime)})
    return tracks


def parse_range(header, size):
    """Возвращает (start, end) для одного диапазона bytes=... или None."""
    unit, _, spec = header.partition("=")
    if unit.strip().lower() != "bytes" or "," in spec:
        return None
    first, dash, last = spec.strip().partition("-")
    if not dash:
        return None
    try:
        if not first:
            length = int(last)
            if length <= 0:
                return None
            return max(0, size - length), size - 1
        start = int(first)
        end = int(last) if last else size - 1
    except ValueError:
        return None
    if start < 0 or start >= size or end < start:
        return None
    return start, min(end, size - 1)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "CatchWave/" + VERSION
    sys_version = ""
    timeout = 60

    def setup(self):
        # Рукопожатие TLS делается в потоке соединения, чтобы медленный клиент не блокировал accept().
        self.request.settimeout(self.timeout)
        self.request = self.server.tls.wrap_socket(self.request, server_side=True)
        super().setup()

    def do_GET(self):
        self.route(head=False)

    def do_HEAD(self):
        self.route(head=True)

    def authorized(self):
        scheme, _, value = self.headers.get("Authorization", "").partition(" ")
        return scheme.lower() == "bearer" and hmac.compare_digest(value.strip().encode(), self.server.token)

    def route(self, head):
        url = urlsplit(self.path)
        path = url.path
        if path == "/api/hello":
            self.send_hello(parse_qs(url.query).get("nonce", [""])[0], head)
            return
        # Без токена сервер не раскрывает ничего, включая то, какие пути существуют.
        if not self.authorized():
            self.send_json(401, {"error": "unauthorized"}, head, {"WWW-Authenticate": "Bearer"})
            return
        if path == "/api/ping":
            self.send_json(200, {"ok": True, "name": "CatchWave", "version": VERSION}, head)
        elif path == "/api/tracks":
            self.send_json(200, {"tracks": scan(self.server.music_dir)}, head)
        elif path.startswith("/api/file/"):
            self.send_file(unquote(path[len("/api/file/"):]), head)
        else:
            self.send_json(404, {"error": "not found"}, head)

    def send_hello(self, nonce, head):
        """Доказывает клиенту, что сервер знает пароль и что сертификат именно его."""
        if not 32 <= len(nonce) <= 128 or any(c not in "0123456789abcdef" for c in nonce):
            self.send_json(400, {"error": "bad nonce"}, head)
            return
        server = self.server
        proof = sign(server.key, "catchwave-server", nonce, server.fingerprint)
        self.send_json(200, {"salt": server.salt, "iterations": server.iterations, "proof": proof}, head)

    def send_json(self, status, payload, head, extra=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def open_track(self, relative):
        """Открывает файл, только если он лежит внутри музыкальной папки и является аудио."""
        root = self.server.music_dir
        parts = relative.split("/")
        if not relative or any(part in ("", ".", "..") or part.startswith(".") for part in parts):
            return None
        if not is_visible_audio(parts[-1]):
            return None
        try:
            full = os.path.realpath(os.path.join(root, *parts))
            if os.path.commonpath([root, full]) != root or full == root:
                return None
            handle = open(full, "rb")
        except (OSError, ValueError):
            return None
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            handle.close()
            return None
        return handle

    def send_file(self, relative, head):
        handle = self.open_track(relative)
        if handle is None:
            self.send_json(404, {"error": "not found"}, head)
            return
        with handle:
            info = os.fstat(handle.fileno())
            size = info.st_size
            etag = '"%x-%x"' % (size, info.st_mtime_ns)
            start, end, status = 0, size - 1, 200
            requested = self.headers.get("Range")
            condition = self.headers.get("If-Range")
            if requested and (condition is None or condition.strip() == etag):
                span = parse_range(requested, size)
                if span is None:
                    self.send_response(416)
                    self.send_header("Content-Range", "bytes */%d" % size)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                start, end = span
                status = 206
            length = end - start + 1
            self.send_response(status)
            self.send_header("Content-Type", AUDIO_TYPES[os.path.splitext(relative)[1].lower()])
            self.send_header("Content-Length", str(length))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "private, no-store")
            if status == 206:
                self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
            self.end_headers()
            if head:
                return
            handle.seek(start)
            try:
                while length > 0:
                    chunk = handle.read(min(CHUNK, length))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    length -= len(chunk)
            except OSError:
                pass
            if length > 0:
                self.close_connection = True


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def handle_error(self, request, client_address):
        # Сканеры портов и оборванные соединения не должны засорять журнал трассировками.
        if isinstance(sys.exc_info()[1], OSError):
            return
        super().handle_error(request, client_address)


def main():
    parser = argparse.ArgumentParser(description="CatchWave music server")
    parser.add_argument("--music-dir")
    parser.add_argument("--auth-file")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--make-auth", action="store_true", help="прочитать пароль из stdin и напечатать строку для auth-файла")
    parser.add_argument("--make-password", action="store_true", help="напечатать случайный пароль")
    parser.add_argument("--print-token", action="store_true", help="напечатать токен и отпечаток для QR-кода")
    args = parser.parse_args()

    if args.make_password:
        alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
        print("-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)))
        return
    if args.make_auth:
        password = sys.stdin.readline().rstrip("\r\n")
        if len(password) < MIN_PASSWORD_LENGTH:
            sys.exit("Пароль слишком короткий: нужно минимум %d символов." % MIN_PASSWORD_LENGTH)
        salt = secrets.token_hex(16)
        print("%s:%s:%d" % (salt, derive_key(password, salt, ITERATIONS).hex(), ITERATIONS))
        return
    if not args.auth_file or not args.cert:
        parser.error("нужны --auth-file и --cert")

    salt, key, iterations = load_auth(args.auth_file)
    fingerprint = certificate_fingerprint(args.cert)
    token = access_token(key, fingerprint)
    if args.print_token:
        print(token, fingerprint)
        return
    if not args.music_dir or not args.key:
        parser.error("нужны --music-dir и --key")
    music_dir = os.path.realpath(args.music_dir)
    if not os.path.isdir(music_dir):
        sys.exit("Папка с музыкой не найдена: %s" % music_dir)

    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(args.cert, args.key)
    if "LibreSSL" in ssl.OPENSSL_VERSION:
        # Старый LibreSSL (например, в системном Python на macOS) не выбирает кривую для ECDHE сам.
        tls.set_ecdh_curve("prime256v1")

    server = Server((args.bind, args.port), Handler)
    server.tls = tls
    server.token = token.encode()
    server.key = key
    server.salt = salt
    server.iterations = iterations
    server.fingerprint = fingerprint
    server.music_dir = music_dir
    print("CatchWave server слушает %s:%d, музыка: %s" % (args.bind, args.port, music_dir), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
