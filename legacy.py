"""Legacy TLS :8770 path (OpenDrop-compatible; Mac receivers)."""

from __future__ import annotations

import base64
import hashlib
import plistlib
import socket
import ssl
import time
from pathlib import Path

import config
from config import hexdump, log, resolve_ca_file, resolve_key_dir
from netutil import bind_to_iface, scoped


def is_http_url(value: str) -> bool:
    return value.startswith(("http://", "https://"))


def normalize_url(value: str) -> str:
    value = value.strip()
    if not is_http_url(value):
        raise ValueError(f"not a URL: {value!r}")
    return value


def guess_file_uti(file_path: Path) -> str:
    """Apple UTI guess (opendrop uses fleep; keep simple extension map)."""
    ext = file_path.suffix.lower()
    return {
        ".txt": "public.plain-text",
        ".jpg": "public.jpeg",
        ".jpeg": "public.jpeg",
        ".png": "public.png",
        ".gif": "com.compuserve.gif",
        ".pdf": "com.adobe.pdf",
        ".zip": "public.zip-archive",
    }.get(ext, "public.content")


def fresh_sender_id() -> str:
    import secrets

    return f"{secrets.randbelow(0xFFFFFFFFFFFF):012x}"


def resolve_ask_file(path: Path) -> Path:
    """Ensure Ask plist references a real file (opendrop uses file metadata in /Ask)."""
    if path.is_file():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("AirDrop probe\n", encoding="utf-8")
    return path


def double_sha1_hash_b64(*values: str) -> str:
    """OpenDrop legacy Contacts hash (double SHA-1, base64, comma-separated)."""
    out: list[str] = []
    for v in values:
        v = (v or "").strip()
        if not v:
            continue
        s = hashlib.sha1(v.encode("utf-8")).digest()
        d = hashlib.sha1(s).digest()
        out.append(base64.b64encode(d).decode("ascii"))
    return ",".join(out)


def load_record_data(path: Path | None) -> bytes | None:
    if path and path.is_file():
        data = path.read_bytes()
        log(f"SenderRecordData loaded ({len(data)}B) from {path}", level="dbg")
        return data
    return None


def is_modern_ios_ask_response(plist: dict | None) -> bool:
    """True when /Ask plist shows iOS 17+ (IDS/asquic path — no :8770 /Upload)."""
    if not plist:
        return False
    if plist.get("IDSSessionID") or plist.get("SupportsContactExchange"):
        return True
    if plist.get("ReceiverPushToken"):
        model = (plist.get("ReceiverModelName") or "").lower()
        if "iphone" in model or "ipad" in model:
            return True
    return False


def prompt_for_accept(accept_wait: float) -> None:
    """Pause for the user to tap Accept on the receiver."""
    log("Tap Accept on receiver, then continue")
    if accept_wait <= 0:
        try:
            input("Press Enter immediately after Accept on receiver ... ")
        except EOFError:
            pass
        return
    log(f"waiting {accept_wait:.0f}s for Accept (--accept-wait)", level="dbg")
    time.sleep(accept_wait)


def wait_for_user_accept(sock: ssl.SSLSocket, timeout: float) -> None:
    """Pause before reading the final /Upload HTTP response (after body is sent)."""
    del sock  # body already sent; prompt only
    prompt_for_accept(timeout)


def _dbg_io(direction: str, label: str, data: bytes, *, max_bytes: int = 4096) -> None:
    if not config.DEBUG or not data:
        return
    log(f"{direction} {label} ({len(data)}B)", level="dbg")
    log(f"{direction} {label} raw:\n" + hexdump(data, max_bytes=max_bytes), level="dbg")


def _read_http_raw(sock: ssl.SSLSocket, timeout: float = 60.0) -> tuple[int, bytes]:
    """Read one HTTP response directly from TLS socket (after manual upload writes)."""
    sock.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    if not buf:
        if config.DEBUG:
            log("<< RX: peer closed TLS connection with no HTTP response (0 bytes)", level="dbg")
            log(
                "<< hint: modern iPhone/iPad rejects :8770 /Upload (uses asquic); "
                "Mac receivers need Expect:100-continue + chunked",
                level="dbg",
            )
        return 0, b""
    head, _, rest = buf.partition(b"\r\n\r\n")
    try:
        status = int(head.split(b"\r\n", 1)[0].split()[1])
    except (IndexError, ValueError):
        status = 0
    headers = head.decode("ascii", errors="ignore").lower()
    body = rest
    if "content-length:" in headers:
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                try:
                    want = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    want = 0
                while len(body) < want:
                    more = sock.recv(4096)
                    if not more:
                        break
                    body += more
                body = body[:want]
                break
    elif "transfer-encoding: chunked" in headers:
        decoded = b""
        chunk_buf = body
        while True:
            while b"\r\n" not in chunk_buf:
                more = sock.recv(4096)
                if not more:
                    break
                chunk_buf += more
            if b"\r\n" not in chunk_buf:
                break
            size_line, chunk_buf = chunk_buf.split(b"\r\n", 1)
            try:
                size = int(size_line.split(b";")[0], 16)
            except ValueError:
                break
            if size == 0:
                break
            while len(chunk_buf) < size + 2:
                chunk_buf += sock.recv(4096)
            decoded += chunk_buf[:size]
            chunk_buf = chunk_buf[size + 2 :]
        body = decoded
    _dbg_io("<<", "HTTP response headers", head, max_bytes=2048)
    if body:
        _dbg_io("<<", "HTTP response body", body, max_bytes=2048)
    elif config.DEBUG:
        log(f"<< RX HTTP {status} (empty body)", level="dbg")
    return status, body


def _build_gzip_cpio(file_path: Path) -> bytes:
    """gzip-cpio archive with a single ./filename entry (AirDrop /Upload body).

    Uses libarchive-c's high-level add_file_from_memory so the entry path is set
    to './name' directly, avoiding the low-level ArchiveEntry/ffi API which is
    not stable across libarchive-c versions (5.x changed the constructor).
    """
    import io

    try:
        import libarchive  # type: ignore
    except ImportError as exc:
        raise ImportError("libarchive missing — pip install libarchive-c") from exc

    data = file_path.read_bytes()
    store_path = f"./{file_path.name}"

    stream = io.BytesIO()
    with libarchive.custom_writer(stream.write, "cpio", filter_name="gzip") as archive:
        # entry_data as a one-chunk iterable works across libarchive-c versions
        archive.add_file_from_memory(store_path, len(data), [data])
    return stream.getvalue()


class LegacyTLSAirDrop:
    """OpenDrop-compatible TLS :8770 — POST /Ask -> wait Accept -> POST /Upload (one connection)."""

    ASK_TIMEOUT = 120.0

    _HTTP_PLIST_HEADERS = (
        "Content-Type: application/octet-stream\r\n"
        "Connection: keep-alive\r\n"
        "Accept: */*\r\n"
        "User-Agent: AirDrop/1.0\r\n"
        "Accept-Language: en-us\r\n"
        "Accept-Encoding: br, gzip, deflate\r\n"
    )

    def __init__(
        self,
        iface: str,
        computer_name: str = "OpenDrop",
        timeout: float = 120.0,
        *,
        apple_id: str | None = None,
        phone: str | None = None,
        record_data: bytes | None = None,
    ):
        self.iface = iface
        self.computer_name = computer_name
        self.timeout = timeout
        self.apple_id = apple_id
        self.phone = phone
        self.record_data = record_data
        self._cert_dir = resolve_key_dir()
        self._ca = resolve_ca_file()

    def _connect(self, host: str, port: int) -> ssl.SSLSocket:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if self._ca and self._ca.is_file():
            ctx.load_verify_locations(cafile=str(self._ca))
        cert = self._cert_dir / "certificate.pem"
        key = self._cert_dir / "key.pem"
        if cert.is_file() and key.is_file():
            ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
        raw = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        raw.settimeout(self.timeout)
        bind_to_iface(raw, self.iface)
        raw.connect((scoped(host, self.iface), port))
        tls_sock = ctx.wrap_socket(raw, server_hostname=host.split("%")[0])
        if config.DEBUG:
            log(f"TLS connected -> {host}:{port} cipher={tls_sock.cipher()}", level="dbg")
        return tls_sock

    def _open_session(self, host: str, port: int) -> ssl.SSLSocket:
        return self._connect(host, port)

    def _host_hdr(self, host: str, port: int) -> str:
        host_n = host.split("%")[0]
        return f"[{host_n}]:{port}"

    def _post(
        self,
        sock: ssl.SSLSocket,
        path: str,
        body: bytes,
        host: str,
        port: int,
        *,
        read_timeout: float | None = None,
    ) -> tuple[int, bytes]:
        host_hdr = self._host_hdr(host, port)
        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host_hdr}\r\n"
            f"{self._HTTP_PLIST_HEADERS}"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n"
        ).encode("ascii") + body
        _dbg_io(">>", f"TLS {path} request", req, max_bytes=4096)
        sock.sendall(req)
        status, resp_body = _read_http_raw(sock, read_timeout or self.timeout)
        if config.DEBUG:
            log(f"TLS {path} Host={host_hdr} -> HTTP {status} body={len(resp_body)}B", level="dbg")
        return status, resp_body

    def discover(self, sock: ssl.SSLSocket, host: str, port: int) -> dict | None:
        body_dict: dict = {}
        if self.record_data:
            body_dict["SenderRecordData"] = self.record_data
        body = plistlib.dumps(body_dict, fmt=plistlib.FMT_BINARY)
        log("TLS /Discover ...", level="dbg")
        status, resp = self._post(sock, "/Discover", body, host, port)
        if status != 200:
            log(f"TLS /Discover failed HTTP {status}", level="dbg")
            return None
        if not resp:
            log("TLS /Discover HTTP 200 empty body — continuing to /Ask", level="dbg")
            return {}
        try:
            plist = plistlib.loads(resp)
            name = plist.get("ReceiverComputerName") or plist.get("ReceiverModelName")
            if name:
                log(f"TLS /Discover -> {name}")
            return plist
        except Exception as exc:
            log(f"TLS /Discover plist parse: {exc} — continuing to /Ask", level="dbg")
            return {}

    def _build_ask_body(
        self,
        sender: str,
        service_id: str | None,
        *,
        file_path: Path | None = None,
        url: str | None = None,
    ) -> bytes:
        ask_body = {
            "SenderComputerName": sender,
            "BundleID": "com.apple.finder",
            "SenderModelName": "OpenDrop",
            "SenderID": service_id or fresh_sender_id(),
            "ConvertMediaFormats": False,
        }
        if self.apple_id:
            ask_body["SenderEmailHash"] = double_sha1_hash_b64(self.apple_id)
            log(f"Ask SenderEmailHash set for {self.apple_id}", level="dbg")
        if self.phone:
            ask_body["SenderPhoneHash"] = double_sha1_hash_b64(self.phone)
            log(f"Ask SenderPhoneHash set", level="dbg")
        if self.record_data:
            ask_body["SenderRecordData"] = self.record_data
            log(f"Ask SenderRecordData embedded ({len(self.record_data)}B)", level="dbg")
        if url:
            # opendrop: Items = [url_string, ...] — no Files, no /Upload
            ask_body["Items"] = [normalize_url(url)]
        else:
            file_path = resolve_ask_file(file_path or Path("/tmp/poke.txt"))
            ask_body["Files"] = [{
                "FileName": file_path.name,
                "FileType": guess_file_uti(file_path),
                "FileBomPath": f"./{file_path.name}",
                "FileIsDirectory": False,
                "ConvertMediaFormats": 0,
            }]
            ask_body["Items"] = []
        return plistlib.dumps(ask_body, fmt=plistlib.FMT_BINARY)

    def ask_on_socket(
        self,
        sock: ssl.SSLSocket,
        sender: str,
        host: str,
        port: int,
        service_id: str | None = None,
        *,
        file_path: Path | None = None,
        url: str | None = None,
    ) -> tuple[bool, dict | None]:
        body = self._build_ask_body(sender, service_id, file_path=file_path, url=url)
        label = normalize_url(url) if url else resolve_ask_file(file_path or Path("poke.txt")).name
        log(f"TLS /Ask -> {label} ({len(body)}B plist, timeout {self.ASK_TIMEOUT:.0f}s)", level="dbg")
        status, resp = self._post(
            sock, "/Ask", body, host, port, read_timeout=self.ASK_TIMEOUT,
        )
        ok = status == 200
        plist: dict | None = None
        if ok and resp:
            try:
                plist = plistlib.loads(resp)
                rname = plist.get("ReceiverComputerName") or plist.get("ReceiverModelName")
                if rname:
                    log(f"TLS /Ask delivered -> receiver {rname}")
                if is_modern_ios_ask_response(plist):
                    log(
                        "TLS /Ask plist: modern iOS (IDSSessionID/asquic) — "
                        ":8770 /Upload will not work on this receiver",
                        level="dbg",
                    )
            except Exception as exc:
                log(f"TLS /Ask response plist: {exc}", level="dbg")
        elif ok and not resp:
            log("TLS /Ask HTTP 200 empty body", level="dbg")
        log(f"TLS /Ask -> {'OK (popup should appear)' if ok else f'FAIL HTTP {status}'}")
        return ok, plist

    def ask_session(
        self,
        host: str,
        port: int,
        sender: str,
        *,
        file_path: Path | None = None,
        url: str | None = None,
        service_id: str | None = None,
        discover: bool = False,
    ) -> tuple[bool, dict | None]:
        """TLS connect + /Ask only (popup). Returns (ok, response plist)."""
        if url:
            file_path = None
        elif file_path:
            file_path = resolve_ask_file(file_path)
        else:
            file_path = resolve_ask_file(Path("/tmp/poke.txt"))

        kind = f"URL {url}" if url else f"file {file_path.name}"
        log(f"TLS /Ask session -> {host}:{port} ({kind})")
        try:
            sock = self._open_session(host, port)
        except OSError as exc:
            log(f"TLS connect :{port}: {exc}", level="err")
            return False, None
        try:
            if discover:
                self.discover(sock, host, port)
            return self.ask_on_socket(
                sock, sender, host, port, service_id, file_path=file_path, url=url,
            )
        except OSError as exc:
            log(f"TLS /Ask session: {exc}", level="err")
            return False, None
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def upload_on_socket(
        self,
        sock: ssl.SSLSocket,
        file_path: Path,
        host: str,
        port: int,
        *,
        accept_wait: float = 0.0,
    ) -> bool:
        try:
            payload = _build_gzip_cpio(file_path)
        except ImportError:
            log("libarchive missing — pip install libarchive-c", level="err")
            return False
        log(f"TLS /Upload archive {len(payload)}B gzip-cpio", level="dbg")
        host_hdr = self._host_hdr(host, port)
        # OpenDrop + iOS expect Expect:100-continue then chunked cpio body (not Content-Length).
        hdr = (
            f"POST /Upload HTTP/1.1\r\n"
            f"Host: {host_hdr}\r\n"
            f"Content-Type: application/x-cpio\r\n"
            f"Expect: 100-continue\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n"
            f"Accept: */*\r\n"
            f"User-Agent: AirDrop/1.0\r\n"
            f"Accept-Language: en-us\r\n"
            f"Accept-Encoding: br, gzip, deflate\r\n"
            f"\r\n"
        ).encode("ascii")
        _dbg_io(">>", "TLS /Upload request headers", hdr)
        sock.sendall(hdr)
        cont, cont_body = _read_http_raw(sock, 60.0)
        if cont != 100:
            log(
                f"TLS /Upload expected 100 Continue, got HTTP {cont} {cont_body[:120]!r}",
                level="warn",
            )
            if cont == 0:
                log(
                    "TLS /Upload: peer closed — wrong upload framing or iOS wants modern asquic path",
                    level="warn",
                )
            return False
        log("TLS /Upload 100 Continue OK", level="dbg")
        chunk = f"{len(payload):x}\r\n".encode("ascii") + payload + b"\r\n0\r\n\r\n"
        _dbg_io(">>", "TLS /Upload chunked body", chunk, max_bytes=512)
        sock.sendall(chunk)
        # OpenDrop/Mac: upload body goes out right after /Ask; final HTTP 200 may wait for Accept.
        wait_for_user_accept(sock, accept_wait)
        status, resp_body = _read_http_raw(sock, self.ASK_TIMEOUT)
        ok = status == 200
        if not ok and config.DEBUG:
            log(f"TLS /Upload final response: HTTP {status} {resp_body[:160]!r}", level="dbg")
        log(f"TLS /Upload -> {'OK' if ok else f'FAIL HTTP {status}'}")
        return ok

    def send_session(
        self,
        host: str,
        port: int,
        sender: str,
        *,
        file_path: Path | None = None,
        url: str | None = None,
        service_id: str | None = None,
        discover: bool = False,
        do_upload: bool = True,
        accept_wait: float = 0.0,
    ) -> bool:
        """OpenDrop: /Ask (+ /Upload for files only; URLs use Items= in Ask, no Upload)."""
        is_url = bool(url)
        if is_url:
            do_upload = False
        elif file_path:
            file_path = resolve_ask_file(file_path)
        else:
            file_path = resolve_ask_file(Path("/tmp/poke.txt"))

        kind = f"URL {url}" if is_url else f"file {file_path.name}"
        log(f"TLS session -> {host}:{port} ({kind})")
        try:
            sock = self._open_session(host, port)
        except OSError as exc:
            log(f"TLS connect :{port}: {exc}", level="err")
            return False
        try:
            if discover:
                self.discover(sock, host, port)
            ask_ok, ask_plist = self.ask_on_socket(
                sock, sender, host, port, service_id, file_path=file_path, url=url,
            )
            if not ask_ok:
                return False
            if is_url:
                log("URL sent via /Ask (no /Upload needed)")
                return True
            if do_upload:
                if is_modern_ios_ask_response(ask_plist):
                    log(
                        "modern iOS receiver — skipping :8770 /Upload "
                        "(file transfer uses companion-link + asquic)",
                        level="warn",
                    )
                    return False
                return self.upload_on_socket(
                    sock, file_path, host, port, accept_wait=accept_wait,
                )
            return True
        except OSError as exc:
            log(f"TLS session: {exc}", level="err")
            return False
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def ask(
        self,
        host: str,
        port: int,
        sender: str | None = None,
        *,
        file_path: Path | None = None,
        url: str | None = None,
    ) -> bool:
        name = sender or self.computer_name
        return self.send_session(
            host, port, name, file_path=file_path, url=url, discover=False, do_upload=False,
        )

    def upload(self, host: str, port: int, file_path: Path, sender: str | None = None) -> bool:
        name = sender or self.computer_name
        return self.send_session(
            host, port, name, file_path=file_path, discover=False, do_upload=True,
        )
