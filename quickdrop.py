from __future__ import annotations

import hashlib
import json
import os
import queue
import secrets
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as exc:  # pragma: no cover - shown only when launched without dependencies
    raise SystemExit("缺少 cryptography 依赖，请先运行 build.ps1。") from exc

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError as exc:  # pragma: no cover - shown only when launched without dependencies
    raise SystemExit("缺少 tkinterdnd2 依赖，请先运行 build.ps1。") from exc


APP_NAME = "Flash Share"
APP_VERSION = "1.1.0"
DEFAULT_PORT = 48231
DISCOVERY_MAGIC = b"QUICKDROP_DISCOVER_V2"
HANDSHAKE_MAGIC = b"QDROP2\x00"
CHUNK_SIZE = 1024 * 1024
MAX_FRAME_SIZE = 40 * 1024 * 1024
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
INVALID_WINDOWS_CHARS = set('<>:"|?*')
RESERVED_WINDOWS_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


class TransferError(Exception):
    pass


class TransferCancelled(TransferError):
    pass


def generate_code() -> str:
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(10))
    return f"{raw[:5]}-{raw[5:]}"


def normalize_code(code: str) -> bytes:
    normalized = "".join(ch for ch in code.upper() if ch.isalnum())
    if len(normalized) < 8:
        raise TransferError("连接码格式不正确")
    return normalized.encode("ascii", "strict")


def derive_key(code: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", normalize_code(code), salt, 220_000, dklen=32)


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        data = sock.recv(length - len(chunks))
        if not data:
            raise TransferError("连接意外中断")
        chunks.extend(data)
    return bytes(chunks)


class SecureChannel:
    def __init__(self, sock: socket.socket, key: bytes, *, is_server: bool) -> None:
        self.sock = sock
        self.aes = AESGCM(key)
        self.send_prefix = b"SRVR" if is_server else b"CLNT"
        self.recv_prefix = b"CLNT" if is_server else b"SRVR"
        self.send_counter = 0
        self.recv_counter = 0

    @staticmethod
    def _nonce(prefix: bytes, counter: int) -> bytes:
        return prefix + struct.pack("!Q", counter)

    def send_frame(self, payload: bytes) -> None:
        nonce = self._nonce(self.send_prefix, self.send_counter)
        self.send_counter += 1
        encrypted = self.aes.encrypt(nonce, payload, None)
        self.sock.sendall(struct.pack("!I", len(encrypted)) + encrypted)

    def recv_frame(self, max_size: int = MAX_FRAME_SIZE) -> bytes:
        size = struct.unpack("!I", recv_exact(self.sock, 4))[0]
        if size < 16 or size > max_size:
            raise TransferError("收到异常数据帧")
        encrypted = recv_exact(self.sock, size)
        nonce = self._nonce(self.recv_prefix, self.recv_counter)
        self.recv_counter += 1
        try:
            return self.aes.decrypt(nonce, encrypted, None)
        except InvalidTag as exc:
            raise TransferError("连接码错误或数据已损坏") from exc

    def send_json(self, data: dict) -> None:
        self.send_frame(json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    def recv_json(self) -> dict:
        try:
            value = json.loads(self.recv_frame().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TransferError("收到无法识别的控制信息") from exc
        if not isinstance(value, dict):
            raise TransferError("控制信息格式不正确")
        return value


@dataclass(frozen=True)
class SourceSelection:
    path: Path
    root_name: str


@dataclass(frozen=True)
class ManifestEntry:
    kind: str
    relative_path: str
    source_path: Path | None
    size: int = 0
    mtime_ns: int = 0

    def wire(self) -> dict:
        return {
            "kind": self.kind,
            "path": self.relative_path,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
        }


def build_manifest(selections: Iterable[SourceSelection]) -> list[ManifestEntry]:
    entries: list[ManifestEntry] = []
    for selection in selections:
        source = selection.path
        if source.is_symlink():
            continue
        if source.is_file():
            stat = source.stat()
            entries.append(ManifestEntry("file", selection.root_name, source, stat.st_size, stat.st_mtime_ns))
            continue
        if not source.is_dir():
            continue

        entries.append(ManifestEntry("dir", selection.root_name, None))
        for current, dir_names, file_names in os.walk(source, followlinks=False):
            current_path = Path(current)
            dir_names[:] = sorted(
                name for name in dir_names if not (current_path / name).is_symlink()
            )
            relative_current = current_path.relative_to(source)
            for name in dir_names:
                relative = PurePosixPath(selection.root_name, *relative_current.parts, name).as_posix()
                entries.append(ManifestEntry("dir", relative, None))
            for name in sorted(file_names):
                file_path = current_path / name
                if file_path.is_symlink() or not file_path.is_file():
                    continue
                stat = file_path.stat()
                relative = PurePosixPath(selection.root_name, *relative_current.parts, name).as_posix()
                entries.append(ManifestEntry("file", relative, file_path, stat.st_size, stat.st_mtime_ns))
    return entries


def manifest_totals(entries: Iterable[ManifestEntry]) -> tuple[int, int]:
    files = [entry for entry in entries if entry.kind == "file"]
    return len(files), sum(entry.size for entry in files)


def format_size(size: float) -> str:
    units = ("B", "KB", "MB", "GB", "TB")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def validate_relative_path(relative: str) -> tuple[str, ...]:
    if not isinstance(relative, str) or not relative or len(relative) > 1200:
        raise TransferError("文件路径不合法")
    path = PurePosixPath(relative)
    if path.is_absolute():
        raise TransferError("禁止绝对路径")
    parts = path.parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise TransferError("文件路径包含危险内容")
    for part in parts:
        if len(part) > 240 or any(ch in INVALID_WINDOWS_CHARS or ord(ch) < 32 for ch in part):
            raise TransferError(f"Windows 不支持此文件名：{part}")
        if part.endswith((" ", ".")) or part.split(".", 1)[0].upper() in RESERVED_WINDOWS_NAMES:
            raise TransferError(f"Windows 不支持此文件名：{part}")
    return parts


def unique_name(base: Path, name: str, reserved: set[str], is_file: bool) -> str:
    candidate = name
    index = 2
    if is_file:
        suffix = Path(name).suffix
        stem = name[:-len(suffix)] if suffix else name
    else:
        stem, suffix = name, ""
    while (base / candidate).exists() or str((base / candidate).resolve(strict=False)).casefold() in reserved:
        candidate = f"{stem} ({index}){suffix}"
        index += 1
    return candidate


def get_local_ipv4_addresses() -> list[str]:
    addresses: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addresses.add(info[4][0])
    except OSError:
        pass
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("8.8.8.8", 80))
        addresses.add(probe.getsockname()[0])
        probe.close()
    except OSError:
        pass
    return sorted(addr for addr in addresses if not addr.startswith("127.")) or ["127.0.0.1"]


EventCallback = Callable[[str, dict], None]


class ReceiverServer:
    def __init__(self, save_dir: Path, port: int, code: str, callback: EventCallback) -> None:
        self.save_dir = save_dir.resolve()
        self.port = port
        self.code = code
        self.callback = callback
        self.stop_event = threading.Event()
        self.tcp_socket: socket.socket | None = None
        self.udp_socket: socket.socket | None = None
        self.client_sockets: set[socket.socket] = set()
        self.client_lock = threading.Lock()
        self.reserved_roots: set[str] = set()
        self.reservation_lock = threading.Lock()

    def start(self) -> None:
        self.save_dir.mkdir(parents=True, exist_ok=True)
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind(("0.0.0.0", self.port))
        tcp.listen(8)
        tcp.settimeout(0.8)
        self.port = tcp.getsockname()[1]
        self.tcp_socket = tcp

        try:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            udp.bind(("0.0.0.0", self.port))
            udp.settimeout(0.8)
            self.udp_socket = udp
        except OSError:
            self.udp_socket = None

        threading.Thread(target=self._accept_loop, name="receiver-accept", daemon=True).start()
        if self.udp_socket:
            threading.Thread(target=self._discovery_loop, name="receiver-discovery", daemon=True).start()
        self.callback("server_started", {"port": self.port, "ips": get_local_ipv4_addresses()})

    def stop(self) -> None:
        self.stop_event.set()
        for sock in (self.tcp_socket, self.udp_socket):
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
        with self.client_lock:
            clients = list(self.client_sockets)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
                client.close()
            except OSError:
                pass
        self.callback("server_stopped", {})

    def _accept_loop(self) -> None:
        assert self.tcp_socket is not None
        while not self.stop_event.is_set():
            try:
                client, address = self.tcp_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.client_lock:
                self.client_sockets.add(client)
            threading.Thread(
                target=self._handle_client,
                args=(client, address),
                name=f"receiver-{address[0]}",
                daemon=True,
            ).start()

    def _discovery_loop(self) -> None:
        assert self.udp_socket is not None
        while not self.stop_event.is_set():
            try:
                data, address = self.udp_socket.recvfrom(1024)
                if data == DISCOVERY_MAGIC:
                    response = json.dumps({
                        "app": "FlashShare",
                        "version": 2,
                        "name": socket.gethostname(),
                        "port": self.port,
                    }, ensure_ascii=False).encode("utf-8")
                    self.udp_socket.sendto(response, address)
            except socket.timeout:
                continue
            except OSError:
                break

    def _plan_targets(self, entries: list[dict]) -> tuple[dict[str, str], set[str]]:
        roots: dict[str, bool] = {}
        for entry in entries:
            parts = validate_relative_path(entry.get("path", ""))
            root = parts[0]
            is_root_file = len(parts) == 1 and entry.get("kind") == "file"
            roots[root] = roots.get(root, False) or is_root_file

        mapping: dict[str, str] = {}
        reservations: set[str] = set()
        with self.reservation_lock:
            for root, is_file in roots.items():
                chosen = unique_name(self.save_dir, root, self.reserved_roots | reservations, is_file)
                resolved_key = str((self.save_dir / chosen).resolve(strict=False)).casefold()
                mapping[root] = chosen
                reservations.add(resolved_key)
            self.reserved_roots.update(reservations)
        return mapping, reservations

    def _target_for(self, relative: str, mapping: dict[str, str]) -> Path:
        parts = list(validate_relative_path(relative))
        parts[0] = mapping[parts[0]]
        target = self.save_dir.joinpath(*parts).resolve(strict=False)
        try:
            if os.path.commonpath((str(self.save_dir), str(target))) != str(self.save_dir):
                raise TransferError("文件目标路径越界")
        except ValueError as exc:
            raise TransferError("文件目标路径越界") from exc
        return target

    def _handle_client(self, client: socket.socket, address: tuple[str, int]) -> None:
        reservations: set[str] = set()
        temp_path: Path | None = None
        peer = address[0]
        try:
            client.settimeout(30)
            salt = secrets.token_bytes(16)
            client.sendall(HANDSHAKE_MAGIC + salt)
            channel = SecureChannel(client, derive_key(self.code, salt), is_server=True)
            hello = channel.recv_json()
            if hello.get("type") != "hello" or hello.get("version") != 2:
                raise TransferError("客户端版本不兼容")
            entries = hello.get("entries")
            if not isinstance(entries, list) or len(entries) > 200_000:
                raise TransferError("文件清单不合法或数量过多")

            total_size = 0
            file_count = 0
            for entry in entries:
                if not isinstance(entry, dict) or entry.get("kind") not in ("file", "dir"):
                    raise TransferError("文件清单不合法")
                validate_relative_path(entry.get("path", ""))
                size = entry.get("size", 0)
                if not isinstance(size, int) or size < 0:
                    raise TransferError("文件大小不合法")
                if entry["kind"] == "file":
                    file_count += 1
                    total_size += size

            free = shutil.disk_usage(self.save_dir).free
            if total_size > max(0, free - 64 * 1024 * 1024):
                channel.send_json({"type": "rejected", "message": "接收电脑磁盘空间不足"})
                return

            mapping, reservations = self._plan_targets(entries)
            for entry in entries:
                if entry["kind"] == "dir":
                    self._target_for(entry["path"], mapping).mkdir(parents=True, exist_ok=True)

            channel.send_json({"type": "accepted", "files": file_count, "size": total_size})
            self.callback("recv_started", {"peer": peer, "files": file_count, "total": total_size})
            received_total = 0
            completed_files = 0
            started_at = time.monotonic()

            for expected in (entry for entry in entries if entry["kind"] == "file"):
                start = channel.recv_json()
                if start.get("type") != "file_start" or start.get("path") != expected["path"]:
                    raise TransferError("文件传输顺序不一致")
                target = self._target_for(expected["path"], mapping)
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    target = target.with_name(unique_name(target.parent, target.name, set(), True))
                temp_path = target.parent / f".{target.name}.{uuid.uuid4().hex}.qpart"
                channel.send_json({"type": "ready", "name": target.name})

                hasher = hashlib.sha256()
                remaining = expected["size"]
                with temp_path.open("wb") as output:
                    while remaining:
                        chunk = channel.recv_frame(CHUNK_SIZE + 32)
                        if not chunk or len(chunk) > remaining:
                            raise TransferError("文件数据长度不正确")
                        output.write(chunk)
                        hasher.update(chunk)
                        remaining -= len(chunk)
                        received_total += len(chunk)
                        elapsed = max(time.monotonic() - started_at, 0.001)
                        self.callback("recv_progress", {
                            "peer": peer,
                            "file": expected["path"],
                            "done": received_total,
                            "total": total_size,
                            "speed": received_total / elapsed,
                        })

                end = channel.recv_json()
                digest = hasher.hexdigest()
                if end.get("type") != "file_end" or not secrets.compare_digest(end.get("sha256", ""), digest):
                    raise TransferError(f"完整性校验失败：{expected['path']}")
                os.replace(temp_path, target)
                temp_path = None
                mtime_ns = expected.get("mtime_ns", 0)
                if isinstance(mtime_ns, int) and mtime_ns > 0:
                    try:
                        os.utime(target, ns=(mtime_ns, mtime_ns))
                    except OSError:
                        pass
                completed_files += 1
                channel.send_json({"type": "file_ok", "sha256": digest})

            channel.send_json({"type": "complete", "files": completed_files, "size": received_total})
            self.callback("recv_complete", {
                "peer": peer,
                "files": completed_files,
                "total": received_total,
                "folder": str(self.save_dir),
            })
        except (TransferError, OSError, ValueError) as exc:
            if not self.stop_event.is_set():
                self.callback("recv_error", {"peer": peer, "message": str(exc)})
        finally:
            if temp_path:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass
            if reservations:
                with self.reservation_lock:
                    self.reserved_roots.difference_update(reservations)
            with self.client_lock:
                self.client_sockets.discard(client)
            try:
                client.close()
            except OSError:
                pass


def send_manifest(
    host: str,
    port: int,
    code: str,
    entries: list[ManifestEntry],
    callback: EventCallback,
    cancel_event: threading.Event,
    socket_holder: dict[str, socket.socket] | None = None,
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if socket_holder is not None:
        socket_holder["socket"] = sock
    try:
        sock.settimeout(15)
        sock.connect((host, port))
        handshake = recv_exact(sock, len(HANDSHAKE_MAGIC) + 16)
        if not handshake.startswith(HANDSHAKE_MAGIC):
            raise TransferError("目标不是兼容的 Flash Share 接收端")
        salt = handshake[len(HANDSHAKE_MAGIC):]
        channel = SecureChannel(sock, derive_key(code, salt), is_server=False)
        files, total_size = manifest_totals(entries)
        channel.send_json({
            "type": "hello",
            "version": 2,
            "name": socket.gethostname(),
            "entries": [entry.wire() for entry in entries],
        })
        response = channel.recv_json()
        if response.get("type") == "rejected":
            raise TransferError(response.get("message", "接收端拒绝了传输"))
        if response.get("type") != "accepted":
            raise TransferError("连接码错误、接收端无响应或版本不兼容")

        callback("send_started", {"files": files, "total": total_size})
        sent_total = 0
        completed_files = 0
        started_at = time.monotonic()
        sock.settimeout(60)

        for entry in (item for item in entries if item.kind == "file"):
            if cancel_event.is_set():
                raise TransferCancelled("传输已取消")
            assert entry.source_path is not None
            channel.send_json({"type": "file_start", "path": entry.relative_path})
            ready = channel.recv_json()
            if ready.get("type") != "ready":
                raise TransferError(f"接收端无法创建文件：{entry.relative_path}")

            hasher = hashlib.sha256()
            with entry.source_path.open("rb") as source:
                while True:
                    if cancel_event.is_set():
                        raise TransferCancelled("传输已取消")
                    chunk = source.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    channel.send_frame(chunk)
                    hasher.update(chunk)
                    sent_total += len(chunk)
                    elapsed = max(time.monotonic() - started_at, 0.001)
                    callback("send_progress", {
                        "file": entry.relative_path,
                        "done": sent_total,
                        "total": total_size,
                        "speed": sent_total / elapsed,
                    })
            digest = hasher.hexdigest()
            channel.send_json({"type": "file_end", "sha256": digest})
            result = channel.recv_json()
            if result.get("type") != "file_ok" or result.get("sha256") != digest:
                raise TransferError(f"接收端校验失败：{entry.relative_path}")
            completed_files += 1

        result = channel.recv_json()
        if result.get("type") != "complete":
            raise TransferError("接收端未能确认传输完成")
        callback("send_complete", {"files": completed_files, "total": sent_total})
    except TransferCancelled as exc:
        callback("send_cancelled", {"message": str(exc)})
    except (TransferError, OSError, ValueError) as exc:
        callback("send_error", {"message": str(exc)})
    finally:
        try:
            sock.close()
        except OSError:
            pass
        if socket_holder is not None:
            socket_holder.pop("socket", None)


def discover_receivers(port: int, timeout: float = 2.0) -> list[dict]:
    found: dict[tuple[str, int], dict] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("0.0.0.0", 0))
        sock.settimeout(0.25)
        sock.sendto(DISCOVERY_MAGIC, ("255.255.255.255", port))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, address = sock.recvfrom(4096)
                payload = json.loads(data.decode("utf-8"))
                if payload.get("app") == "FlashShare":
                    item = {
                        "ip": address[0],
                        "port": int(payload.get("port", port)),
                        "name": str(payload.get("name", address[0])),
                    }
                    found[(item["ip"], item["port"])] = item
            except socket.timeout:
                continue
            except (OSError, ValueError, json.JSONDecodeError):
                continue
    finally:
        sock.close()
    return list(found.values())


def enable_windows_dpi_awareness() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


class QuickDropApp:
    def __init__(self) -> None:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk

        self.tk = tk
        self.ttk = ttk
        self.filedialog = filedialog
        self.messagebox = messagebox
        self.root = TkinterDnD.Tk()
        self.root.title(f"{APP_NAME} {APP_VERSION}")
        self.root.geometry("820x660")
        self.root.minsize(760, 600)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.events: queue.Queue[tuple[str, dict]] = queue.Queue()
        self.selections: list[SourceSelection] = []
        self.receiver: ReceiverServer | None = None
        self.send_cancel = threading.Event()
        self.sender_socket: dict[str, socket.socket] = {}
        self.sending = False
        self.active_send_selections: list[SourceSelection] = []
        self._selection_drag_anchor: str | None = None
        self._selection_drag_initial: set[str] = set()

        self._configure_style()
        self._build_ui()
        self.root.after(80, self._poll_events)

    def _configure_style(self) -> None:
        style = self.ttk.Style(self.root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        self.root.option_add("*Font", ("Microsoft YaHei UI", 10))
        style.configure("Title.TLabel", font=("Microsoft YaHei UI", 20, "bold"), foreground="#1769aa")
        style.configure("Sub.TLabel", foreground="#52616b")
        style.configure("Accent.TButton", font=("Microsoft YaHei UI", 11, "bold"))
        style.configure("TNotebook.Tab", padding=(18, 8))

    def _build_ui(self) -> None:
        ttk = self.ttk
        outer = ttk.Frame(self.root, padding=(18, 14))
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="Flash Share", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            outer,
            text="两台电脑运行同一个程序，使用临时连接码进行加密直传",
            style="Sub.TLabel",
        ).pack(anchor="w", pady=(0, 10))

        notebook = ttk.Notebook(outer)
        notebook.pack(fill="both", expand=True)
        self.send_tab = ttk.Frame(notebook, padding=14)
        self.recv_tab = ttk.Frame(notebook, padding=14)
        notebook.add(self.send_tab, text="发送文件")
        notebook.add(self.recv_tab, text="接收文件")
        self._build_send_tab()
        self._build_recv_tab()

        ttk.Label(
            outer,
            text="无需账号 · 文件不经过云端 · 公网使用时需端口映射或组网连接",
            style="Sub.TLabel",
        ).pack(anchor="center", pady=(9, 0))

    def _build_send_tab(self) -> None:
        tk, ttk = self.tk, self.ttk
        target = ttk.LabelFrame(self.send_tab, text="1. 连接接收电脑", padding=10)
        target.pack(fill="x")
        target.columnconfigure(1, weight=1)
        ttk.Label(target, text="接收端 IP / 主机名").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        self.host_var = tk.StringVar()
        self.host_combo = ttk.Combobox(target, textvariable=self.host_var)
        self.host_combo.grid(row=0, column=1, columnspan=3, sticky="ew", pady=4)
        ttk.Button(target, text="扫描局域网", command=self._scan_network).grid(row=0, column=4, padx=(8, 0), pady=4)

        ttk.Label(target, text="端口").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        self.send_port_var = tk.StringVar(value=str(DEFAULT_PORT))
        ttk.Entry(target, textvariable=self.send_port_var, width=10).grid(row=1, column=1, sticky="w", pady=4)
        ttk.Label(target, text="连接码").grid(row=1, column=2, sticky="e", padx=(16, 8), pady=4)
        self.send_code_var = tk.StringVar()
        ttk.Entry(target, textvariable=self.send_code_var, width=18, font=("Consolas", 11)).grid(
            row=1, column=3, sticky="w", pady=4
        )

        files_frame = ttk.LabelFrame(self.send_tab, text="2. 选择要发送的内容", padding=10)
        files_frame.pack(fill="both", expand=True, pady=(12, 0))
        toolbar = ttk.Frame(files_frame)
        toolbar.pack(fill="x", pady=(0, 8))
        self.add_files_button = ttk.Button(toolbar, text="添加文件", command=self._add_files)
        self.add_files_button.pack(side="left")
        self.add_folder_button = ttk.Button(toolbar, text="添加文件夹", command=self._add_folder)
        self.add_folder_button.pack(side="left", padx=6)
        self.remove_selected_button = ttk.Button(toolbar, text="移除所选", command=self._remove_selected)
        self.remove_selected_button.pack(side="left")
        self.clear_selections_button = ttk.Button(toolbar, text="清空", command=self._clear_selections)
        self.clear_selections_button.pack(side="left", padx=6)
        self.selection_buttons = (
            self.add_files_button,
            self.add_folder_button,
            self.remove_selected_button,
            self.clear_selections_button,
        )
        self.summary_var = tk.StringVar(value="尚未选择文件")
        ttk.Label(toolbar, textvariable=self.summary_var, style="Sub.TLabel").pack(side="right")

        self.drop_hint_var = tk.StringVar(value="可将文件或文件夹拖到下方列表 · 按住左键拖过多行可批量选择 · Delete 删除")
        ttk.Label(files_frame, textvariable=self.drop_hint_var, style="Sub.TLabel").pack(anchor="w", pady=(0, 6))

        tree_frame = ttk.Frame(files_frame)
        tree_frame.pack(fill="both", expand=True)
        self.file_tree = ttk.Treeview(
            tree_frame,
            columns=("type", "size", "path"),
            show="headings",
            height=9,
            selectmode="extended",
        )
        self.file_tree.heading("type", text="类型")
        self.file_tree.heading("size", text="大小")
        self.file_tree.heading("path", text="位置")
        self.file_tree.column("type", width=70, anchor="center", stretch=False)
        self.file_tree.column("size", width=100, anchor="e", stretch=False)
        self.file_tree.column("path", width=500)
        scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=scroll.set)
        self.file_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.file_tree.drop_target_register(DND_FILES)
        self.file_tree.dnd_bind("<<DropEnter>>", self._on_drop_enter)
        self.file_tree.dnd_bind("<<DropLeave>>", self._on_drop_leave)
        self.file_tree.dnd_bind("<<Drop>>", self._on_drop_files)
        self.file_tree.bind("<ButtonPress-1>", self._begin_selection_drag, add="+")
        self.file_tree.bind("<B1-Motion>", self._extend_selection_drag, add="+")
        self.file_tree.bind("<ButtonRelease-1>", self._end_selection_drag, add="+")
        self.file_tree.bind("<Delete>", self._delete_selected_from_keyboard)

        action = ttk.Frame(self.send_tab)
        action.pack(fill="x", pady=(12, 0))
        self.send_button = ttk.Button(action, text="开始发送", style="Accent.TButton", command=self._start_send)
        self.send_button.pack(side="left")
        self.cancel_button = ttk.Button(action, text="取消", command=self._cancel_send, state="disabled")
        self.cancel_button.pack(side="left", padx=8)
        self.send_progress = ttk.Progressbar(action, maximum=100)
        self.send_progress.pack(side="left", fill="x", expand=True, padx=(8, 0))
        self.send_status_var = tk.StringVar(value="就绪")
        ttk.Label(self.send_tab, textvariable=self.send_status_var, style="Sub.TLabel").pack(anchor="w", pady=(6, 0))

    def _build_recv_tab(self) -> None:
        tk, ttk = self.tk, self.ttk
        settings = ttk.LabelFrame(self.recv_tab, text="接收设置", padding=12)
        settings.pack(fill="x")
        settings.columnconfigure(1, weight=1)
        ttk.Label(settings, text="保存到").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=5)
        default_downloads = Path.home() / "Downloads" / "Flash Share"
        self.save_dir_var = tk.StringVar(value=str(default_downloads))
        ttk.Entry(settings, textvariable=self.save_dir_var).grid(row=0, column=1, sticky="ew", pady=5)
        ttk.Button(settings, text="浏览", command=self._choose_save_dir).grid(row=0, column=2, padx=(8, 0), pady=5)

        ttk.Label(settings, text="监听端口").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=5)
        self.recv_port_var = tk.StringVar(value=str(DEFAULT_PORT))
        self.recv_port_entry = ttk.Entry(settings, textvariable=self.recv_port_var, width=12)
        self.recv_port_entry.grid(row=1, column=1, sticky="w", pady=5)

        ttk.Label(settings, text="本次连接码").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=5)
        self.recv_code_var = tk.StringVar(value=generate_code())
        ttk.Label(settings, textvariable=self.recv_code_var, font=("Consolas", 18, "bold"), foreground="#1769aa").grid(
            row=2, column=1, sticky="w", pady=5
        )
        self.refresh_code_button = ttk.Button(settings, text="换一个", command=lambda: self.recv_code_var.set(generate_code()))
        self.refresh_code_button.grid(row=2, column=2, padx=(8, 0), pady=5)

        ttk.Label(settings, text="本机地址").grid(row=3, column=0, sticky="nw", padx=(0, 8), pady=5)
        self.ip_var = tk.StringVar(value="启动接收后显示")
        ttk.Label(settings, textvariable=self.ip_var, foreground="#334e68").grid(row=3, column=1, columnspan=2, sticky="w", pady=5)

        controls = ttk.Frame(self.recv_tab)
        controls.pack(fill="x", pady=(12, 0))
        self.start_recv_button = ttk.Button(controls, text="开始接收", style="Accent.TButton", command=self._start_receiver)
        self.start_recv_button.pack(side="left")
        self.stop_recv_button = ttk.Button(controls, text="停止接收", command=self._stop_receiver, state="disabled")
        self.stop_recv_button.pack(side="left", padx=8)
        self.recv_progress = ttk.Progressbar(controls, maximum=100)
        self.recv_progress.pack(side="left", fill="x", expand=True, padx=(8, 0))

        self.recv_status_var = tk.StringVar(value="尚未启动")
        ttk.Label(self.recv_tab, textvariable=self.recv_status_var, style="Sub.TLabel").pack(anchor="w", pady=(8, 4))
        log_frame = ttk.LabelFrame(self.recv_tab, text="接收记录", padding=8)
        log_frame.pack(fill="both", expand=True)
        self.recv_log = tk.Text(log_frame, height=12, state="disabled", wrap="word", relief="flat", bg="#f7f9fb")
        self.recv_log.pack(fill="both", expand=True)

    def _event(self, name: str, data: dict) -> None:
        self.events.put((name, data))

    def _add_files(self) -> None:
        if self.sending:
            return
        paths = self.filedialog.askopenfilenames(title="选择要发送的文件")
        for raw in paths:
            self._add_selection(Path(raw))
        self._refresh_file_tree()

    def _add_folder(self) -> None:
        if self.sending:
            return
        raw = self.filedialog.askdirectory(title="选择要发送的文件夹")
        if raw:
            self._add_selection(Path(raw))
            self._refresh_file_tree()

    def _add_selection(self, path: Path) -> bool:
        try:
            resolved = path.expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            return False
        if not (resolved.is_file() or resolved.is_dir()):
            return False
        if any(item.path == resolved for item in self.selections):
            return False
        used = {item.root_name.casefold() for item in self.selections}
        name = resolved.name or "文件"
        candidate = name
        index = 2
        suffix = resolved.suffix if resolved.is_file() else ""
        stem = name[:-len(suffix)] if suffix else name
        while candidate.casefold() in used:
            candidate = f"{stem} ({index}){suffix}"
            index += 1
        self.selections.append(SourceSelection(resolved, candidate))
        return True

    def _on_drop_enter(self, event):
        if self.sending:
            self.drop_hint_var.set("正在发送，完成或取消后可继续添加")
        else:
            self.drop_hint_var.set("松开鼠标即可添加文件或文件夹")
        return event.action

    def _on_drop_leave(self, event):
        self._restore_drop_hint()
        return event.action

    def _on_drop_files(self, event):
        if self.sending:
            self._restore_drop_hint()
            return event.action
        added = 0
        for raw in self.root.tk.splitlist(event.data):
            if self._add_selection(Path(raw)):
                added += 1
        self._refresh_file_tree()
        if added:
            self.send_status_var.set(f"已拖入 {added} 项，可开始发送")
        self._restore_drop_hint()
        return event.action

    def _restore_drop_hint(self) -> None:
        self.drop_hint_var.set("可将文件或文件夹拖到下方列表 · 按住左键拖过多行可批量选择 · Delete 删除")

    def _begin_selection_drag(self, event) -> None:
        if self.file_tree.identify_region(event.x, event.y) != "cell":
            self._selection_drag_anchor = None
            return
        row = self.file_tree.identify_row(event.y)
        self._selection_drag_anchor = row or None
        self._selection_drag_initial = set(self.file_tree.selection()) if event.state & 0x0004 else set()

    def _extend_selection_drag(self, event):
        anchor = self._selection_drag_anchor
        row = self.file_tree.identify_row(event.y)
        if not anchor or not row:
            return None
        children = list(self.file_tree.get_children())
        try:
            start = children.index(anchor)
            end = children.index(row)
        except ValueError:
            return None
        selected = self._selection_drag_initial.union(children[min(start, end):max(start, end) + 1])
        self.file_tree.selection_set(tuple(selected))
        self.file_tree.focus(row)
        self.file_tree.see(row)
        return "break"

    def _end_selection_drag(self, _event) -> None:
        self._selection_drag_anchor = None
        self._selection_drag_initial.clear()

    def _delete_selected_from_keyboard(self, _event):
        self._remove_selected()
        return "break"

    def _refresh_file_tree(self) -> None:
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        total = 0
        for index, selection in enumerate(self.selections):
            is_file = selection.path.is_file()
            size = selection.path.stat().st_size if is_file else self._folder_size(selection.path)
            total += size
            self.file_tree.insert("", "end", iid=str(index), values=(
                "文件" if is_file else "文件夹",
                format_size(size),
                str(selection.path),
            ))
        self.summary_var.set(f"{len(self.selections)} 项，共 {format_size(total)}" if self.selections else "尚未选择文件")

    @staticmethod
    def _folder_size(path: Path) -> int:
        total = 0
        try:
            for current, dirs, files in os.walk(path, followlinks=False):
                current_path = Path(current)
                dirs[:] = [name for name in dirs if not (current_path / name).is_symlink()]
                for name in files:
                    file_path = current_path / name
                    if not file_path.is_symlink():
                        try:
                            total += file_path.stat().st_size
                        except OSError:
                            pass
        except OSError:
            pass
        return total

    def _remove_selected(self) -> None:
        if self.sending:
            return
        indices = sorted((int(item) for item in self.file_tree.selection()), reverse=True)
        for index in indices:
            self.selections.pop(index)
        self._refresh_file_tree()

    def _clear_selections(self) -> None:
        if self.sending:
            return
        self.selections.clear()
        self._refresh_file_tree()

    def _set_selection_controls_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for button in self.selection_buttons:
            button.configure(state=state)
        self._restore_drop_hint()

    def _scan_network(self) -> None:
        try:
            port = int(self.send_port_var.get())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            self.messagebox.showerror("端口错误", "请输入 1 到 65535 之间的端口。")
            return
        self.send_status_var.set("正在扫描局域网接收端…")
        threading.Thread(target=lambda: self._event("discovery", {"items": discover_receivers(port)}), daemon=True).start()

    def _start_send(self) -> None:
        if self.sending:
            return
        host = self.host_var.get().split("  —  ", 1)[0].strip()
        code = self.send_code_var.get().strip()
        if not host or not code or not self.selections:
            self.messagebox.showwarning("信息不完整", "请填写接收端地址和连接码，并选择要发送的文件。")
            return
        try:
            port_text = self.send_port_var.get().strip()
            if host.count(":") == 1:
                host_part, embedded_port = host.rsplit(":", 1)
                if embedded_port.isdigit():
                    host = host_part.strip()
                    port_text = embedded_port
            port = int(port_text)
            if not 1 <= port <= 65535:
                raise ValueError
            normalize_code(code)
            send_selections = list(self.selections)
            entries = build_manifest(send_selections)
            files, _ = manifest_totals(entries)
            if not entries or files == 0:
                raise TransferError("没有可发送的文件（符号链接不会被发送）")
        except (ValueError, TransferError, OSError) as exc:
            self.messagebox.showerror("无法发送", str(exc) or "端口格式不正确")
            return

        self.sending = True
        self.active_send_selections = send_selections
        self.host_var.set(host)
        self.send_port_var.set(str(port))
        self.send_cancel.clear()
        self.send_progress["value"] = 0
        self.send_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self._set_selection_controls_enabled(False)
        self.send_status_var.set("正在连接接收端…")
        threading.Thread(
            target=send_manifest,
            args=(host, port, code, entries, self._event, self.send_cancel, self.sender_socket),
            name="sender",
            daemon=True,
        ).start()

    def _cancel_send(self) -> None:
        self.send_cancel.set()
        sock = self.sender_socket.get("socket")
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except OSError:
                pass
        self.send_status_var.set("正在取消…")

    def _choose_save_dir(self) -> None:
        raw = self.filedialog.askdirectory(title="选择接收文件保存位置", initialdir=self.save_dir_var.get())
        if raw:
            self.save_dir_var.set(raw)

    def _start_receiver(self) -> None:
        if self.receiver:
            return
        try:
            port = int(self.recv_port_var.get())
            if not 1 <= port <= 65535:
                raise ValueError
            save_dir = Path(self.save_dir_var.get()).expanduser()
            save_dir.mkdir(parents=True, exist_ok=True)
        except (ValueError, OSError) as exc:
            self.messagebox.showerror("无法启动", f"端口或保存位置不可用：{exc}")
            return
        try:
            receiver = ReceiverServer(save_dir, port, self.recv_code_var.get(), self._event)
            receiver.start()
            self.receiver = receiver
        except OSError as exc:
            self.messagebox.showerror("无法启动接收", f"端口 {port} 可能已被占用。\n\n{exc}")

    def _stop_receiver(self) -> None:
        if self.receiver:
            receiver, self.receiver = self.receiver, None
            receiver.stop()

    def _append_recv_log(self, text: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        self.recv_log.configure(state="normal")
        self.recv_log.insert("end", f"[{timestamp}] {text}\n")
        self.recv_log.see("end")
        self.recv_log.configure(state="disabled")

    def _finish_sending(self, *, remove_sent: bool = False) -> None:
        if remove_sent:
            sent = set(self.active_send_selections)
            self.selections = [selection for selection in self.selections if selection not in sent]
            self._refresh_file_tree()
        self.active_send_selections.clear()
        self.sending = False
        self.send_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
        self._set_selection_controls_enabled(True)

    def _poll_events(self) -> None:
        try:
            while True:
                name, data = self.events.get_nowait()
                if name == "discovery":
                    items = data["items"]
                    values = [f"{item['ip']}  —  {item['name']}" for item in items]
                    self.host_combo["values"] = values
                    if items:
                        self.host_var.set(items[0]["ip"])
                        self.send_port_var.set(str(items[0]["port"]))
                        self.send_status_var.set(f"发现 {len(items)} 个接收端，已选择 {items[0]['name']}")
                    else:
                        self.send_status_var.set("未发现接收端，可手动填写 IP 地址")
                elif name == "send_started":
                    self.send_status_var.set(f"已连接，开始发送 {data['files']} 个文件")
                elif name == "send_progress":
                    percent = data["done"] / data["total"] * 100 if data["total"] else 100
                    self.send_progress["value"] = percent
                    self.send_status_var.set(
                        f"正在发送 {data['file']}  ·  {percent:.1f}%  ·  {format_size(data['speed'])}/s"
                    )
                elif name == "send_complete":
                    self.send_progress["value"] = 100
                    self.send_status_var.set(f"发送完成：{data['files']} 个文件，共 {format_size(data['total'])}")
                    self._finish_sending(remove_sent=True)
                    self.messagebox.showinfo("发送完成", "文件已加密传输并通过完整性校验，已从发送列表移除。")
                elif name == "send_cancelled":
                    self.send_status_var.set("传输已取消")
                    self._finish_sending()
                elif name == "send_error":
                    self.send_status_var.set(f"发送失败：{data['message']}")
                    self._finish_sending()
                    self.messagebox.showerror("发送失败", data["message"])
                elif name == "server_started":
                    self.start_recv_button.configure(state="disabled")
                    self.stop_recv_button.configure(state="normal")
                    self.recv_port_entry.configure(state="disabled")
                    self.refresh_code_button.configure(state="disabled")
                    addresses = "  /  ".join(f"{ip}:{data['port']}" for ip in data["ips"])
                    self.ip_var.set(addresses)
                    self.recv_status_var.set("正在等待发送端连接…")
                    self._append_recv_log(f"接收已启动，地址：{addresses}，连接码：{self.recv_code_var.get()}")
                elif name == "server_stopped":
                    self.start_recv_button.configure(state="normal")
                    self.stop_recv_button.configure(state="disabled")
                    self.recv_port_entry.configure(state="normal")
                    self.refresh_code_button.configure(state="normal")
                    self.ip_var.set("启动接收后显示")
                    self.recv_status_var.set("已停止接收")
                    self._append_recv_log("接收已停止")
                elif name == "recv_started":
                    self.recv_progress["value"] = 0
                    self.recv_status_var.set(f"来自 {data['peer']}：准备接收 {data['files']} 个文件")
                    self._append_recv_log(f"{data['peer']} 已通过连接码验证，开始接收 {format_size(data['total'])}")
                elif name == "recv_progress":
                    percent = data["done"] / data["total"] * 100 if data["total"] else 100
                    self.recv_progress["value"] = percent
                    self.recv_status_var.set(
                        f"正在接收 {data['file']}  ·  {percent:.1f}%  ·  {format_size(data['speed'])}/s"
                    )
                elif name == "recv_complete":
                    self.recv_progress["value"] = 100
                    self.recv_status_var.set(f"接收完成：{data['files']} 个文件，共 {format_size(data['total'])}")
                    self._append_recv_log(f"接收完成，文件已保存到 {data['folder']}")
                elif name == "recv_error":
                    self.recv_status_var.set(f"接收失败：{data['message']}")
                    self._append_recv_log(f"来自 {data['peer']} 的连接失败：{data['message']}")
        except queue.Empty:
            pass
        self.root.after(80, self._poll_events)

    def _on_close(self) -> None:
        if self.receiver:
            self.receiver.stop()
            self.receiver = None
        self._cancel_send() if self.sending else None
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def run_self_test() -> int:
    events: list[tuple[str, dict]] = []

    def callback(name: str, data: dict) -> None:
        events.append((name, data))

    with tempfile.TemporaryDirectory(prefix="flash-share-test-") as raw:
        root = Path(raw)
        source = root / "source"
        target = root / "target"
        source.mkdir()
        (source / "hello.txt").write_text("Flash Share 自检\n" * 1000, encoding="utf-8")
        nested = source / "资料"
        nested.mkdir()
        payload = secrets.token_bytes(2 * 1024 * 1024 + 137)
        (nested / "payload.bin").write_bytes(payload)

        code = generate_code()
        server = ReceiverServer(target, 0, code, callback)
        server.start()
        entries = build_manifest([SourceSelection(source, "自检文件")])
        cancel = threading.Event()
        send_manifest("127.0.0.1", server.port, code, entries, callback, cancel)
        server.stop()

        received_text = target / "自检文件" / "hello.txt"
        received_payload = target / "自检文件" / "资料" / "payload.bin"
        ok = (
            received_text.read_text(encoding="utf-8") == "Flash Share 自检\n" * 1000
            and received_payload.read_bytes() == payload
            and any(name == "send_complete" for name, _ in events)
            and any(name == "recv_complete" for name, _ in events)
        )
        return 0 if ok else 1


def main() -> int:
    if "--self-test" in sys.argv:
        return run_self_test()
    enable_windows_dpi_awareness()
    QuickDropApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
