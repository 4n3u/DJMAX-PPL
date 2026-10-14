"""Fetch playPatternList from DJMAX RESPECT V and save the played records as JSON."""

from __future__ import annotations

import argparse
import base64
import csv
import ctypes
import hashlib
import hmac
import io
import json
import logging
import os
import re
import struct
import sys
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------------------------------------------------------------------
# Constants & Configuration
# ---------------------------------------------------------------------------
DATA_FILE = "data.unity3d"
METADATA_REL_PATH = Path("il2cpp_data/Metadata/global-metadata.dat")
STEAM_API_REL_PATH = Path("Plugins/x86_64/steam_api64.dll")
STEAM_APPID = "960170"
TABLE_NAME = "song_text_table"

ENDPOINTS = {
    "health": "login/checkHealth",
    "login": "login/steam",
    "session": "play/addSessionStart",
    "patterns": "play/playPatternList",
}

HEADERS = {
    "token": "x-auth-token",
    "app": "appVersion",
    "data": "dataVer",
    "platform": "platformType",
    "unity": "x-unity-version",
}

PLATFORM_PC = "0"
DATA_VERSION_LIMIT = 64
APP_VERSION_TRIES = 12
AUTH_ATTEMPT_LIMIT = 48

MODE_NAMES = {4: "4B", 5: "5B", 6: "6B", 8: "8B"}
DIFF_NAMES = {1: "NM", 2: "HD", 3: "MX", 4: "SC"}

STEAM_USER_INTERFACES = (
    "SteamAPI_SteamUser_v023",
    "SteamAPI_SteamUser_v022",
    "SteamAPI_SteamUser_v021",
    "SteamAPI_SteamUser_v020",
    "SteamAPI_SteamUser_v019",
)
STEAM_FRIENDS_INTERFACES = (
    "SteamAPI_SteamFriends_v018",
    "SteamAPI_SteamFriends_v017",
    "SteamAPI_SteamFriends_v016",
    "SteamAPI_SteamFriends_v015",
)

log = logging.getLogger("djmax_fetcher")


# ---------------------------------------------------------------------------
# Exceptions & Data Models
# ---------------------------------------------------------------------------
class FetcherError(Exception):
    """Base exception for expected operational failures."""
    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class Credentials:
    token: str
    aes_key: bytes
    mac_key: bytes


@dataclass(frozen=True)
class AuthSession:
    app_version: str
    data_version: int
    payload_size: int
    credentials: Credentials


@dataclass
class SongEntry:
    song_id: int
    artist: str = ""
    composer: str = ""
    names: dict[str, str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.names is None:
            self.names = {}

    def title(self, locale: str) -> str:
        return self.names.get(locale) or self.names.get("en_US") or ""


# ---------------------------------------------------------------------------
# Client & File Discovery
# ---------------------------------------------------------------------------
def find_data_dir(input_path: Path) -> Path | None:
    base = input_path.parent if input_path.is_file() else input_path
    if (base / DATA_FILE).is_file():
        return base
    try:
        for entry in base.iterdir():
            if entry.is_dir() and (entry / DATA_FILE).is_file():
                return entry
    except OSError:
        pass
    return None


def resolve_client_dir(input_path: Path | None) -> Path:
    if input_path is not None:
        if not input_path.exists():
            raise FetcherError(f"path not found: {input_path}", exit_code=2)
        return input_path

    steam_roots = [
        Path(r"C:\Program Files (x86)\Steam"),
        Path(r"C:\Program Files\Steam"),
        Path.home() / "AppData/Local/Steam",
    ]
    libraries: list[Path] = []
    for root in steam_roots:
        if not root.exists():
            continue
        libraries.append(root)
        vdf = root / "steamapps/libraryfolders.vdf"
        if vdf.exists():
            try:
                text = vdf.read_text(encoding="utf-8", errors="replace")
                libraries.extend(
                    Path(m.group(1).replace("\\\\", "\\"))
                    for m in re.finditer(r'"path"\s*"([^"]+)"', text)
                )
            except OSError:
                continue

    for lib in libraries:
        common = lib / "steamapps/common"
        if not common.is_dir():
            continue
        for game_dir in common.iterdir():
            if not game_dir.is_dir():
                continue
            data_dir = find_data_dir(game_dir)
            if data_dir and (data_dir / METADATA_REL_PATH).exists():
                log.info("[auto] client folder: %s", game_dir)
                return game_dir

    raise FetcherError("client folder not found; pass it as an argument", exit_code=2)


# ---------------------------------------------------------------------------
# Unity Metadata & Asset Parsing
# ---------------------------------------------------------------------------
def decode_literals(metadata: bytes) -> str:
    anchor = b"https://"
    patterns = {
        idx: bytes(b ^ (((idx + off) & 0xFF) ^ 0xAA) for off, b in enumerate(anchor))
        for idx in range(256)
    }
    phase = 0
    for idx, pat in patterns.items():
        pos = metadata.find(pat)
        if pos >= 0:
            phase = (idx - pos) % 256
            break

    out = bytearray(len(metadata))
    for offset in range(256):
        key = ((offset + phase) & 0xFF) ^ 0xAA
        table = bytes(b ^ key for b in range(256))
        out[offset::256] = metadata[offset::256].translate(table)
    return out.decode("utf-8", "replace")


def parse_unity_engine_version(data_file: Path) -> str:
    try:
        with data_file.open("rb") as f:
            head = f.read(64)
    except OSError:
        return ""
    if not head.startswith(b"UnityFS\x00"):
        return ""
    pos = 12
    strings: list[str] = []
    for _ in range(2):
        end = head.find(b"\x00", pos)
        if end < 0:
            return ""
        strings.append(head[pos:end].decode("ascii", "replace"))
        pos = end + 1
    return strings[1]


def build_user_agent(client_dir: Path, unity_ver: str) -> str:
    player = client_dir / "UnityPlayer.dll"
    if player.exists():
        try:
            blob = player.read_bytes()
            pos = blob.find(b"libcurl/")
            if pos >= 0:
                end = pos
                while end < len(blob) and 33 <= blob[end] < 127:
                    end += 1
                curl = blob[pos:end].decode("ascii", "replace")
                return f"UnityPlayer/{unity_ver} (UnityWebRequest/1.0, {curl})"
        except OSError:
            pass
    return f"UnityPlayer/{unity_ver}"


def extract_version_candidates(data_file: Path, unity_env=None, limit: int = 64) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    pattern = re.compile(rb"\d{1,3}(?:\.\d{1,5}){2,3}")
    chunk_size = 8 * 1024 * 1024
    overlap = 32

    def _collect(buffer: bytes, check_boundary: bool = False) -> None:
        for match in pattern.finditer(buffer):
            end = match.end()
            if check_boundary and end < len(buffer) and (
                buffer[end : end + 1].isdigit() or buffer[end : end + 1] == b"."
            ):
                continue
            cand = match.group(0).decode("ascii")
            parts = cand.split(".")
            if any(len(p) > 1 and p.startswith("0") for p in parts):
                continue
            if cand not in seen:
                seen.add(cand)
                found.append(cand)
                if len(found) >= limit:
                    return

    with data_file.open("rb") as f:
        tail = b""
        while len(found) < limit:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            buf = tail + chunk
            _collect(buf, check_boundary=True)
            tail = buf[-overlap:]

    if not found and unity_env is not None:
        log.info("[versions] no candidate in raw bundle; scanning decompressed assets")
        for obj in unity_env.objects:
            try:
                raw = obj.get_raw_data()
            except Exception:
                continue
            if raw and len(raw) <= chunk_size:
                _collect(raw)
                if len(found) >= limit:
                    break

    return found[:limit]


def load_text_asset(unity_env, name: str) -> bytes:
    for obj in unity_env.objects:
        if obj.type.name != "TextAsset":
            continue
        try:
            data = obj.read()
        except Exception:
            continue
        if getattr(data, "m_Name", "") == name:
            raw = getattr(data, "m_Script", None) or getattr(data, "m_Text", b"")
            return raw.encode("utf-8", "replace") if isinstance(raw, str) else bytes(raw)
    raise FetcherError(f"'{name}' was not found in {DATA_FILE}")


def parse_song_table(raw_csv: bytes, locale: str) -> tuple[list[dict], dict[int, SongEntry]]:
    text = raw_csv.decode("utf-8-sig", "replace")
    reader = csv.DictReader(io.StringIO(text))
    songs: dict[int, SongEntry] = {}

    for row in reader:
        clean = {(k or "").strip(): (v or "").strip() for k, v in row.items()}
        raw_id = clean.get("id", "")
        if not raw_id.isdigit():
            continue
        song_id = int(raw_id)
        entry = songs.setdefault(song_id, SongEntry(song_id=song_id))
        entry.names[clean.get("locale", "?")] = clean.get("songname", "")
        if not entry.artist:
            entry.artist = clean.get("artist", "")
        if not entry.composer:
            entry.composer = clean.get("composer", "")

    listing = [
        {
            "songId": sid,
            "songName": songs[sid].title(locale),
            "artist": songs[sid].artist,
            "composer": songs[sid].composer,
        }
        for sid in sorted(songs)
    ]
    return listing, songs


# ---------------------------------------------------------------------------
# Steamworks FFI Context
# ---------------------------------------------------------------------------
@contextmanager
def steam_session(dll_path: Path) -> Iterator[ tuple[str, str] ]:
    """Initialize SteamAPI, yield (ticket_hex, nickname), and guarantee shutdown."""
    if not dll_path.exists():
        raise FetcherError(f"steam_api64.dll not found: {dll_path}")
    try:
        dll = ctypes.CDLL(str(dll_path))
    except OSError as exc:
        raise FetcherError(f"could not load {dll_path.name} ({exc}); use 64-bit Python") from exc

    os.environ["SteamAppId"] = STEAM_APPID
    os.environ["SteamGameId"] = STEAM_APPID

    init_fn = getattr(dll, "SteamAPI_InitSafe", None) or getattr(dll, "SteamAPI_Init", None)
    if init_fn is None:
        raise FetcherError("steam_api64.dll has no SteamAPI_InitSafe/SteamAPI_Init export")
    init_fn.restype = ctypes.c_bool
    if not init_fn():
        raise FetcherError("SteamAPI init failed; make sure the Steam client is running")

    try:
        user_fn = next((getattr(dll, name, None) for name in STEAM_USER_INTERFACES if hasattr(dll, name)), None)
        if user_fn is None:
            raise FetcherError("steam_api64.dll has no SteamUser interface export")
        user_fn.restype = ctypes.c_void_p
        user_ptr = user_fn()
        if not user_ptr:
            raise FetcherError("could not get the SteamUser interface")

        get_ticket = getattr(dll, "SteamAPI_ISteamUser_GetAuthSessionTicket", None)
        if get_ticket is None:
            raise FetcherError("steam_api64.dll has no GetAuthSessionTicket export")
        get_ticket.restype = ctypes.c_uint32
        get_ticket.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_uint32)]

        buf = ctypes.create_string_buffer(4096)
        length = ctypes.c_uint32(0)
        handle = get_ticket(user_ptr, buf, 4096, ctypes.byref(length))
        if not handle or not length.value:
            raise FetcherError("Steam did not return an auth ticket")

        nickname = ""
        friends_fn = next((getattr(dll, name, None) for name in STEAM_FRIENDS_INTERFACES if hasattr(dll, name)), None)
        persona_fn = getattr(dll, "SteamAPI_ISteamFriends_GetPersonaName", None)
        if friends_fn and persona_fn:
            friends_fn.restype = ctypes.c_void_p
            friends_ptr = friends_fn()
            if friends_ptr:
                persona_fn.restype = ctypes.c_char_p
                persona_fn.argtypes = [ctypes.c_void_p]
                nickname = (persona_fn(friends_ptr) or b"").decode("utf-8", "replace")

        yield buf.raw[: length.value].hex().upper(), nickname
    finally:
        shutdown_fn = getattr(dll, "SteamAPI_Shutdown", None)
        if shutdown_fn:
            try:
                shutdown_fn()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Cryptography & Network Client
# ---------------------------------------------------------------------------
def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    aligned_len = len(data) - (len(data) % 16)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(data[:aligned_len]) + decryptor.finalize()


def verify_mac(body: bytes, mac_key: bytes) -> bool:
    if len(body) < 48 or len(mac_key) < 16:
        return False
    expected = hmac.new(mac_key, body[32:], hashlib.sha256).digest()
    return hmac.compare_digest(expected, body[:32])


def extract_credentials(login_plain: bytes) -> Credentials | None:
    matches = [m.group(0) for m in re.finditer(rb"[A-Za-z0-9+/]{100,512}={0,2}", login_plain)]
    if not matches:
        return None
    b64_token = matches[0]
    frame = base64.b64decode(b64_token + b"=" * (-len(b64_token) % 4))
    if len(frame) < 64:
        return None

    mac_tag, cipher = frame[:32], frame[32:]
    windows = [
        login_plain[i : i + 32]
        for i in range(len(login_plain) - 32)
        if all(33 <= b < 127 for b in login_plain[i : i + 32])
    ]

    mac_key = next(
        (w for w in windows if hmac.compare_digest(hmac.new(w, cipher, hashlib.sha256).digest(), mac_tag)),
        None,
    )
    if mac_key is None:
        return None

    for candidate_key in windows:
        if candidate_key == mac_key:
            continue
        plain = aes_cbc_decrypt(candidate_key, cipher[:16], cipher)
        runs = [m.group(0) for m in re.finditer(rb"[A-Za-z0-9+/=]{40,}", plain)]
        if runs:
            token = max(runs, key=len).decode("ascii")
            return Credentials(token=token, aes_key=candidate_key, mac_key=mac_key)
    return None


class DjmaxApiClient:
    def __init__(self, base_url: str, user_agent: str, unity_ver: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.user_agent = user_agent
        self.unity_ver = unity_ver

    def post(self, endpoint: str, extra_headers: dict[str, str], timeout: int = 60) -> tuple[int, bytes]:
        url = f"{self.base_url}/{endpoint}"
        headers = {
            "user-agent": self.user_agent,
            "accept": "*/*",
            HEADERS["unity"]: self.unity_ver,
            **extra_headers,
        }
        req = urllib.request.Request(url, data=b"", headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    @classmethod
    def discover_host(cls, literals: str, user_agent: str, unity_ver: str) -> DjmaxApiClient:
        hosts = list(dict.fromkeys(re.findall(r"https?://[A-Za-z0-9.\-]+(?::\d+)?", literals)))
        ordered = [h for h in hosts if h.startswith("https://")] + [
            h for h in hosts if not h.startswith("https://")
        ]
        for host in ordered:
            client = cls(host, user_agent, unity_ver)
            try:
                status, body = client.post(ENDPOINTS["login"], {}, timeout=10)
                text = body.decode("utf-8", "replace")
                if status == 400 and ("Bad Request" in text or '"path"' in text):
                    return client
            except Exception:
                continue
        raise FetcherError(f"no reachable api host among {hosts}")

    def authenticate(self, ticket: str, nickname: str, version_candidates: list[str]) -> AuthSession:
        raw_ticket = ticket.strip().upper().encode("ascii", "ignore")
        if len(raw_ticket) < 144:
            raise FetcherError("Steam ticket is too short")
        login_key = hashlib.sha256(raw_ticket[128:144] + raw_ticket[32:48]).digest()
        encoded_nick = base64.b64encode(nickname.encode("utf-8")).decode("ascii")

        attempts = 0
        for app_ver in version_candidates[:APP_VERSION_TRIES]:
            for data_ver in range(DATA_VERSION_LIMIT + 1):
                attempts += 1
                if attempts > AUTH_ATTEMPT_LIMIT:
                    break
                status, body = self.post(
                    ENDPOINTS["login"],
                    {
                        "ticket": ticket,
                        "nickname": encoded_nick,
                        HEADERS["app"]: app_ver,
                        HEADERS["data"]: str(data_ver),
                        "content-type": "application/x-www-form-urlencoded",
                    },
                )
                if status != 200 or len(body) < 64:
                    continue

                plain = aes_cbc_decrypt(login_key, body[:16], body[32:])
                creds = extract_credentials(plain)
                if not creds:
                    continue

                if not self.start_session(app_ver, creds.token):
                    continue

                status, patterns = self.post(
                    ENDPOINTS["patterns"],
                    {
                        HEADERS["token"]: creds.token,
                        HEADERS["app"]: app_ver,
                        HEADERS["platform"]: PLATFORM_PC,
                        "content-type": "binary/octet-stream",
                    },
                )
                if status != 200 or not patterns:
                    log.info("[login] appversion=%s dataver=%d rejected by playPatternList (%d)",
                             app_ver, data_ver, status)
                    continue

                log.info("[login] appversion=%s dataver=%d payload=%dB", app_ver, data_ver, len(body))
                return AuthSession(app_ver, data_ver, len(body), creds)
            if attempts > AUTH_ATTEMPT_LIMIT:
                break

        raise FetcherError("no appversion/dataver combination was accepted")

    def start_session(self, app_version: str, token: str) -> bool:
        status, _ = self.post(
            ENDPOINTS["session"],
            {
                HEADERS["token"]: token,
                HEADERS["app"]: app_version,
                HEADERS["platform"]: PLATFORM_PC,
                "content-type": "application/x-www-form-urlencoded",
            },
        )
        return status == 200


# ---------------------------------------------------------------------------
# FlatBuffers Binary Pattern Parser
# ---------------------------------------------------------------------------
def parse_flatbuffer_patterns(payload: bytes) -> list[tuple[int, ...]]:
    if len(payload) < 8:
        return []
    root_rel = struct.unpack_from("<I", payload, 0)[0]
    table_pos = root_rel
    if root_rel < 4 or table_pos + 4 > len(payload):
        return []

    vtable_offset = struct.unpack_from("<i", payload, table_pos)[0]
    vtable = table_pos - vtable_offset
    if vtable < 0 or vtable + 4 > len(payload):
        return []

    vlen, tsize = struct.unpack_from("<HH", payload, vtable)
    if vlen < 4 or vlen % 2 != 0 or vlen > 4 + 2 * 128 or tsize < 4 or table_pos + tsize > len(payload):
        return []

    num_fields = (vlen - 4) // 2
    offsets = struct.unpack_from(f"<{num_fields}H", payload, vtable + 4)
    if any(off >= tsize for off in offsets if off) or len(offsets) < 2 or not offsets[1]:
        return []

    field_pos = table_pos + offsets[1]
    target = field_pos + struct.unpack_from("<I", payload, field_pos)[0]
    if target + 4 > len(payload):
        return []

    count = struct.unpack_from("<I", payload, target)[0]
    if not count:
        return []

    rest = len(payload) - (target + 4)
    best_width = 0
    best_slack: int | None = None

    for width in range(8, 129, 4):
        total = count * width
        if total <= rest:
            slack = rest - total
            if slack <= 65536 and (best_slack is None or slack < best_slack):
                best_slack = slack
                best_width = width

    if not best_width:
        return []

    cols = best_width // 4
    row_fmt = f"<{cols}I"
    base_offset = target + 4
    return [
        struct.unpack_from(row_fmt, payload, base_offset + i * best_width)
        for i in range(count)
    ]


def build_records(rows: list[tuple[int, ...]], songs: dict[int, SongEntry], locale: str) -> list[dict]:
    records = []
    for row in rows:
        if len(row) < 8:
            continue
        uid, score, packed, flag = row[0], row[1], row[2], row[3]
        dj_power = struct.unpack("<f", struct.pack("<I", row[4]))[0]
        song_id, suffix = divmod(uid, 100)
        mode_key, diff_key = divmod(suffix, 10)
        song = songs.get(song_id)

        records.append({
            "patternUid": uid,
            "songId": song_id,
            "songName": (song.title(locale) if song else "") or f"#{song_id}",
            "composer": song.composer if song else "",
            "mode": MODE_NAMES.get(mode_key, f"?{mode_key}"),
            "difficulty": DIFF_NAMES.get(diff_key, f"?{diff_key}"),
            "score": score,
            "scoreRate": round(score / 10000, 2),
            "allCombo": flag,
            "combo": packed >> 16,
            "djPower": round(dj_power, 4),
            "plays": row[6],
        })
    return records


# ---------------------------------------------------------------------------
# Main Orchestration
# ---------------------------------------------------------------------------
def run_pipeline(client_dir: Path, out_dir: Path, locale: str) -> None:
    try:
        import UnityPy
    except ImportError as exc:
        raise FetcherError("UnityPy is required: py -m pip install -r requirements.txt", exit_code=2) from exc

    data_dir = find_data_dir(client_dir)
    if data_dir is None:
        raise FetcherError(f"{DATA_FILE} not found under {client_dir}", exit_code=2)

    metadata_path = data_dir / METADATA_REL_PATH
    data_file = data_dir / DATA_FILE
    steam_api_path = data_dir / STEAM_API_REL_PATH

    for path in (metadata_path, data_file, steam_api_path):
        if not path.exists():
            raise FetcherError(f"missing client file: {path}", exit_code=2)

    unity_ver = parse_unity_engine_version(data_file)
    log.info("[client] %s  (unity %s)", data_dir, unity_ver)

    literals = decode_literals(metadata_path.read_bytes())
    required_strings = (*ENDPOINTS.values(), TABLE_NAME, *list(HEADERS.values())[:4])
    for wanted in required_strings:
        if wanted not in literals:
            raise FetcherError(f"'{wanted}' was not found in the client strings")

    agent = build_user_agent(client_dir, unity_ver)
    api = DjmaxApiClient.discover_host(literals, agent, unity_ver)
    log.info("[api] %s", api.base_url)

    log.info("[loading] %s  (%.0fMB)", data_file, data_file.stat().st_size / 1e6)
    unity_env = UnityPy.load(str(data_file))

    candidates = extract_version_candidates(data_file, unity_env=unity_env)
    if not candidates:
        raise FetcherError("no version candidates were found in the client")
    log.info("[versions] %d candidates: %s", len(candidates), ", ".join(candidates[:6]))

    raw_table = load_text_asset(unity_env, TABLE_NAME)
    song_list, songs = parse_song_table(raw_table, locale)
    log.info("[songs] %s songs for locale %s", f"{len(song_list):,}", locale)

    with steam_session(steam_api_path) as (ticket, nickname):
        log.info("[steam] ticket %d bytes, nickname %r", len(ticket) // 2, nickname)
        session = api.authenticate(ticket, nickname, candidates)
        creds = session.credentials
        log.info("[token] derived (%d chars)", len(creds.token))

        auth_headers = {
            HEADERS["token"]: creds.token,
            HEADERS["app"]: session.app_version,
            HEADERS["platform"]: PLATFORM_PC,
        }

        status, body = api.post(
            ENDPOINTS["session"],
            {**auth_headers, "content-type": "application/x-www-form-urlencoded"},
        )
        log.info("[api] %s status=%d %dB", ENDPOINTS["session"], status, len(body))
        if status != 200:
            raise FetcherError(f"addSessionStart failed: {body[:200]!r}")

        status, body = api.post(
            ENDPOINTS["patterns"],
            {**auth_headers, "content-type": "binary/octet-stream"},
        )
        log.info("[api] %s status=%d %dB", ENDPOINTS["patterns"], status, len(body))
        if status != 200:
            raise FetcherError(f"playPatternList failed: {body[:200]!r}")

    if not verify_mac(body, creds.mac_key):
        raise FetcherError("the playPatternList response failed the MAC check")

    plain = aes_cbc_decrypt(creds.aes_key, body[:16], body[32:])
    if len(plain) < 24:
        raise FetcherError("could not decrypt the playPatternList response")

    rows = parse_flatbuffer_patterns(plain[16:])
    records = build_records(rows, songs, locale)
    if not records:
        raise FetcherError("no pattern records were parsed")

    payload = {"patterns": [record for record in records if record["plays"] > 0]}
    played = payload["patterns"]

    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"play_pattern_list_{time.strftime('%Y%m%d-%H%M%S')}.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    scored_count = sum(1 for r in played if r["score"] > 0)
    total_plays = sum(r["plays"] for r in played)
    all_combo_count = sum(1 for r in played if r["allCombo"])

    log.info("\n[saved] %s  (%s records)", json_path, f"{len(played):,}")
    log.info(
        "\n[summary] patterns=%s scored=%s allCombo=%s totalPlays=%s locale=%s",
        f"{len(played):,}",
        f"{scored_count:,}",
        f"{all_combo_count:,}",
        f"{total_plays:,}",
        locale,
    )


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)

    parser = argparse.ArgumentParser(
        prog="fetch_play_pattern_list",
        description="Fetch playPatternList and save the played records as JSON.",
        epilog='example: py main.py "D:\\Games\\DJMAX RESPECT V"',
    )
    parser.add_argument("path", nargs="?", help="game folder, _Data folder, or data.unity3d")
    parser.add_argument("-o", "--out", default=".", help="output folder (default: the current folder)")
    parser.add_argument("--locale", default="ko_KR", help="song name locale (default: ko_KR)")
    args = parser.parse_args(argv)

    try:
        client_dir = resolve_client_dir(Path(args.path) if args.path else None)
        run_pipeline(client_dir, Path(args.out), args.locale)
        return 0
    except FetcherError as exc:
        log.error("[error] %s", exc)
        return exc.exit_code
    except Exception as exc:
        log.error("[error] unexpected failure: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())