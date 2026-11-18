"""Decoder for the Kiwik proprietary video container.

The app's web worker fetches ``stream.media.uri`` (a signed HTTPS URL) and
gets a concatenation of JPEG-structured blocks. Each block:

- ``FF D8`` SOI, then ``FF E2`` APP2 with a binary Kiwik header
  (version, length, index, width, height, type, rate, rotate, crypt,
  pts, utc, videoSize, audioSize, audioFmt, aecm…),
- then ``FF DA`` SOS followed by the raw payload:
  ``videoSize`` video bytes + ``audioSize`` audio + ``aecmSize`` aecm.

For MJPEG-type frames the whole block is a complete viewable JPEG (the
Kiwik header just rides along in APP2). For type 32/48 the payload is a
raw H.264 / HEVC elementary-stream chunk.

``crypt > 0`` means the payloads are sparsely encrypted: only every
16th 16-byte block is AES-CTR'd (stride 256 bytes) — a cheap "scramble
the key bits" scheme. Key = hex-decoded ``media.secret``; the counter
block is ``BE32[pts, utc, length, index<<16 | block_idx]``.
"""
from __future__ import annotations

import asyncio
import logging
import struct
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .const import CAMERA_CANVAS_MAX_H, CAMERA_CANVAS_MAX_W

_LOGGER = logging.getLogger(__name__)

BLOCK_MAGIC = b"\xff\xd8\xff\xe2"  # SOI + APP2, the u32 the app scans for

VIDEO_H264 = 32
VIDEO_HEVC = 48


def _u16(buf: bytes | bytearray, i: int) -> int:
    return buf[i] << 8 | buf[i + 1]


def _u32(buf: bytes | bytearray, i: int) -> int:
    return _u16(buf, i) << 16 | _u16(buf, i + 2)


def iter_blocks(buf: bytes):
    """Yield complete blocks from a downloaded clip (app's ``q()``)."""
    i, n = 0, len(buf)
    while i + 12 < n:
        if buf[i : i + 4] == BLOCK_MAGIC:
            size = _u32(buf, i + 8)
            if i + size > n:
                break
            yield buf[i : i + size]
            i += size
        else:
            i += 4


class BlockStream:
    """Incremental splitter for a live chunked HTTP response."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        self._buf += data
        out: list[bytes] = []
        while True:
            i = self._buf.find(BLOCK_MAGIC)
            if i < 0:
                # Keep a possible partial magic at the tail.
                keep = 3
                while keep and self._buf[-keep:] not in (
                    BLOCK_MAGIC[:keep],
                ):
                    keep -= 1
                del self._buf[: len(self._buf) - keep]
                break
            if i:
                del self._buf[:i]
            if len(self._buf) < 12:
                break
            size = _u32(self._buf, 8)
            if size < 12 or size > 8 * 1024 * 1024:
                # Bogus length — skip the magic and resync.
                del self._buf[:4]
                continue
            if len(self._buf) < size:
                break
            out.append(bytes(self._buf[:size]))
            del self._buf[:size]
        return out


def _o1(secret: str) -> bytes:
    """App's ``o1()`` hex decoder — per-byte parseInt(x,16), NaN->0,
    odd tail char parsed alone. Forgiving like the bundle, not strict."""
    out = bytearray(len(secret) // 2)
    for r in range(len(out)):
        try:
            out[r] = int(secret[2 * r : 2 * r + 2], 16)
        except ValueError:
            out[r] = 0
    return bytes(out)


class _Cryptor:
    """Sparse AES-CTR used when frame.crypt > 0 (module 22543 ``log()``)."""

    __slots__ = ("_enc",)

    def __init__(self, secret: str | bytes | None) -> None:
        if isinstance(secret, str):
            key = _o1(secret)
        else:
            key = bytes(secret or b"")
        if len(key) not in (16, 24, 32):
            raise ValueError("invalid media secret length")
        self._enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()

    def apply(
        self,
        buf: bytearray,
        offset: int,
        size: int,
        salt: list[int],
        stride: int = 16,
    ) -> None:
        """XOR keystream on every ``stride``-th 16B block (in place).

        The app calls it with stride 16 for video (sparse scrambling)
        and stride 1 for audio/aecm payloads.
        """
        blocks = (size + 15) // 16
        for blk in range(blocks + 1):
            if blk % stride:
                continue
            salt[3] = (salt[3] & 0xFFFF0000) | (blk & 0xFFFF)
            ks = self._enc.update(
                struct.pack(">4I", *[w & 0xFFFFFFFF for w in salt])
            )
            for j in range(16):
                if 16 * blk + j < size:
                    buf[offset + 16 * blk + j] ^= ks[j]


@dataclass
class KiwikFrame:
    """Decoded frame metadata + decrypted payloads."""

    type: int = 0
    index: int = 0
    width: int = 0
    height: int = 0
    rate: int = 0
    rotate: int = 0
    crypt: int = 0
    pts: int = 0
    utc: int = 0
    length: int = 0
    video: bytes | None = None
    audio: bytes | None = None
    keyframe: bool = False
    raw: bytes = b""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_jpeg(self) -> bool:
        """MJPEG-type frame: the whole block is a displayable JPEG."""
        return self.type not in (VIDEO_H264, VIDEO_HEVC)


def decode_frame(
    block: bytes | bytearray, cryptor: _Cryptor | None
) -> KiwikFrame | None:
    """Parse one block. ``block`` is copied before in-place decrypt."""
    a = bytearray(block)
    if len(a) < 12 or _u16(a, 0) != 0xFFD8:
        return None
    i = 2
    fr = KiwikFrame()
    video_off = video_size = audio_off = audio_size = aecm_off = 0
    aecm_size = 0
    while i + 4 <= len(a):
        marker = _u16(a, i)
        i += 2
        if marker == 0xFFD9:
            break
        n = _u16(a, i) - 2
        payload_at = i + 2
        if marker == 0xFF00:  # byte stuffing
            i -= 2
            continue
        if marker == 0xFFE2:
            j = payload_at
            fr.extra["version"] = _u16(a, j)
            j += 2
            fr.length = _u32(a, j)
            j += 4
            fr.index = _u16(a, j)
            fr.height = _u16(a, j + 2)
            fr.width = _u16(a, j + 4)
            j += 6
            fr.type, fr.rate, fr.rotate, fr.crypt = a[j : j + 4]
            j += 4
            fr.pts = _u32(a, j)
            fr.utc = _u32(a, j + 4)
            j += 8
            if n >= 36:
                video_size = _u32(a, j)
                audio_size = _u32(a, j + 4)
                fr.extra["audio_fmt"] = a[j + 8]
                j += 9
                if n >= 40:
                    fr.extra["aecm_mode"] = a[j]
                    fr.extra["aecm_pack"] = _u16(a, j + 1)
                    aecm_size = _u32(a, j + 3)
                    fr.extra["aecm_size"] = aecm_size
                    j += 7
            i = payload_at + n
            continue
        if marker == 0xFFE3:
            # APP3 on delta frames: MCU-update bitmask (see DeltaCompositor).
            fr.extra["app3"] = bytes(a[payload_at : payload_at + n])
            i = payload_at + n
            continue
        if marker == 0xFFDA:
            i = payload_at + n
            video_off = i
            if not video_size and i < len(a):
                video_size = len(a) - i
            salt = [fr.pts, fr.utc, fr.length, (fr.index << 16) & 0xFFFFFFFF]
            if fr.crypt and cryptor is not None:
                if fr.crypt == 2:
                    salt[2] &= 0xFFFFFF
                cryptor.apply(a, i, video_size, salt)
            i += video_size
            audio_off = i
            if audio_size:
                if fr.crypt and cryptor is not None:
                    if fr.crypt == 2:
                        salt[2] = (salt[2] & 0xFFFFFF) | (1 << 24)
                    cryptor.apply(a, i, audio_size, salt, stride=1)
                i += audio_size
            aecm_off = i
            if aecm_size:
                if fr.crypt and cryptor is not None:
                    if fr.crypt == 2:
                        salt[2] = (salt[2] & 0xFFFFFF) | (2 << 24)
                    cryptor.apply(a, i, aecm_size, salt, stride=1)
                i += aecm_size
            continue
        # DQT/DHT/SOF0 etc. (real JPEG segments in MJPEG blocks), APPn,
        # or unknown — skip by declared length, resync on junk.
        if marker >= 0xFFC0 or marker in (0xFF01,) or 0xFFD0 <= marker <= 0xFFD7:
            i = payload_at + n
        else:
            i -= 2
    if video_size:
        fr.video = bytes(a[video_off : video_off + video_size])
    if audio_size:
        fr.audio = bytes(a[audio_off : audio_off + audio_size])
    if fr.type in (VIDEO_H264, VIDEO_HEVC):
        v = fr.video or b""
        fr.keyframe = v[:4] == b"\x00\x00\x00\x01" and (
            (fr.type == VIDEO_H264 and (v[4] & 0x1F) in (5, 7, 8))
            or (
                fr.type == VIDEO_HEVC
                and ((v[4] >> 1) & 0x3F) in (32, 33, 34, 19, 20, 21)
            )
        )
    else:
        fr.keyframe = fr.type == 1
    fr.raw = bytes(a)  # block bytes with payloads already decrypted
    return fr


def _fit_canvas(img: Any, fit: str | tuple[int, int]) -> Any:
    """Scale/letterbox ``img`` onto a landscape canvas.

    ``fit="auto"``: portrait → letterboxed to ~16:9 at native height
    (capped CAMERA_CANVAS_MAX_*); landscape → scaled to fit the box.
    ``fit=(w, h)``: contain inside an exact w×h canvas.
    """
    from PIL import Image

    w, h = img.size
    if isinstance(fit, tuple):
        tw, th = fit
    elif h > w:
        th = min(h, CAMERA_CANVAS_MAX_H)
        tw = min(CAMERA_CANVAS_MAX_W, (th * 16 // 9) & ~1)
    else:
        s = min(
            CAMERA_CANVAS_MAX_W / w, CAMERA_CANVAS_MAX_H / h, 1.0
        )
        tw, th = max(2, int(w * s) & ~1), max(2, int(h * s) & ~1)
    if (w, h) == (tw, th):
        return img
    s = min(tw / w, th / h)
    nw, nh = max(1, int(w * s)), max(1, int(h * s))
    canvas = Image.new("RGB", (tw, th), (8, 8, 12))
    if (nw, nh) != (w, h):
        img = img.resize((nw, nh), Image.LANCZOS)
    canvas.paste(img, ((tw - nw) // 2, (th - nh) // 2))
    return canvas


def fit_jpeg(jpg: bytes, fit: str | tuple[int, int] | None = "auto") -> bytes:
    """Scale/letterbox an arbitrary JPEG (snapshots) like the live canvas."""
    import io

    from PIL import Image

    try:
        img = Image.open(io.BytesIO(jpg))
        img.load()
        img = img.convert("RGB")
    except Exception:
        return jpg
    if fit:
        img = _fit_canvas(img, fit)
    out = io.BytesIO()
    img.save(out, "JPEG", quality=90)
    return out.getvalue()


class DeltaCompositor:
    """Rebuild full frames from type-1 keyframes + type-2 MCU strips.

    A type-2 ("delta") frame's video payload is a JPEG strip of the
    changed MCUs laid side by side, and its APP3 segment carries a
    bitmask over the full-frame MCU grid (``ceil(W/mcu) x
    ceil(H/mcu)``, row-major, LSB-first per byte; a 0 bit marks a
    changed MCU). APP3 header: ``u16 version, u8 mcuW, u8 mcuH,
    u16 maskLen``, then the bitmask.
    """

    def __init__(self, fit: str | tuple[int, int] | None = "auto") -> None:
        self._img: Any = None
        self._gw = self._gh = 0
        # "auto": letterbox portrait frames onto a ~16:9 canvas so the
        # tall stream fits the camera dialog; (w, h): exact canvas;
        # None: pass frames through untouched.
        self._fit = fit
        self._canvas: tuple[int, int] | None = None

    def _encode(self, img: Any) -> bytes:
        import io

        if self._fit:
            if self._canvas is None:
                w, h = img.size
                if isinstance(self._fit, tuple):
                    self._canvas = self._fit
                elif h > w:
                    th = min(h, CAMERA_CANVAS_MAX_H)
                    self._canvas = (
                        min(CAMERA_CANVAS_MAX_W, (th * 16 // 9) & ~1),
                        th,
                    )
                else:
                    s = min(
                        CAMERA_CANVAS_MAX_W / w,
                        CAMERA_CANVAS_MAX_H / h,
                        1.0,
                    )
                    self._canvas = (
                        max(2, int(w * s) & ~1),
                        max(2, int(h * s) & ~1),
                    )
            img = _fit_canvas(img, self._canvas)
        out = io.BytesIO()
        img.save(out, "JPEG", quality=88)
        return out.getvalue()

    def feed(self, fr: KiwikFrame) -> bytes | None:
        """Return a displayable JPEG for this frame, or None to skip."""
        import io

        from PIL import Image

        if fr.type == 1 or fr.keyframe:
            try:
                img = Image.open(io.BytesIO(fr.raw)).convert("RGB")
            except Exception:
                return None
            self._img = img
            self._gw = (img.width + 15) // 16
            self._gh = (img.height + 15) // 16
            return self._encode(img)
        app3 = fr.extra.get("app3")
        if self._img is None or not app3 or len(app3) < 6:
            return None
        mcu_w, mcu_h = app3[2], app3[3]
        if not mcu_w or not mcu_h:
            return None
        mask = app3[6:]
        gw = (self._img.width + mcu_w - 1) // mcu_w
        gh = (self._img.height + mcu_h - 1) // mcu_h
        try:
            strip = Image.open(io.BytesIO(fr.raw)).convert("RGB")
        except Exception:
            return None
        tiles = strip.width // mcu_w
        if not tiles:
            return None
        img = self._img.copy()
        t = 0
        for i in range(min(gw * gh, len(mask) * 8)):
            if mask[i >> 3] >> (i & 7) & 1:
                continue  # bit set = unchanged MCU
            if t >= tiles:
                break
            x, y = (i % gw) * mcu_w, (i // gw) * mcu_h
            img.paste(strip.crop((t * mcu_w, 0, t * mcu_w + mcu_w, mcu_h)), (x, y))
            t += 1
        if t != tiles:
            _LOGGER.debug(
                "delta strip: placed %s of %s tiles (mask zeros mismatch)",
                t, tiles,
            )
        self._img = img
        return self._encode(img)


async def composited_frames(
    frames: AsyncIterator[KiwikFrame],
    fit: str | tuple[int, int] | None = "auto",
) -> AsyncIterator[bytes]:
    """Yield displayable JPEGs — keyframes pass through, MCU strips are
    composited onto the running frame in an executor (PIL is CPU-bound)."""
    comp = DeltaCompositor(fit)
    loop = asyncio.get_running_loop()
    try:
        async for fr in frames:
            try:
                jpg = await loop.run_in_executor(None, comp.feed, fr)
            except Exception as err:
                _LOGGER.debug("delta composite failed: %s", err)
                jpg = None
            if jpg:
                yield jpg
    finally:
        # Close the media ws promptly when the relay client goes
        # away — the device keeps burning battery while it streams.
        await frames.aclose()


def first_jpeg(buf: bytes, secret: str | None) -> bytes | None:
    """First displayable JPEG from a clip (MJPEG frame or the block itself)."""
    try:
        cryptor = _Cryptor(secret) if secret else None
    except ValueError as err:
        _LOGGER.debug("media secret rejected: %s", err)
        cryptor = None
    for block in iter_blocks(buf):
        fr = decode_frame(block, cryptor)
        if fr is None:
            continue
        if fr.is_jpeg:
            return fr.raw
        break
    return None


def elementary_stream(
    buf: bytes, secret: str | None, limit: int = 60
) -> tuple[str, bytes] | None:
    """Concatenated H.264/HEVC chunks of a clip → (codec, bytes)."""
    try:
        cryptor = _Cryptor(secret) if secret else None
    except ValueError:
        cryptor = None
    codec: str | None = None
    out = bytearray()
    for block in iter_blocks(buf):
        fr = decode_frame(block, cryptor)
        if fr is None:
            continue
        if fr.type == VIDEO_H264:
            codec = "h264"
        elif fr.type == VIDEO_HEVC:
            codec = "hevc"
        else:
            continue
        if fr.video:
            out += fr.video
        limit -= 1
        if limit <= 0:
            break
    if codec and out:
        return codec, bytes(out)
    return None


async def es_to_jpeg(codec: str, data: bytes) -> bytes | None:
    """Extract one frame from an elementary stream via ffmpeg."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "ffmpeg",
            "-f",
            "hevc" if codec == "hevc" else "h264",
            "-i",
            "pipe:0",
            "-frames:v",
            "1",
            "-f",
            "image2pipe",
            "-vcodec",
            "mjpeg",
            "pipe:1",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except FileNotFoundError:
        _LOGGER.debug("ffmpeg not found — cannot decode %s clip", codec)
        return None
    try:
        out, _ = await asyncio.wait_for(proc.communicate(data), 20)
    except (asyncio.TimeoutError, TimeoutError):
        proc.kill()
        return None
    return out or None


async def iter_stream_frames(
    session_get,
    uri: str,
    secret: str | None,
) -> AsyncIterator[KiwikFrame]:
    """Yield decoded frames from a live/chunked media.uri response."""
    try:
        cryptor = _Cryptor(secret) if secret else None
    except ValueError:
        cryptor = None
    parser = BlockStream()
    async with session_get(uri) as resp:
        resp.raise_for_status()
        async for chunk in resp.content.iter_chunked(65536):
            for block in parser.feed(chunk):
                fr = decode_frame(block, cryptor)
                if fr is not None:
                    yield fr


async def _media_ws_ping(ws) -> None:
    """Empty binary keepalive — the app sends ArrayBuffer(0) every 4s."""
    try:
        while True:
            await asyncio.sleep(4.0)
            if ws.closed:
                return
            await ws.send_bytes(b"")
    except asyncio.CancelledError:
        raise
    except Exception:
        pass


async def iter_stream_frames_ws(
    ws_connect,
    uri: str,
    secret: str | None,
    retries: int = 5,
) -> AsyncIterator[KiwikFrame]:
    """Same as iter_stream_frames but over the live media WebSocket.

    Binary messages carry Kiwik blocks (each message may hold a whole
    block or an arbitrary fragment — BlockStream resyncs either way).
    ``retries`` bounds same-uri re-dials (the token is often
    single-use, so callers usually pass a low value or 0).
    """
    import aiohttp  # lazy — keeps the parser usable without aiohttp

    try:
        cryptor = _Cryptor(secret) if secret else None
    except ValueError as err:
        _LOGGER.debug("media ws cryptor failed: %s", err)
        cryptor = None
    _LOGGER.debug(
        "media ws: cryptor=%s secret_len=%s",
        "on" if cryptor else "off",
        len(str(secret or "")),
    )
    parser = BlockStream()
    got = 0
    reconnects = 0
    while True:
        ws = None
        try:
            async with ws_connect(uri) as ws:
                ping = asyncio.ensure_future(_media_ws_ping(ws))
                try:
                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.BINARY:
                            for block in parser.feed(msg.data):
                                fr = decode_frame(block, cryptor)
                                if fr is not None:
                                    got += 1
                                    if got <= 8:
                                        _LOGGER.debug(
                                            "frame type=%s crypt=%s "
                                            "%sx%s video=%s audio=%s "
                                            "idx=%s",
                                            fr.type, fr.crypt,
                                            fr.width, fr.height,
                                            len(fr.video or b""),
                                            len(fr.audio or b""),
                                            fr.index,
                                        )
                                    yield fr
                        elif msg.type == aiohttp.WSMsgType.TEXT:
                            _LOGGER.debug(
                                "media ws text: %.200s", msg.data
                            )
                        else:
                            break
                finally:
                    ping.cancel()
        finally:
            if ws is not None:
                _LOGGER.debug(
                    "media ws closed: code=%s exc=%r frames=%d",
                    ws.close_code, ws.exception(), got,
                )
        if ws is not None and ws.close_code == 1000:
            break
        # The app reconnects on a 4004 kick (≤5×, 1s apart). Any other
        # abnormal close before the first frame is almost certainly
        # the same early-consumer race while the device's upstream
        # spins up, so treat it identically.
        reconnects += 1
        if reconnects > retries:
            break
        await asyncio.sleep(1.0)
