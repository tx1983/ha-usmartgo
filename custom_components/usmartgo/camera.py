"""Camera entity — event snapshots and live stream relay.

Media flow (reverse-engineered from the app's bundle):

- Events carrying ``stream_id`` / ``media`` / ``image`` are tracked by
  the coordinator in ``data["media"][did]``.
- ``GET /api/devices/{did}/streams/{id}`` returns
  ``{media: {uri, secret}, type, state}``; ``uri`` is a signed URL
  serving the proprietary Kiwik block container (see video.py).
- MJPEG-type blocks are complete JPEGs — relayed as-is. H.264/HEVC
  chunks go through an ffmpeg pipe producing MJPEG.
- ``camera.turn_on`` sends SELFVIEW (5134) over WS, waking the device
  into a LIVE stream whose ``stream_id`` then arrives via EventNotify.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, AsyncIterator

from aiohttp import web
from homeassistant.components.camera import Camera
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import video
from .const import CAMERA_STREAM_MAX_SECONDS
from .coordinator import UsmartCoordinator
from .entity import UsmartEntity

_LOGGER = logging.getLogger(__name__)

_MJPEG_BOUNDARY = "usmartgo_frame"

_MOBILE_UA = re.compile(
    r"android|iphone|ipad|mobile|home assistant", re.I
)


def _is_mobile_request(request: web.Request) -> bool:
    if request.headers.get("Sec-CH-UA-Mobile") == "?1":
        return True
    return bool(_MOBILE_UA.search(request.headers.get("User-Agent", "")))


async def async_setup_entry(
    hass: HomeAssistant, entry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: UsmartCoordinator = entry.runtime_data["coordinator"]
    async_add_entities(
        UsmartCamera(coordinator, did)
        for did, dev in coordinator.data.get("devices", {}).items()
        if dev.get("type") in ("LOCK", "IPC")
    )


class UsmartCamera(UsmartEntity, Camera):
    """Snapshot = latest media event's first frame; live = MJPEG relay."""

    _attr_translation_key = "camera"

    def __init__(self, coordinator: UsmartCoordinator, did: str) -> None:
        UsmartEntity.__init__(self, coordinator, did, "camera")
        Camera.__init__(self)
        self._client = coordinator.client
        self._image: bytes | None = None
        self._image_key: Any = None
        self._stream_info: dict[str, Any] | None = None
        # Framing chosen by the last stream request — stills reuse it
        # so card preview and live view look the same on the device.
        self._fit_hint: str | tuple[int, int] | None = "auto"

    # ------------------------------------------------------------------
    # Media discovery
    # ------------------------------------------------------------------

    @property
    def media_event(self) -> dict[str, Any]:
        return (self.coordinator.data or {}).get("media", {}).get(
            self._did, {}
        )

    def _event_fields(self, info: dict[str, Any]) -> dict[str, Any]:
        """Event fields flattened: top-level plus ``data.*``."""
        data = info.get("data") if isinstance(info.get("data"), dict) else {}
        return {**data, **info}

    def _event_image_uri(self, info: dict[str, Any]) -> str | None:
        fields = self._event_fields(info)
        image = fields.get("image")
        uri = image.get("uri") if isinstance(image, dict) else None
        return uri or fields.get("image_uri")

    async def _event_media(self, info: dict[str, Any]) -> dict[str, Any] | None:
        """Resolve {uri, secret, live, type} for a media event."""
        if not info:
            return None
        fields = self._event_fields(info)
        media = fields.get("media")
        if isinstance(media, dict) and media.get("uri"):
            _LOGGER.debug(
                "media for %s: uri=%s… keys=%s live=%s",
                self._did,
                str(media.get("uri"))[:60],
                sorted(media.keys()),
                media.get("live"),
            )
            return {**media, "live": bool(media.get("live"))}
        stream_id = fields.get("stream_id") or fields.get("streamId")
        if stream_id:
            stream = await self._client.async_get_stream(
                self._did, stream_id
            )
            if stream and stream.get("uri"):
                self._stream_info = stream
                return stream
        return None

    # ------------------------------------------------------------------
    # Still image
    # ------------------------------------------------------------------

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        info = self.media_event
        key = info.get("id") or info.get("stream_id")
        if self._image is not None and key and key == self._image_key:
            return self._image
        img = await self._fetch_snapshot(info)
        if img:
            fit: str | tuple[int, int] | None = (
                (width, height) if width and height else self._fit_hint
            )
            img = await self.hass.async_add_executor_job(
                video.fit_jpeg, img, fit
            )
            self._image, self._image_key = img, key
        return self._image

    async def _fetch_snapshot(self, info: dict[str, Any]) -> bytes | None:
        # 1) Plain JPEG thumbnail the event carries (image_uri).
        img_uri = self._event_image_uri(info)
        if img_uri and img_uri.startswith("http"):
            buf = await self._client.async_fetch_media(img_uri)
            if buf:
                _LOGGER.debug(
                    "snapshot %s: %d bytes head=%s uri=%s…",
                    self._did,
                    len(buf),
                    buf[:8].hex(),
                    img_uri[:60],
                )
                if buf[:4] == video.BLOCK_MAGIC:
                    jpg = video.first_jpeg(buf, None)
                    if jpg:
                        return jpg
                elif buf[:2] == b"\xff\xd8":
                    return buf
        # 2) Clip behind media.uri — only fetchable over http(s).
        try:
            media = await self._event_media(info)
        except Exception as err:
            _LOGGER.debug("stream lookup failed for %s: %s", self._did, err)
            return None
        uri = (media or {}).get("uri") or ""
        if not uri.startswith("http"):
            return None
        buf = await self._client.async_fetch_media(uri)
        if not buf:
            return None
        if buf[:2] == b"\xff\xd8" and buf[:4] != video.BLOCK_MAGIC:
            return buf
        jpg = video.first_jpeg(buf, media.get("secret"))
        if jpg:
            return jpg
        es = video.elementary_stream(buf, media.get("secret"))
        if es:
            return await video.es_to_jpeg(*es)
        return None

    # ------------------------------------------------------------------
    # Live stream
    # ------------------------------------------------------------------

    def _fit_for(
        self, request: web.Request
    ) -> str | tuple[int, int] | None:
        """Pick output framing.

        ``?width=&height=`` gives an exact canvas; ``?fit=desktop``/
        ``auto``/``16:9`` forces the letterbox, any other ``?fit``
        value (``0``/``native``/``mobile``/``portrait``) sends raw
        frames. Without params: mobile clients get the native portrait
        stream (their portrait screens fit it), desktop gets the 16:9
        letterbox.
        """
        fit: str | tuple[int, int] | None = "auto"
        try:
            qw, qh = (
                request.query.get("width"),
                request.query.get("height"),
            )
            if qw and qh:
                fit = (int(qw), int(qh))
            else:
                mode = (request.query.get("fit") or "").lower()
                if mode in ("auto", "desktop", "16:9", "16x9"):
                    fit = "auto"
                elif mode:
                    fit = None
                elif _is_mobile_request(request):
                    fit = None
        except (TypeError, ValueError):
            pass
        self._fit_hint = fit
        return fit

    async def handle_async_mjpeg_stream(
        self, request: web.Request
    ) -> web.StreamResponse:
        """Relay the shared live session.

        The device allows a single monitoring session, so the
        coordinator pumps one media socket and fans composited JPEGs
        out to every viewer; each request applies its own framing.
        """
        fit = self._fit_for(request)
        source = self.coordinator.live_frames(self._did)

        async def _fitted() -> AsyncIterator[bytes]:
            try:
                async for jpg in source:
                    if fit is None:
                        yield jpg
                    else:
                        yield await self.hass.async_add_executor_job(
                            video.fit_jpeg, jpg, fit
                        )
            finally:
                await source.aclose()

        return await self._relay_mjpeg(request, _fitted())

    async def _relay_mjpeg(
        self, request: web.Request, jpegs: AsyncIterator[bytes]
    ) -> web.StreamResponse:
        resp = web.StreamResponse(
            status=200,
            headers={
                "Content-Type": "multipart/x-mixed-replace;"
                f"boundary={_MJPEG_BOUNDARY}"
            },
        )
        err = ""
        try:
            await resp.prepare(request)
            end = asyncio.get_running_loop().time() + CAMERA_STREAM_MAX_SECONDS
            async for jpg in jpegs:
                transport = request.transport
                if transport is None or transport.is_closing():
                    break
                if asyncio.get_running_loop().time() > end:
                    break
                await resp.write(
                    b"--"
                    + _MJPEG_BOUNDARY.encode()
                    + b"\r\nContent-Type: image/jpeg\r\n\r\n"
                    + jpg
                    + b"\r\n"
                )
        except (asyncio.CancelledError, ConnectionResetError):
            raise
        except Exception as exc:
            err = f": {exc!r}"
        finally:
            _LOGGER.debug("mjpeg relay for %s ended%s", self._did, err)
            await jpegs.aclose()
            try:
                await resp.write_eof()
            except Exception:
                pass
        return resp

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------

    async def async_turn_on(self) -> None:
        """Wake the camera (SELFVIEW) — the LIVE stream follows via WS."""
        ws = self.coordinator.ws
        if ws is None:
            _LOGGER.warning("ws not connected — cannot start view")
            return
        uid = self._client.uid or ""
        resp = await ws.start_view(self._did, uid)
        _LOGGER.debug("start_view %s -> %r", self._did, resp)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        info = self.media_event
        stream = self._stream_info or {}
        return {
            "event": info.get("name"),
            "event_at": info.get("created_at") or info.get("time"),
            "stream_id": info.get("stream_id"),
            "stream_type": stream.get("type"),
            "stream_state": stream.get("state"),
            "live": stream.get("live"),
        }


