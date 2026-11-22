"""Polling coordinator: groups -> devices -> latest lock events."""
from __future__ import annotations

import asyncio
import html
import logging
import os
import shutil
import time
from datetime import datetime, timedelta
from typing import Any, AsyncIterator

from homeassistant.components import persistent_notification
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from . import video
from .api import UsmartClient, UsmartWs
from .const import (
    CAMERA_STREAM_MAX_SECONDS,
    CONF_RECORD_COOLDOWN,
    CONF_RECORD_ENABLED,
    CONF_RECORD_KEEP_DAYS,
    CONF_RECORD_SECONDS,
    DEFAULT_RECORD_COOLDOWN,
    DEFAULT_RECORD_KEEP_DAYS,
    DEFAULT_RECORD_SECONDS,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

# The lock drives the bolt back a few seconds after opening and does
# not emit a "locked" event for it — the app uses its own unlockTime
# countdown for the same reason.
_AUTO_RELOCK_SECONDS = 5.0

# Event names that mean "locked" vs "unlocked" (from the bundle's
# status list `I` — everything else is an alert/info record).
LOCKED_EVENTS = {
    "LOCKED",
    "DOOR_LOCKED",
    "LOCK_INDOOR_BUTTON_LOCK",
    "LOCK_INDOOR_LEVER_LOCK",
    "LOCK_TIMED_LOCK",
    "LOCK_AUTO_LOCKED",
    "DOOR_LOCK_ARMED",
}
UNLOCKED_EVENTS = {
    "UNLOCKED",
    "DOOR_UNLOCKED",
    "EMERGENCY_UNLOCK",
    "LOCK_INDOOR_BUTTON_UNLOCK",
    "LOCK_INDOOR_LEVER_UNLOCK",
    "DOOR_LOCK_UNLOCKED_KNOB",
    # Alert in the app, but the door is factually open when it fires.
    "ARMED_DOOR_LOCK_UNLOCKED",
}
# Doorbell ring — a *request* to open, not an actual unlock: someone
# pressed the bell and the device asks for remote confirmation.
RING_EVENTS = {
    "REMOTE_UNLOCK",
}
STATE_EVENT_NAMES = ",".join(sorted(LOCKED_EVENTS | UNLOCKED_EVENTS))

# Sentinel pushed to subscriber queues when the pump ends.
_LIVE_END = object()


class _LiveSession:
    """Per-device fan-out state for the shared live stream.

    The device allows a single monitoring session, so one pump reads
    the media socket and broadcasts composited JPEGs to every
    subscriber's queue (slow subscribers drop the oldest frame).
    """

    def __init__(self, did: str) -> None:
        self.did = did
        self.subs: set[asyncio.Queue] = set()
        self.task: asyncio.Task | None = None
        self.last_jpeg: bytes | None = None
        self.used_uris: set[str] = set()

# data.lock_user.type — from the app's LockUserType enum.
LOCK_USER_TYPES = {
    0: "default",
    1: "fingerprint",
    2: "password",
    3: "card",
    4: "key",
    5: "phone",
    6: "face",
    7: "palmprint",
    8: "iris",
    9: "temp",
    10: "finger_vein",
    11: "palm_vein",
}


# Top-level (or data.*) keys that make an event media-bearing.
_MEDIA_KEYS = ("stream_id", "streamId", "media", "image", "image_uri")


def _event_has_media(event: dict[str, Any]) -> bool:
    data = event.get("data")
    return any(k in event for k in _MEDIA_KEYS) or (
        isinstance(data, dict) and any(k in data for k in _MEDIA_KEYS)
    )


def _extract_lock_user(event: dict[str, Any]) -> dict[str, Any] | None:
    """Pull ``data.lock_user`` out of an event, if present."""
    lock_user = (event.get("data") or {}).get("lock_user")
    if not isinstance(lock_user, dict) or not lock_user.get("alias"):
        return None
    return {
        "alias": lock_user.get("alias"),
        "type": lock_user.get("type"),
        "id": lock_user.get("id"),
        "user_id": lock_user.get("user_id"),
        "at": event.get("created_at") or event.get("time"),
    }


def _synthetic_relock(
    did: str, unlock_event: dict[str, Any]
) -> dict[str, Any]:
    return {
        "did": did,
        "name": "LOCK_AUTO_LOCKED",
        "synthetic": True,
        "replaces_key": unlock_event.get("id")
        or unlock_event.get("created_at"),
    }


def _event_age(event: dict[str, Any]) -> float | None:
    """Seconds since the event's server timestamp; None if unparsable."""
    ts = event.get("created_at") or event.get("time")
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    return time.time() - dt.timestamp()


class UsmartCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Fetches all groups' devices and each lock's latest event."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: UsmartClient,
        update_interval: timedelta,
        entry: ConfigEntry | None = None,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=update_interval,
        )
        self.client = client
        self.entry = entry
        self.ws: UsmartWs | None = None
        self.data: dict[str, Any] = {
            "devices": {},
            "events": {},
            "users": {},
            "media": {},
            "state": {},
        }
        self._relock_handles: dict[str, asyncio.TimerHandle] = {}
        self._record_tasks: dict[str, asyncio.Task] = {}
        self._record_last: dict[str, float] = {}
        self._live: dict[str, _LiveSession] = {}

    async def _async_update_data(self) -> dict[str, Any]:
        devices: dict[str, dict[str, Any]] = {}
        groups = await self.client.async_get_groups()
        for group in groups:
            gid = str(group.get("gid") or group.get("id"))
            if not gid:
                continue
            try:
                for dev in await self.client.async_get_devices(gid):
                    did = str(dev.get("did") or "")
                    if did:
                        dev["_gid"] = gid
                        devices[did] = dev
            except Exception:
                _LOGGER.debug("failed to list devices for group %s", gid)

        events: dict[str, dict[str, Any]] = dict(self.data.get("events", {}))
        users: dict[str, dict[str, Any]] = dict(self.data.get("users", {}))
        media: dict[str, dict[str, Any]] = dict(self.data.get("media", {}))
        state: dict[str, dict[str, Any]] = dict(self.data.get("state", {}))
        no_abilities: list[str] = []
        for did, dev in devices.items():
            if dev.get("type") not in ("LOCK", "DOOR_SENSOR", "IPC"):
                continue
            try:
                # Battery / online / rssi live in /devices/{did}/abilities,
                # merged into the device object like the app does.
                abilities = await self.client.async_get_abilities(did)
                dev.update(abilities)
                if not abilities:
                    no_abilities.append(did)
            except Exception:
                _LOGGER.debug("failed to fetch abilities for %s", did)
            try:
                latest = await self.client.async_get_events(
                    did, page=1, per_page=10
                )
                for ev in latest:
                    if _event_has_media(ev):
                        media[did] = ev
                        break
                if latest:
                    incoming = latest[0]
                    events[did] = incoming
                    if _event_has_media(incoming):
                        media[did] = incoming
                # Lock state comes from the newest *state-bearing*
                # event — ACTIVE_MONITOR/alerts between unlocks must
                # not blank it. When the raw page has none, ask the
                # API for state events directly (name_in), like the
                # app does — monitor bursts can bury the last unlock
                # beyond any reasonable page depth.
                state_ev = next(
                    (
                        e
                        for e in latest
                        if str(e.get("name") or "")
                        in LOCKED_EVENTS | UNLOCKED_EVENTS
                    ),
                    None,
                )
                if state_ev is None:
                    state_rows = await self.client.async_get_events(
                        did, per_page=1, name_in=STATE_EVENT_NAMES
                    )
                    state_ev = state_rows[0] if state_rows else None
                _LOGGER.debug(
                    "events %s: %d rows, state=%s",
                    did,
                    len(latest),
                    state_ev.get("name") if state_ev else None,
                )
                if state_ev:
                    key = state_ev.get("id") or state_ev.get(
                        "created_at"
                    )
                    # Don't let polling roll back a synthesized
                    # auto-relock onto the same unlock it replaced.
                    if not (
                        state.get(did, {}).get("synthetic")
                        and key
                        and key
                        == state.get(did, {}).get("replaces_key")
                    ):
                        name = str(state_ev.get("name") or "")
                        if name in UNLOCKED_EVENTS:
                            lock_user = _extract_lock_user(state_ev)
                            if lock_user:
                                users[did] = lock_user
                            state[did] = state_ev
                            age = _event_age(state_ev)
                            if (
                                age is not None
                                and age >= _AUTO_RELOCK_SECONDS
                            ):
                                # Stale unlock — bolt's already back.
                                state[did] = _synthetic_relock(
                                    did, state_ev
                                )
                            else:
                                self._schedule_relock(did)
                        else:
                            state[did] = state_ev
            except Exception as err:
                _LOGGER.debug(
                    "failed to fetch events for %s: %r", did, err
                )

        # Devices with an empty REST /abilities get them over the WS
        # channel instead (Iot.Device.GetDevicesAbility, as in the app).
        if no_abilities and self.ws is not None:
            try:
                resp = await self.ws.get_devices_ability(no_abilities)
                _LOGGER.debug("GetDevicesAbility: %r", resp)
                for did in no_abilities:
                    node = None
                    if isinstance(resp, dict):
                        node = resp.get(did)
                        if node is None:
                            node = (resp.get("abilities") or {}).get(did)
                    if isinstance(node, dict):
                        devices[did].update(
                            {
                                str(k): v if isinstance(v, dict) else {"status": v}
                                for k, v in node.items()
                            }
                        )
                        # The device answered over the relay — it's online.
                        devices[did]["last_seen"] = time.time()
            except Exception as err:
                _LOGGER.debug("GetDevicesAbility failed: %s", err)

        return {
            "devices": devices,
            "events": events,
            "users": users,
            "media": media,
            "state": state,
        }

    def apply_ws_event(self, event: dict[str, Any]) -> None:
        """Fold an EventNotify push into cached data and notify entities."""
        did = str(event.get("did") or "")
        if not did:
            return
        dev = self.data.get("devices", {}).get(did)
        if dev is not None:
            dev["last_seen"] = time.time()
        if event.get("name") == "__ABILITY__":
            # Server-pushed ability report (decoded CtrlResponse echo).
            if dev is not None:
                dev[str(event["cmd"])] = {
                    "status": event.get("value"),
                    "updated_at": time.time(),
                }
                self.async_set_updated_data(self.data)
            return
        name = str(event.get("name") or "")
        if name in UNLOCKED_EVENTS:
            lock_user = _extract_lock_user(event)
            if lock_user:
                self.data.setdefault("users", {})[did] = lock_user
        if _event_has_media(event):
            self.data.setdefault("media", {})[did] = event
        # The newest event wins; pushes arrive in order anyway.
        self.data.setdefault("events", {})[did] = event
        if name in LOCKED_EVENTS or name in UNLOCKED_EVENTS:
            # Only state-bearing events drive the lock entity —
            # ACTIVE_MONITOR/alerts must not blank the lock state.
            self.data.setdefault("state", {})[did] = event
        self.async_set_updated_data(self.data)
        if name in UNLOCKED_EVENTS:
            # Auto-relocking bolts emit no "locked" event — flip the
            # state on a timer, like the app's unlockTime countdown.
            self._schedule_relock(did)
        if name == "HUMAN_LINGERING":
            self._maybe_record(did, name)
        if name in RING_EVENTS:
            self._fire_ring(did, event)

    def _schedule_relock(self, did: str) -> None:
        handle = self._relock_handles.pop(did, None)
        if handle is not None:
            handle.cancel()
        self._relock_handles[did] = self.hass.loop.call_later(
            _AUTO_RELOCK_SECONDS, self._mark_locked, did
        )

    def _mark_locked(self, did: str) -> None:
        """Synthesize the auto-relock event the device never sends."""
        self._relock_handles.pop(did, None)
        state = self.data.setdefault("state", {})
        last = state.get(did) or {}
        if str(last.get("name") or "") in UNLOCKED_EVENTS:
            state[did] = _synthetic_relock(did, last)
            self.async_set_updated_data(self.data)

    # ------------------------------------------------------------------
    # Shared live session (fan-out)
    # ------------------------------------------------------------------

    def live_session(self, did: str) -> _LiveSession:
        sess = self._live.get(did)
        if sess is None:
            sess = self._live[did] = _LiveSession(did)
        return sess

    async def live_frames(self, did: str) -> AsyncIterator[bytes]:
        """Subscribe to the device's shared live stream.

        First subscriber starts the pump (SELFVIEW -> media socket),
        the last one stops it, and a late joiner replays the latest
        frame instantly instead of waiting for a keyframe.
        """
        sess = self.live_session(did)
        queue: asyncio.Queue = asyncio.Queue(maxsize=8)
        sess.subs.add(queue)
        if sess.task is None or sess.task.done():
            sess.task = self.hass.async_create_task(
                self._live_pump(sess)
            )
        try:
            if sess.last_jpeg is not None:
                yield sess.last_jpeg
            while True:
                item = await queue.get()
                if item is _LIVE_END:
                    return
                yield item
        finally:
            sess.subs.discard(queue)
            if not sess.subs and sess.task is not None:
                sess.task.cancel()

    @staticmethod
    def _live_push(sess: _LiveSession, item: Any) -> None:
        if item is not _LIVE_END:
            sess.last_jpeg = item
        for queue in list(sess.subs):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                queue.put_nowait(item)
            except asyncio.QueueFull:
                pass

    async def _open_live(
        self, sess: _LiveSession
    ) -> dict[str, Any] | None:
        """SELFVIEW, then wait for a media uri this session has not
        burned yet — media tokens are single-use, a used uri can
        never be re-dialed."""
        did = sess.did
        ws = self.ws
        if ws is None:
            return None
        uid = self.client.uid or ""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 30.0
        next_send = 0.0
        sends = 0
        while sess.subs and loop.time() < deadline:
            now = loop.time()
            # Re-send is deliberately sparse: a second SELFVIEW right
            # after the first restarts monitoring server-side and
            # kills the token the push is about to deliver.
            if sends < 2 and now >= next_send:
                try:
                    resp = await ws.start_view(did, uid)
                    _LOGGER.debug(
                        "live %s: start_view -> %r", did, resp
                    )
                except Exception as err:
                    _LOGGER.debug("live %s: start_view: %s", did, err)
                sends += 1
                next_send = now + 14.0
            info = self.data.get("media", {}).get(did) or {}
            media = self._event_media_dict(info)
            uri = str((media or {}).get("uri") or "")
            if (
                uri
                and uri not in sess.used_uris
                and (
                    media.get("live")
                    or uri.startswith(("wss://", "ws://"))
                )
            ):
                sess.used_uris.add(uri)
                return media
            await asyncio.sleep(0.5)
        return None

    async def _live_pump(self, sess: _LiveSession) -> None:
        """Read the media socket once and broadcast to subscribers.

        A closed socket means a burned token, so abnormal ends restart
        the session through a fresh SELFVIEW cycle (subscribers see a
        pause, not a disconnect) while any subscriber stays attached.
        """
        did = sess.did
        loop = asyncio.get_running_loop()
        deadline = loop.time() + CAMERA_STREAM_MAX_SECONDS
        cycles = 0
        try:
            while sess.subs and loop.time() < deadline:
                media = await self._open_live(sess)
                if not media:
                    break
                uri = str(media.get("uri") or "")
                secret = media.get("secret")
                if uri.startswith(("wss://", "ws://")):
                    frames = video.iter_stream_frames_ws(
                        self.client.media_ws_connect,
                        uri,
                        secret,
                        retries=4,
                    )
                else:
                    frames = video.iter_stream_frames(
                        self.client.media_stream_get, uri, secret
                    )
                comp = video.DeltaCompositor(None)
                got = 0
                try:
                    async for fr in frames:
                        if not sess.subs or loop.time() > deadline:
                            break
                        jpg = comp.feed(fr)
                        if jpg:
                            got += 1
                            self._live_push(sess, jpg)
                except asyncio.CancelledError:
                    raise
                except Exception as err:
                    _LOGGER.debug(
                        "live %s: pump read: %s", did, err
                    )
                finally:
                    await frames.aclose()
                _LOGGER.debug(
                    "live %s: session ended frames=%d", did, got
                )
                if not sess.subs:
                    break
                cycles += 1
                if cycles >= 5:
                    break
                await asyncio.sleep(0.5)
        finally:
            _LOGGER.debug(
                "live %s: pump ended subs=%d", did, len(sess.subs)
            )
            self._live_push(sess, _LIVE_END)
            sess.task = None

    def _record_cfg(self) -> tuple[bool, float, float, float]:
        options = self.entry.options if self.entry is not None else {}

        def _num(key: str, default: float) -> float:
            try:
                return float(options.get(key, default))
            except (TypeError, ValueError):
                return default

        return (
            bool(options.get(CONF_RECORD_ENABLED, True)),
            _num(CONF_RECORD_SECONDS, DEFAULT_RECORD_SECONDS),
            _num(CONF_RECORD_COOLDOWN, DEFAULT_RECORD_COOLDOWN),
            _num(CONF_RECORD_KEEP_DAYS, DEFAULT_RECORD_KEEP_DAYS),
        )

    def _maybe_record(self, did: str, trigger: str) -> None:
        enabled, seconds, cooldown, _keep = self._record_cfg()
        if not enabled or seconds <= 0:
            return
        task = self._record_tasks.get(did)
        if task is not None and not task.done():
            return
        now = time.monotonic()
        if now - self._record_last.get(did, -cooldown - 1) < cooldown:
            return
        self._record_last[did] = now
        _LOGGER.debug(
            "record %s: %s -> %.0fs clip", did, trigger, seconds
        )
        self._record_tasks[did] = self.hass.async_create_task(
            self._record_clip(did, seconds)
        )

    def shutdown(self) -> None:
        """Cancel background tasks (recordings, live pumps) on unload."""
        for task in self._record_tasks.values():
            task.cancel()
        self._record_tasks.clear()
        for sess in self._live.values():
            if sess.task is not None:
                sess.task.cancel()

    @staticmethod
    def _event_media_dict(
        info: dict[str, Any]
    ) -> dict[str, Any] | None:
        data = info.get("data") if isinstance(info.get("data"), dict) else {}
        media = data.get("media") or info.get("media")
        return media if isinstance(media, dict) else None

    @staticmethod
    def _event_stream_id(info: dict[str, Any]) -> str | None:
        data = info.get("data") if isinstance(info.get("data"), dict) else {}
        sid = (
            info.get("stream_id")
            or info.get("streamId")
            or data.get("stream_id")
            or data.get("streamId")
        )
        return str(sid) if sid else None

    @staticmethod
    def _event_image_url(info: dict[str, Any]) -> str | None:
        data = info.get("data") if isinstance(info.get("data"), dict) else {}
        uri = info.get("image_uri") or data.get("image_uri")
        if not uri:
            image = data.get("image") or info.get("image")
            uri = image.get("uri") if isinstance(image, dict) else None
        return str(uri) if uri else None

    def _fire_ring(self, did: str, event: dict[str, Any]) -> None:
        """Bus event for doorbell rings — usable as an automation
        trigger (e.g. actionable "open the door" notification)."""
        name = (
            (self.data.get("devices", {}).get(did) or {}).get("name")
            or did
        )
        self.hass.bus.async_fire(
            f"{DOMAIN}_ring",
            {
                "did": did,
                "name": name,
                "event": str(event.get("name") or ""),
                "image_url": self._event_image_url(event),
            },
        )
        self._maybe_record(did, str(event.get("name") or "ring"))

    async def _record_clip(self, did: str, seconds: float) -> None:
        jpegs: list[bytes] = []
        source = ""
        event = dict(self.data.get("events", {}).get(did) or {})
        try:
            # The device's own full recording lands in /streams/{id}
            # a few seconds after the push — retry briefly. This is
            # the real clip; media.uri on the event is often just
            # the ~1s cover animation.
            sid = self._event_stream_id(event)
            if sid:
                for _ in range(4):
                    if jpegs:
                        break
                    try:
                        stream = await self.client.async_get_stream(
                            did, sid
                        )
                    except Exception as err:
                        _LOGGER.debug(
                            "record %s: stream lookup: %s", did, err
                        )
                        stream = None
                    uri = str((stream or {}).get("uri") or "")
                    if uri.startswith(("http://", "https://")):
                        jpegs = await self._collect_clip(
                            uri,
                            (stream or {}).get("secret"),
                            int(seconds) * 15,
                        )
                        source = "stream"
                        break
                    await asyncio.sleep(4)
        except Exception as err:
            _LOGGER.debug("record %s: clip fetch failed: %s", did, err)
        if not jpegs:
            try:
                jpegs = await self._capture_live(did, seconds)
                source = "live"
            except Exception as err:
                _LOGGER.debug(
                    "record %s: live capture failed: %s", did, err
                )
        if not jpegs:
            # Last resort — the inline media uri (often a short
            # cover clip, but better than nothing).
            media = self._event_media_dict(event)
            uri = str((media or {}).get("uri") or "")
            if uri.startswith(("http://", "https://")):
                try:
                    jpegs = await self._collect_clip(
                        uri,
                        (media or {}).get("secret"),
                        int(seconds) * 15,
                    )
                    source = "cover"
                except Exception as err:
                    _LOGGER.debug(
                        "record %s: cover clip failed: %s", did, err
                    )
        if not jpegs:
            _LOGGER.debug("record %s: no frames captured", did)
            return
        try:
            path, url = await self._save_clip(did, jpegs)
            await self._prune_clips()
        except Exception as err:
            _LOGGER.warning("record %s: save failed: %s", did, err)
            return
        name = (
            (self.data.get("devices", {}).get(did) or {}).get("name")
            or did
        )
        _LOGGER.debug(
            "record %s: path=%s frames=%d -> %s",
            did,
            source,
            len(jpegs),
            url,
        )
        persistent_notification.async_create(
            self.hass,
            f'<a href="{html.escape(url, quote=True)}" target="_blank">'
            f"{html.escape(os.path.basename(path))}</a>",
            title=f"Кто-то у двери — {name}",
            notification_id=f"usmartgo_record_{did}",
        )
        self.hass.bus.async_fire(
            f"{DOMAIN}_recorded",
            {"did": did, "name": name, "path": path, "url": url},
        )

    async def _collect_clip(
        self, uri: str, secret: str | None, max_frames: int
    ) -> list[bytes]:
        comp = video.DeltaCompositor(None)
        jpegs: list[bytes] = []
        frames = video.iter_stream_frames(
            self.client.media_stream_get, uri, secret
        )
        try:
            async for fr in frames:
                jpg = comp.feed(fr)
                if jpg:
                    jpegs.append(jpg)
                    if len(jpegs) >= max_frames:
                        break
        finally:
            await frames.aclose()
        return jpegs

    async def _capture_live(
        self, did: str, seconds: float
    ) -> list[bytes]:
        """Record seconds of the shared live stream — subscribes to
        the fan-out session, so an ongoing viewer is not stomped."""
        jpegs: list[bytes] = []
        loop = asyncio.get_running_loop()
        frames = self.live_frames(did)
        try:
            first = await asyncio.wait_for(
                frames.__aiter__().__anext__(), 35.0
            )
            jpegs.append(first)
        except (asyncio.TimeoutError, StopAsyncIteration):
            await frames.aclose()
            return jpegs
        end = loop.time() + seconds
        try:
            async for jpg in frames:
                jpegs.append(jpg)
                if loop.time() >= end:
                    break
        finally:
            await frames.aclose()
        return jpegs

    async def _save_clip(
        self, did: str, jpegs: list[bytes]
    ) -> tuple[str, str]:
        folder = self.hass.config.path("www", "usmartgo")

        def _mkdir() -> None:
            os.makedirs(folder, exist_ok=True)

        await self.hass.async_add_executor_job(_mkdir)
        # Date first so clips sort and read naturally; the device id
        # is only appended (short tail) when there are several devices.
        base = time.strftime("%Y-%m-%d_%H-%M-%S")
        if len(self.data.get("devices", {})) > 1:
            base = f"{base}_{did[-4:]}"
        ffmpeg = shutil.which("ffmpeg")
        if ffmpeg:
            fname = f"{base}.mp4"
            path = os.path.join(folder, fname)
            try:
                proc = await asyncio.create_subprocess_exec(
                    ffmpeg,
                    "-y",
                    "-f", "image2pipe",
                    "-framerate", "10",
                    "-i", "pipe:0",
                    "-c:v", "libx264",
                    "-preset", "ultrafast",
                    "-pix_fmt", "yuv420p",
                    "-crf", "28",
                    path,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await proc.communicate(b"".join(jpegs))
                if proc.returncode == 0:
                    return path, f"/local/usmartgo/{fname}"
                _LOGGER.debug("record ffmpeg rc=%s", proc.returncode)
            except Exception as err:
                _LOGGER.debug("record ffmpeg failed: %s", err)
        fname = f"{base}.mjpg"
        path = os.path.join(folder, fname)
        blob = b"".join(jpegs)

        def _write() -> None:
            with open(path, "wb") as fh:
                fh.write(blob)

        await self.hass.async_add_executor_job(_write)
        return path, f"/local/usmartgo/{fname}"

    async def _prune_clips(self) -> None:
        """Delete recorded clips older than record_keep_days."""
        _enabled, _sec, _cd, keep_days = self._record_cfg()
        if keep_days <= 0:
            return
        folder = self.hass.config.path("www", "usmartgo")
        cutoff = time.time() - keep_days * 86400

        def _prune() -> int:
            removed = 0
            try:
                for fname in os.listdir(folder):
                    path = os.path.join(folder, fname)
                    if not os.path.isfile(path):
                        continue
                    if os.path.getmtime(path) < cutoff:
                        os.remove(path)
                        removed += 1
            except OSError:
                pass
            return removed

        removed = await self.hass.async_add_executor_job(_prune)
        if removed:
            _LOGGER.debug("record: pruned %d old clip(s)", removed)
