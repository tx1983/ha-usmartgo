"""Async client for the USmart Go / Kiwik IoT cloud.

Reverse-engineered from com.kiwik.usmartgo 1.16.2 and the bundled web app
served from ``https://go.kiwik.cn/app/na/`` — the Android app is a thin
WebView shell around that React bundle, so all traffic is plain HTTPS.

Auth is OAuth2 authorization-code on a Keycloak-style realm:

1. ``POST /restapi/session/token`` trades identifier + password for a
   ``session_token``. When the deployment requires credential protection
   the identifier and password are RSA-OAEP-SHA256 ciphertexts built with
   the public key hardcoded in the bundle (see below).
2. ``GET {auth}/oauth/authorize?response_type=code&session_token=...``
   302-redirects to ``redirect_uri?code=...``.
3. ``POST {auth}/oauth/token`` (form-encoded) exchanges the code for
   ``access_token`` / ``refresh_token``.

Data endpoints live on ``go.kiwik.cn`` under ``/restapi/*`` and ``/api/*``.
Device control and realtime events go through
``wss://wsapi.kiwiot.com/?access_token=...`` with an Alexa-style envelope
``{header: {namespace, name, messageId, payloadVersion}, payload}`` — the
``Iot.Device`` namespace implements ``Ctrl``/``Relay``/``GetDeviceInfo``,
incoming pushes arrive as ``EventNotify``.

Remote unlock is ``Iot.Device.Ctrl`` with cmd ``RMUNLK`` (5132) whose body
is ``[uid_len + 2, flag, uid_len, *uid_utf8]``; the whole command frame
``[cmd_hi, cmd_lo, *body]`` is base64url-encoded into ``payload.data``.
Commands that mutate the lock additionally need a *secure token* in the
WS header — ``POST /restapi/users/{uid}/mfa/tokens`` with the password.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
import uuid
from typing import Any, Callable

import aiohttp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

_LOGGER = logging.getLogger(__name__)

API_ORIGIN = "https://go.kiwik.cn"
AUTH_ORIGIN = "https://account.kiwik.cn"
AUTHORIZE_URL = f"{AUTH_ORIGIN}/auth/realms/kiwik/oauth/authorize"
TOKEN_URL = f"{AUTH_ORIGIN}/auth/realms/kiwik/oauth/token"
WS_URL = "wss://wsapi.kiwiot.com/"

# Public client_id and credential-protection RSA-4096 key of the Android
# app (region "na"), lifted from the /app/na/ bootstrap page and the JS
# bundle config.
CLIENT_ID = "vvwVSAXKa4NoTw1eejTNd3gXUtv3LorF"
REDIRECT_URI = f"{API_ORIGIN}/app/na/oauth/callback"
CREDENTIAL_PROTECTION_PUBLIC_KEY = (
    "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAxrG8Hf00bOvSKLkVLzUn"
    "7NPWhYSYXay/cWk/l0d0Gh+0Wq8kyImOdLVLzBxnMzlIK5bI6AAs5IIwKbNkVV"
    "GWQIAYb6PAM7DCprcz3bocAFn88d8siYE9AJM+sIgJYHDGBhAB6U63Z7HuEYps"
    "Wbsa2/QQkAhHAX/ftltZvURZzmXY0qMyfF13/bsHt3jWIEpNDuRQq4PfUcaBKn"
    "35RdMHjMAyLY/UF8K9raM7Pi5yq1G9ce27VdPXQOGD6FhgiaHhIDzcY5Szx7rY"
    "GwU8xsUxbzzuHxz33U+0NXwRGNd2nKyuD8UujUHf3ulxNQCxfmhcNTLAT59Lah"
    "A4R7aFYCMtHh7n7S5GxUPjFtIwz0wCjU5dZpo0L75IZdmrw1MEhJNsfEmHzMCv"
    "r1c3JDsFLqiFKb5iKZMg4E/eg9bEZ2eUcLnz0WRYTlr7/WCMK9peSZCvsV52YN"
    "eEdkpxPQET/pBAmBqMvx8YhxEj+9Ona+R9QV5+5/CwJSnExNBuiZI9R8yHAgMB"
    "AAE="
)

# Iot.Device command ids that matter for locks (from the bundle's dD enum).
CMD_DOORPW = 2063
CMD_LKSTATS = 3097
CMD_BATPWR = 3102
CMD_RMUNLK = 5132
CMD_CMDCACHE = 5638
CMD_WIFITIME = 4631
CMD_BLETIME = 4632
CMD_LOWPWR = 4615
CMD_RSSI = 4103
CMD_BATPRO = 4617
CMD_ELEQNT1 = 4102
CMD_ELEQNT2 = 4106
CMD_SELFVIEW = 5134

_TIMEOUT = aiohttp.ClientTimeout(total=30)
_WS_PING_INTERVAL = 25.0
_WS_HEARTBEAT = 30.0


class UsmartError(Exception):
    """Generic API error."""


class UsmartAuthError(UsmartError):
    """Credentials or tokens rejected — reauth required."""


def _b64url(data: bytes, *, pad: bool = False) -> str:
    out = base64.urlsafe_b64encode(data).decode()
    return out if pad else out.rstrip("=")


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _rsa_encrypt(payload: dict[str, Any]) -> str:
    """RSA-OAEP-SHA256 encrypt a JSON dict, return base64url (no pad)."""
    key = serialization.load_der_public_key(
        base64.b64decode(CREDENTIAL_PROTECTION_PUBLIC_KEY)
    )
    blob = json.dumps(payload, separators=(",", ":")).encode()
    ct = key.encrypt(
        blob,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return _b64url(ct)


def _sha256_b64(text: str) -> str:
    return _b64url(hashlib.sha256(text.encode()).digest())


class UsmartClient:
    """REST + WS client for one USmart Go account."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        identifier: str,
        password: str,
    ) -> None:
        self._session = session
        self._identifier = identifier
        self._password = password
        self._tokens: dict[str, Any] = {}
        self.uid: str | None = None
        self._ws_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    async def _async_session_token(self) -> str:
        """POST /restapi/session_token -> session_token.

        Tries the plaintext body first; if the deployment requires
        credential protection (loginIdentifierProtection=1) retries with
        RSA ciphertexts, matching the app's two code paths.
        """
        url = f"{API_ORIGIN}/restapi/session/token"
        plain = {
            "auth_type": "password",
            "identifier": self._identifier,
            "credential": self._password,
        }
        resp = await self._post(url, plain)
        if "session_token" in resp:
            return resp["session_token"]

        exp = int(time.time()) + 120
        ctx = _sha256_b64(
            f"session_token\n{CLIENT_ID}\n{self._identifier}\npassword"
        )
        protected = {
            "auth_type": "password",
            "identifier_ciphertext": _rsa_encrypt(
                {"identifier": self._identifier, "exp": exp}
            ),
            "credential_ciphertext": _rsa_encrypt(
                {"credential": self._password, "exp": exp, "ctx": ctx}
            ),
        }
        resp = await self._post(url, protected)
        if "session_token" not in resp:
            raise UsmartAuthError(f"session/token returned {resp!r}")
        return resp["session_token"]

    async def async_login(self) -> dict[str, Any]:
        """Run the full OAuth dance; fill self._tokens and self.uid."""
        session_token = await self._async_session_token()
        state = uuid.uuid4().hex[:16]
        params = {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "session_token": session_token,
            "redirect_uri": REDIRECT_URI,
            "state": state,
        }
        async with self._session.get(
            AUTHORIZE_URL,
            params=params,
            allow_redirects=False,
            timeout=_TIMEOUT,
        ) as resp:
            if resp.status not in (301, 302, 303, 307, 308):
                raise UsmartAuthError(
                    f"authorize returned HTTP {resp.status}"
                )
            location = resp.headers.get("Location", "")
        from urllib.parse import parse_qs, urlparse

        query = parse_qs(urlparse(location).query)
        code = query.get("code", [None])[0]
        if not code:
            raise UsmartAuthError(f"no code in redirect: {location!r}")

        tokens = await self._token_request(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
            }
        )
        self._tokens = tokens
        profile = await self.async_get_profile()
        self.uid = str(profile.get("uid") or "")
        return profile

    async def _token_request(self, data: dict[str, str]) -> dict[str, Any]:
        data = {"client_id": CLIENT_ID, **data}
        async with self._session.post(
            TOKEN_URL,
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                "X-Kiwik-Client-Id": CLIENT_ID,
            },
            timeout=_TIMEOUT,
        ) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise UsmartAuthError(
                    f"token request failed: HTTP {resp.status} {text[:200]}"
                )
            tokens = await resp.json()
        tokens["expires_at"] = time.time() + int(
            tokens.get("expires_in", 3600)
        )
        return tokens

    async def _async_access_token(self) -> str:
        """Valid access_token: refresh -> re-login -> raise."""
        tokens = self._tokens
        if tokens.get("access_token") and (
            tokens.get("expires_at", 0) - time.time() > 60
        ):
            return tokens["access_token"]
        if tokens.get("refresh_token"):
            try:
                self._tokens = await self._token_request(
                    {
                        "grant_type": "refresh_token",
                        "refresh_token": tokens["refresh_token"],
                    }
                )
                return self._tokens["access_token"]
            except UsmartError:
                _LOGGER.debug("refresh_token rejected, re-logging in")
        await self.async_login()
        return self._tokens["access_token"]

    # ------------------------------------------------------------------
    # REST
    # ------------------------------------------------------------------

    async def _post(self, url: str, body: dict[str, Any]) -> dict[str, Any]:
        async with self._session.post(
            url,
            json=body,
            headers={"X-Kiwik-Client-Id": CLIENT_ID},
            timeout=_TIMEOUT,
        ) as resp:
            if resp.status in (401, 403):
                text = await resp.text()
                raise UsmartAuthError(
                    f"HTTP {resp.status} on {url}: {text[:200]}"
                )
            if resp.status >= 400:
                text = await resp.text()
                raise UsmartError(
                    f"HTTP {resp.status} on {url}: {text[:200]}"
                )
            try:
                return await resp.json()
            except Exception:
                return {}

    async def _request(
        self,
        method: str,
        path: str,
        *,
        prefix: str = "/restapi",
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        _retry: bool = True,
    ) -> Any:
        token = await self._async_access_token()
        async with self._session.request(
            method,
            f"{API_ORIGIN}{prefix}{path}",
            json=json_body,
            params=params,
            headers={
                "Authorization": f"Bearer {token}",
                "X-Kiwik-Client-Id": CLIENT_ID,
            },
            timeout=_TIMEOUT,
        ) as resp:
            if resp.status == 401 and _retry:
                self._tokens = {}
                return await self._request(
                    method, path, prefix=prefix, json_body=json_body,
                    params=params, _retry=False,
                )
            if resp.status in (401, 403):
                text = await resp.text()
                raise UsmartAuthError(
                    f"HTTP {resp.status} on {path}: {text[:200]}"
                )
            if resp.status == 404:
                return None
            if resp.status >= 400:
                text = await resp.text()
                raise UsmartError(
                    f"HTTP {resp.status} on {path}: {text[:200]}"
                )
            if resp.status == 204:
                return None
            try:
                return await resp.json()
            except Exception:
                return None

    async def async_get_profile(self) -> dict[str, Any]:
        data = await self._request("GET", "/user")
        return data or {}

    async def async_get_groups(self) -> list[dict[str, Any]]:
        data = await self._request("GET", "/groups")
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("list") or data.get("groups") or []
        return []

    async def async_get_devices(self, gid: str) -> list[dict[str, Any]]:
        data = await self._request("GET", f"/groups/{gid}/devices")
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("list") or data.get("devices") or []
        return []

    async def async_get_abilities(self, did: str) -> dict[str, Any]:
        """GET /restapi/devices/{did}/abilities.

        Returns ``[{type, value, updated_at}, ...]``; the app merges it
        into the device object as ``{[type]: {status, updated_at}}`` —
        battery, online timestamps, RSSI etc. live here, not in the
        group device list.
        """
        data = await self._request("GET", f"/devices/{did}/abilities")
        if not isinstance(data, list):
            _LOGGER.debug("abilities for %s: %r", did, data)
            return {}
        _LOGGER.debug("abilities for %s: %d items", did, len(data))
        out: dict[str, Any] = {}
        for item in data:
            if isinstance(item, dict) and "type" in item:
                out[str(item["type"])] = {
                    "status": item.get("value"),
                    "updated_at": item.get("updated_at"),
                }
        _LOGGER.debug("abilities for %s keys: %s", did, sorted(out))
        return out

    async def async_get_events(
        self,
        did: str,
        *,
        page: int = 1,
        per_page: int = 15,
        name_in: str | None = None,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"page": page, "per_page": per_page}
        if name_in:
            params["name_in"] = name_in
        data = await self._request(
            "GET",
            f"/devices/{did}/events",
            prefix="/api",
            params=params,
        )
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("list") or data.get("events") or []
        return []

    async def async_get_stream(
        self, did: str, stream_id: str | int
    ) -> dict[str, Any] | None:
        """GET /api/devices/{did}/streams/{id} → {media:{uri,secret},…}.

        The app merges ``media`` into the record and marks it ``live``
        when ``type=="LIVE" and state!="CLOSED"``.
        """
        data = await self._request(
            "GET", f"/devices/{did}/streams/{stream_id}", prefix="/api"
        )
        if not isinstance(data, dict):
            return None
        media = data.get("media") or {}
        out = {**data, **media}
        out["live"] = (
            data.get("type") == "LIVE" and data.get("state") != "CLOSED"
        )
        _LOGGER.debug(
            "stream %s for %s: type=%s state=%s live=%s",
            stream_id,
            did,
            data.get("type"),
            data.get("state"),
            out["live"],
        )
        return out

    async def async_fetch_media(self, url: str) -> bytes | None:
        """GET a signed media.uri (clip or snapshot) — no auth headers."""
        try:
            async with self._session.get(
                url, timeout=aiohttp.ClientTimeout(total=120)
            ) as resp:
                if resp.status != 200:
                    _LOGGER.debug(
                        "media GET %s… -> HTTP %s", url[:80], resp.status
                    )
                    return None
                return await resp.read()
        except Exception as err:
            _LOGGER.debug("media fetch failed: %s", err)
            return None

    def media_stream_get(self, url: str) -> aiohttp.ClientResponse:
        """Streaming GET for a live media.uri (chunked, long-lived)."""
        return self._session.get(
            url, timeout=aiohttp.ClientTimeout(sock_read=300)
        )

    def media_ws_connect(
        self, url: str
    ) -> aiohttp.ClientWebSocketResponse:
        """Live media.uri is ``wss://*.ims.kiwiot.com?token=<JWT>`` —
        proprietary Kiwik blocks arrive as binary WS messages."""
        # ws_connect takes ClientWSTimeout (or float) — passing
        # ClientTimeout crashes aiohttp's close path with
        # "float + ClientTimeout" TypeError and a 1006 close code.
        try:
            ws_timeout: Any = aiohttp.ClientWSTimeout(
                ws_receive=300.0, ws_close=10.0
            )
        except AttributeError:  # aiohttp < 3.12
            ws_timeout = 300.0
        return self._session.ws_connect(url, timeout=ws_timeout)

    async def async_get_secure_token(self) -> str:
        """MFA/secure token required by mutating commands (unlock, settings)."""
        if not self.uid:
            profile = await self.async_get_profile()
            self.uid = str(profile.get("uid") or "")
        body: dict[str, Any] = {
            "auth_type": "password",
            "credential": self._password,
        }
        data = await self._request(
            "POST",
            f"/users/{self.uid}/mfa/tokens",
            json_body=body,
        )
        token = (data or {}).get("access_token")
        if not token:
            raise UsmartError(f"mfa/tokens returned {data!r}")
        return token

    # ------------------------------------------------------------------
    # WebSocket — device control + realtime events
    # ------------------------------------------------------------------


class UsmartWs:
    """Persistent wss://wsapi.kiwiot.com connection.

    Sends ``Iot.*`` requests and dispatches ``EventNotify`` pushes to
    ``on_event`` callbacks. Reconnects forever with a fresh access token;
    ``close()`` stops the loop cleanly on entry unload.
    """

    def __init__(
        self,
        client: UsmartClient,
        session: aiohttp.ClientSession,
        on_event: Callable[[dict[str, Any]], None] | None = None,
        on_connect: Callable[[], None] | None = None,
    ) -> None:
        self._client = client
        self._session = session
        self._on_event = on_event
        self._on_connect = on_connect
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._pending: dict[str, asyncio.Future] = {}
        self._task: asyncio.Task | None = None
        self._ping_task: asyncio.Task | None = None
        self._closed = False

    def start(self) -> None:
        self._task = asyncio.ensure_future(self._run())

    async def close(self) -> None:
        self._closed = True
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(UsmartError("ws closed"))
        if self._ping_task:
            self._ping_task.cancel()
        if self._ws is not None:
            await self._ws.close()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass

    async def _run(self) -> None:
        backoff = 5.0
        while not self._closed:
            try:
                token = await self._client._async_access_token()
                async with self._session.ws_connect(
                    f"{WS_URL}?access_token={token}",
                    timeout=_TIMEOUT,
                    heartbeat=_WS_HEARTBEAT,
                ) as ws:
                    self._ws = ws
                    backoff = 5.0
                    _LOGGER.debug("ws connected")
                    if self._on_connect:
                        try:
                            self._on_connect()
                        except Exception:
                            _LOGGER.exception("on_connect callback failed")
                    self._ping_task = asyncio.ensure_future(self._ping())
                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            self._handle_text(msg.data)
                        elif msg.type in (
                            aiohttp.WSMsgType.CLOSED,
                            aiohttp.WSMsgType.ERROR,
                            aiohttp.WSMsgType.CLOSING,
                        ):
                            break
                    _LOGGER.debug("ws closed: %s", ws.close_code)
            except asyncio.CancelledError:
                raise
            except Exception as err:
                _LOGGER.debug("ws connect failed: %s", err)
            finally:
                if self._ping_task:
                    self._ping_task.cancel()
                    self._ping_task = None
                self._ws = None
                for fut in self._pending.values():
                    if not fut.done():
                        fut.set_exception(UsmartError("ws reconnect"))
            if self._closed:
                return
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 120.0)

    async def _drop_ws(self) -> None:
        """Close the current socket; _run() will reconnect with a new token."""
        ws, self._ws = self._ws, None
        if ws is not None and not ws.closed:
            await ws.close()

    async def _ping(self) -> None:
        try:
            while True:
                await asyncio.sleep(_WS_PING_INTERVAL)
                try:
                    await self.request("Iot.Application", "Ping", {}, timeout=10)
                except Exception as err:
                    # Keep looping: a missed app-level ping must not kill
                    # keep-alive forever (that used to leave the socket
                    # stale while _run kept waiting on it).
                    _LOGGER.debug("ws ping failed: %s", err)
        except asyncio.CancelledError:
            raise

    def _handle_text(self, raw: str) -> None:
        try:
            msg = json.loads(raw)
        except ValueError:
            return
        header = msg.get("header") or {}
        payload = msg.get("payload") or {}
        name = header.get("name")
        if name not in ("Ping", "Pong"):
            _LOGGER.debug("ws recv: %s", raw[:500])
        message_id = header.get("messageId")
        if name == "EventNotify":
            event = dict(payload)
            event.setdefault("id", message_id)
            if self._on_event:
                try:
                    self._on_event(event)
                except Exception:
                    _LOGGER.exception("event callback failed")
        fut = self._pending.pop(message_id, None)
        if fut is not None and not fut.done():
            error = payload.get("errorCode") or payload.get("error")
            if error:
                fut.set_exception(UsmartError(f"device error: {error}"))
            else:
                fut.set_result(payload)
        elif (
            isinstance(message_id, str)
            and len(message_id) >= 15
            and message_id[14] == "1"
            and payload.get("did")
            and isinstance(payload.get("data"), str)
        ):
            # Server-initiated CtrlResponse echoes use v1 UUIDs and carry
            # short ability reports (e.g. "EAdG" -> cmd 0x1007/RSSI=71).
            data = payload["data"]
            try:
                raw_ability = base64.b64decode(
                    data + "=" * (-len(data) % 4), altchars=b"-_"
                )
            except Exception:
                raw_ability = b""
            if 3 <= len(raw_ability) <= 6 and self._on_event:
                try:
                    self._on_event(
                        {
                            "did": payload["did"],
                            "name": "__ABILITY__",
                            "cmd": int.from_bytes(raw_ability[:2], "big"),
                            "value": int.from_bytes(raw_ability[2:], "big"),
                        }
                    )
                except Exception:
                    _LOGGER.exception("ability callback failed")

    async def request(
        self,
        namespace: str,
        name: str,
        payload: dict[str, Any],
        *,
        header: dict[str, Any] | None = None,
        timeout: float = 30,
    ) -> dict[str, Any]:
        ws = self._ws
        if ws is None or ws.closed:
            raise UsmartError("ws not connected")
        # The server echoes messageId back normalized to a dashed UUID —
        # send it in that form (like the app's uuid.v4()) or responses
        # never match the pending future.
        message_id = str(uuid.uuid4())
        frame: dict[str, Any] = {
            "header": {
                "namespace": namespace,
                "name": name,
                "messageId": message_id,
                "payloadVersion": 1,
                **(header or {}),
            },
        }
        # The app's payload is `undefined` for e.g. Ping — JSON.stringify
        # then omits the key entirely, so mirror that instead of "{}".
        if payload:
            frame["payload"] = payload
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[message_id] = fut
        if name != "Ping":
            _LOGGER.debug("ws send: %s", frame)
        await ws.send_json(frame)
        try:
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(message_id, None)

    async def ctrl(
        self,
        did: str,
        cmd: int,
        data: list[int] | bytes,
        *,
        secure_token: str | None = None,
    ) -> dict[str, Any]:
        """Iot.Device.Ctrl — the channel remote unlock goes over.

        Frame = big-endian cmd + body bytes, base64url in payload.data.
        """
        frame = bytes([cmd >> 8 & 0xFF, cmd & 0xFF]) + bytes(data)
        header = {"secureToken": secure_token} if secure_token else None
        try:
            # The app keeps "=" padding in payload.data — a strict server
            # decoder drops the frame silently, so do the same here.
            return await self.request(
                "Iot.Device",
                "Ctrl",
                {"did": did, "data": _b64url(frame, pad=True)},
                header=header,
            )
        except TimeoutError:
            # No response at all means the request never got routed —
            # the socket is almost certainly dead. Force a reconnect so
            # the next command goes over a fresh connection.
            await self._drop_ws()
            raise

    async def get_devices_ability(
        self, dids: list[str]
    ) -> dict[str, Any]:
        """Iot.Device.GetDevicesAbility — abilities for devices whose
        REST /abilities endpoint is empty (the app picks this path by
        ``YF(pk, product_id)``)."""
        return await self.request(
            "Iot.Device", "GetDevicesAbility", {"dids": dids}, timeout=10
        )

    async def remote_unlock(
        self,
        did: str,
        uid: str,
        *,
        pk: str | None = None,
        unlock: bool = True,
    ) -> dict[str, Any]:
        """Remote unlock/lock, mirroring the app's three code paths.

        - pk falsy          -> plain ``RMUNLK`` (5132):
          body ``[uid_len + 2, flag, uid_len, *uid]`` (the app's selfLock
          path over ``devCtrl``).
        - pk startswith "1002" -> ``CMDCACHE`` (5638) wrapping RMUNLK:
          ``[0, uid_len + 11, 0, 0, 0, flag, 0, uid_len + 5,
          cmd_hi, cmd_lo, uid_len + 2, flag, uid_len, *uid]``.
        - other pk          -> ``DOORPW`` (2063), body ``[flag]``.
        """
        secure_token = await self._client.async_get_secure_token()
        uid_bytes = uid.encode()
        # RMUNLK is an "open pulse", not lock/unlock: the bolt re-locks
        # mechanically. Empirically only flag=0 opens the door — flag=1
        # gets ACKed but does nothing on pk-1002* models.
        flag = 0
        r = len(uid_bytes)
        if not pk:
            cmd, body = CMD_RMUNLK, bytes([r + 2, flag, r]) + uid_bytes
        elif str(pk).startswith("1002"):
            cmd = CMD_CMDCACHE
            body = (
                bytes([0, r + 11, 0, 0, 0, flag, 0, r + 5])
                + bytes([CMD_RMUNLK >> 8 & 0xFF, CMD_RMUNLK & 0xFF])
                + bytes([r + 2, flag, r])
                + uid_bytes
            )
        else:
            cmd, body = CMD_DOORPW, bytes([flag])
        return await self.ctrl(did, cmd, body, secure_token=secure_token)

    async def start_view(self, did: str, uid: str) -> dict[str, Any]:
        """Iot.Device.Ctrl SELFVIEW (5134) — wake the camera stream.

        Body mirrors the app's ``startView`` saga:
        ``[uid_len + 2, 1, uid_len, *uid_utf8]``; the saga dispatches it
        through ``devCtrl`` with ``ignoreVerify`` — no secure token.
        After this the device opens a LIVE stream and an EventNotify
        carrying ``stream_id`` arrives; fetch it via async_get_stream.
        """
        b = uid.encode()
        body = bytes([len(b) + 2, 1, len(b)]) + b
        return await self.ctrl(did, CMD_SELFVIEW, body)
