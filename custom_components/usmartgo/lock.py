"""Lock entities — remote unlock via the Iot.Device/Ctrl WS channel."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.lock import LockEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .api import UsmartError
from .const import CONF_UNLOCK_CODE, DOMAIN
from .coordinator import (
    LOCK_USER_TYPES,
    LOCKED_EVENTS,
    UNLOCKED_EVENTS,
    UsmartCoordinator,
)
from .entity import UsmartEntity, battery_level, device_online, rssi_level

_LOGGER = logging.getLogger(__name__)

# Events that mark the lock as broken/jammed.
JAMMED_EVENTS = {"LOCK_BROKEN", "DEVICE_ABNORMAL"}


async def async_setup_entry(
    hass: HomeAssistant, entry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: UsmartCoordinator = entry.runtime_data["coordinator"]
    entities = [
        UsmartLock(entry, coordinator, did)
        for did, dev in coordinator.data.get("devices", {}).items()
        if dev.get("type") == "LOCK"
    ]
    async_add_entities(entities)


class UsmartLock(UsmartEntity, LockEntity):
    """A Kiwik smart lock."""

    _attr_name = None  # use the device name as the entity name

    def __init__(self, entry, coordinator: UsmartCoordinator, did: str) -> None:
        super().__init__(coordinator, did, "lock")
        self._entry = entry

    @property
    def is_locked(self) -> bool | None:
        name = str(self.state_event.get("name") or "")
        if name in LOCKED_EVENTS:
            return True
        if name in UNLOCKED_EVENTS:
            return False
        # Fall back to any known state cached in the device object.
        state = self.device.get("state") or self.device.get("lock_state")
        if state in LOCKED_EVENTS:
            return True
        if state in UNLOCKED_EVENTS:
            return False
        return None

    @property
    def is_jammed(self) -> bool:
        return str(self.state_event.get("name") or "") in JAMMED_EVENTS

    @property
    def is_locking(self) -> bool:
        return False

    @property
    def is_unlocking(self) -> bool:
        return False

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        ev = self.last_event
        user = self.last_user
        return {
            "did": self._did,
            "online": device_online(self.device),
            "battery": battery_level(self.device),
            "rssi": rssi_level(self.device),
            "last_event": ev.get("name"),
            "last_event_time": ev.get("time") or ev.get("created_at"),
            "last_event_level": ev.get("level"),
            "last_unlock_user": user.get("alias"),
            "last_unlock_method": LOCK_USER_TYPES.get(
                user.get("type") or 0, str(user.get("type") or "")
            )
            or None,
            "product_id": self.device.get("product_id"),
        }

    @property
    def code_format(self) -> str | None:
        """PIN required for unlock when configured in entry options."""
        if self._entry.options.get(CONF_UNLOCK_CODE):
            return r"^\d{4,8}$"
        return None

    async def async_unlock(self, **kwargs: Any) -> None:
        """Remote unlock: secure token + Iot.Device.Ctrl RMUNLK flag=1."""
        pin = str(self._entry.options.get(CONF_UNLOCK_CODE) or "")
        if not pin:
            raise HomeAssistantError(
                "Remote unlock is disabled: set the unlock PIN in the "
                "integration options"
            )
        if str(kwargs.get("code") or "") != pin:
            raise ServiceValidationError("Invalid unlock code")
        await self._remote(unlock=True)

    async def async_lock(self, **kwargs: Any) -> None:
        """This lock auto-locks itself — there is no remote re-lock, and
        the RMUNLK frame opens the door regardless of the flag byte, so
        sending it from 'Lock' would unlock without a PIN. Just re-sync
        the state: the bolt is driven back by the lock itself."""
        _LOGGER.debug("lock.lock: model auto-locks, refreshing state")
        await self.coordinator.async_request_refresh()

    async def _remote(self, *, unlock: bool) -> None:
        ws = self._entry.runtime_data["ws"]
        client = self._entry.runtime_data["client"]
        uid = client.uid or ""
        pk = self.device.get("pk")
        try:
            await ws.remote_unlock(
                self._did, uid, pk=pk, unlock=unlock
            )
        except (UsmartError, TimeoutError):
            # Some firmwares only accept RMUNLK when a secure token was
            # just issued; retry once after a fresh one.
            _LOGGER.debug("remote op failed, retrying with fresh token")
            await ws.remote_unlock(
                self._did, uid, pk=pk, unlock=unlock
            )
        await self.coordinator.async_request_refresh()

    @callback
    def _handle_coordinator_update(self) -> None:
        self.async_write_ha_state()
