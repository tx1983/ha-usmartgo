"""Sensors: battery level and the latest lock event."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.const import PERCENTAGE, EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import LOCK_USER_TYPES, UsmartCoordinator
from .entity import UsmartEntity, battery_level, rssi_level

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: UsmartCoordinator = entry.runtime_data["coordinator"]
    entities: list[UsmartEntity] = []
    for did, dev in coordinator.data.get("devices", {}).items():
        if dev.get("type") == "LOCK":
            entities.append(UsmartBatterySensor(coordinator, did))
            entities.append(UsmartLastEventSensor(coordinator, did))
            entities.append(UsmartLastUserSensor(coordinator, did))
            entities.append(UsmartRssiSensor(coordinator, did))
    async_add_entities(entities)


class UsmartBatterySensor(UsmartEntity, SensorEntity):
    """Lock battery percentage (ability BATPWR/BATPRO)."""

    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_translation_key = "battery"

    def __init__(self, coordinator: UsmartCoordinator, did: str) -> None:
        super().__init__(coordinator, did, "battery")

    @property
    def native_value(self) -> int | None:
        return battery_level(self.device)


class UsmartRssiSensor(UsmartEntity, SensorEntity):
    """Wi-Fi signal level (ability RSSI)."""

    _attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "dBm"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_translation_key = "rssi"

    def __init__(self, coordinator: UsmartCoordinator, did: str) -> None:
        super().__init__(coordinator, did, "rssi")

    @property
    def native_value(self) -> int | None:
        return rssi_level(self.device)


class UsmartLastEventSensor(UsmartEntity, SensorEntity):
    """The most recent lock event (name, time, level)."""

    _attr_translation_key = "last_event"

    def __init__(self, coordinator: UsmartCoordinator, did: str) -> None:
        super().__init__(coordinator, did, "last_event")

    @property
    def native_value(self) -> str | None:
        return self.last_event.get("name")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        ev = self.last_event
        return {
            "time": ev.get("time") or ev.get("created_at"),
            "level": ev.get("level"),
            "title": ev.get("title"),
            "event_id": ev.get("id"),
        }


class UsmartLastUserSensor(UsmartEntity, SensorEntity):
    """Who/what unlocked the door last (data.lock_user)."""

    _attr_translation_key = "last_user"

    def __init__(self, coordinator: UsmartCoordinator, did: str) -> None:
        super().__init__(coordinator, did, "last_user")

    @property
    def native_value(self) -> str | None:
        user = self.last_user
        if not user:
            return None
        method = LOCK_USER_TYPES.get(
            user.get("type") or 0, str(user.get("type") or "default")
        )
        alias = user.get("alias")
        return f"{alias} ({method})" if alias else method

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        user = self.last_user
        return {
            "method": LOCK_USER_TYPES.get(
                user.get("type") or 0, str(user.get("type") or "default")
            ),
            "user_id": user.get("user_id"),
            "user_no": user.get("id"),
            "at": user.get("at"),
        }
