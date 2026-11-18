"""Binary sensors: lock connectivity + DOOR_SENSOR devices."""
from __future__ import annotations

import logging

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import UsmartCoordinator
from .entity import UsmartEntity, device_online

_LOGGER = logging.getLogger(__name__)

OPEN_EVENTS = {"OPEN", "DOOR_OPEN", "DOOR_FORCED_OPEN", "DOOR_UNLOCKED"}
CLOSE_EVENTS = {"CLOSE", "CLOSED", "DOOR_CLOSED", "DOOR_LOCKED"}


async def async_setup_entry(
    hass: HomeAssistant, entry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: UsmartCoordinator = entry.runtime_data["coordinator"]
    entities: list[UsmartEntity] = []
    for did, dev in coordinator.data.get("devices", {}).items():
        dtype = dev.get("type")
        if dtype == "LOCK":
            entities.append(UsmartOnlineSensor(coordinator, did))
        elif dtype == "DOOR_SENSOR":
            entities.append(UsmartDoorSensor(coordinator, did))
            entities.append(UsmartOnlineSensor(coordinator, did))
    async_add_entities(entities)


class UsmartOnlineSensor(UsmartEntity, BinarySensorEntity):
    """Device reachable (wifi seen <120 s or ble <60 s ago, as in the app)."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_translation_key = "online"

    def __init__(self, coordinator: UsmartCoordinator, did: str) -> None:
        super().__init__(coordinator, did, "online")

    @property
    def is_on(self) -> bool:
        return device_online(self.device)


class UsmartDoorSensor(UsmartEntity, BinarySensorEntity):
    """DOOR_SENSOR devices — state from the latest event."""

    _attr_device_class = BinarySensorDeviceClass.DOOR
    _attr_translation_key = "door"

    def __init__(self, coordinator: UsmartCoordinator, did: str) -> None:
        super().__init__(coordinator, did, "door")

    @property
    def is_on(self) -> bool | None:
        name = str(self.last_event.get("name") or "")
        if name in OPEN_EVENTS:
            return True
        if name in CLOSE_EVENTS:
            return False
        state = self.device.get("state")
        if state in OPEN_EVENTS:
            return True
        if state in CLOSE_EVENTS:
            return False
        return None
