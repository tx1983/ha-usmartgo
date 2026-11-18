"""Shared entity plumbing for USmart Go devices."""
from __future__ import annotations

import time
from typing import Any

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import (
    CMD_BATPRO,
    CMD_BATPWR,
    CMD_BLETIME,
    CMD_LOWPWR,
    CMD_RSSI,
    CMD_WIFITIME,
)
from .const import DOMAIN
from .coordinator import UsmartCoordinator


def ability_status(device: dict[str, Any], cmd: int, default: Any = 0) -> Any:
    """Mirror of the app's ``_o`` helper: ability[cmd].status or dev[cmd].status."""
    if not device:
        return default
    if device.get("ability"):
        node = device["ability"].get(str(cmd)) or device["ability"].get(cmd)
    else:
        node = device.get(str(cmd)) or device.get(cmd)
    if isinstance(node, dict):
        return node.get("status", default)
    return node if node is not None else default


def ability_updated_at(device: dict[str, Any], cmd: int) -> float:
    if not device:
        return 0
    if device.get("ability"):
        node = device["ability"].get(str(cmd)) or device["ability"].get(cmd)
    else:
        node = device.get(str(cmd)) or device.get(cmd)
    if isinstance(node, dict):
        try:
            return float(node.get("updated_at") or 0)
        except (TypeError, ValueError):
            return 0
    return 0


def device_online(device: dict[str, Any]) -> bool:
    """Same heuristic as the app: wifi seen <120 s ago or ble <60 s ago."""
    if device.get("online") is True:
        return True
    now = time.time()
    wifi = ability_status(device, CMD_WIFITIME) or 0
    ble = ability_status(device, CMD_BLETIME) or 0
    lowpwr = int(ability_status(device, CMD_LOWPWR) or 0)
    wifi_ok = (lowpwr >> 24 & 1) == 1 and (lowpwr >> 8 & 0xFFFF) == 0
    try:
        if wifi_ok and wifi and now - float(wifi) < 120:
            return True
        if ble and now - float(ble) < 60:
            return True
        # No heartbeat timestamps on this model — fall back to "the
        # cloud relay heard from it recently" (ability response, event).
        last_seen = device.get("last_seen")
        if last_seen and now - float(last_seen) < 600:
            return True
    except (TypeError, ValueError):
        pass
    return False


class UsmartEntity(CoordinatorEntity[UsmartCoordinator]):
    """Base class: one entity bound to one device id."""

    _attr_has_entity_name = True

    def __init__(
        self, coordinator: UsmartCoordinator, did: str, suffix: str
    ) -> None:
        super().__init__(coordinator)
        self._did = did
        self._attr_unique_id = f"{DOMAIN}_{did}_{suffix}"

    @property
    def device(self) -> dict[str, Any]:
        return (self.coordinator.data or {}).get("devices", {}).get(
            self._did, {}
        )

    @property
    def last_event(self) -> dict[str, Any]:
        return (self.coordinator.data or {}).get("events", {}).get(
            self._did, {}
        )

    @property
    def state_event(self) -> dict[str, Any]:
        """Latest event that carries a lock state — media/monitor
        events don't overwrite it. No fallback to ``last_event``: a
        monitor/alert record is not a lock state."""
        return (self.coordinator.data or {}).get("state", {}).get(
            self._did, {}
        )

    @property
    def last_user(self) -> dict[str, Any]:
        """The last lock_user seen on an unlock-ish event."""
        return (self.coordinator.data or {}).get("users", {}).get(
            self._did, {}
        )

    @property
    def device_info(self) -> DeviceInfo:
        dev = self.device
        return DeviceInfo(
            identifiers={(DOMAIN, self._did)},
            name=dev.get("name") or f"USmart {self._did}",
            manufacturer="Kiwik",
            model=str(dev.get("product_id") or dev.get("type") or ""),
            serial_number=self._did,
        )

    @property
    def available(self) -> bool:
        return super().available and bool(self.device)


def battery_level(device: dict[str, Any]) -> int | None:
    # Models that report BATPWR/BATPRO get a percent; the app shows no
    # battery at all for the rest (ELEQNT* values are slot counters,
    # not charge) — stay honest and return None.
    for cmd in (CMD_BATPWR, CMD_BATPRO):
        try:
            val = int(ability_status(device, cmd, None))
        except (TypeError, ValueError):
            continue
        if 0 <= val <= 100:
            return val
    return None


def rssi_level(device: dict[str, Any]) -> int | None:
    try:
        val = int(ability_status(device, CMD_RSSI, None))
    except (TypeError, ValueError):
        return None
    return val if val != 0 else None
