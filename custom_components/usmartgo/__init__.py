"""The USmart Go (Kiwik) integration."""
from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import UsmartClient, UsmartWs
from .const import (
    CONF_IDENTIFIER,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL_MINUTES,
    DOMAIN,
)
from .coordinator import UsmartCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [
    Platform.LOCK,
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
    Platform.CAMERA,
]


async def async_setup_entry(hass: HomeAssistant, entry) -> bool:
    """Настройка интеграции USmart Go по записи конфигурации."""
    session = async_get_clientsession(hass)

    client = UsmartClient(
        session,
        identifier=entry.data[CONF_IDENTIFIER],
        password=entry.data[CONF_PASSWORD],
    )
    minutes = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL_MINUTES)
    coordinator = UsmartCoordinator(
        hass, client, timedelta(minutes=minutes), entry
    )
    await coordinator.async_config_entry_first_refresh()

    ws = UsmartWs(
        client,
        session,
        on_event=coordinator.apply_ws_event,
        on_connect=lambda: hass.async_create_task(
            coordinator.async_request_refresh()
        ),
    )
    coordinator.ws = ws
    ws.start()
    entry.async_on_unload(ws.close)
    entry.async_on_unload(coordinator.shutdown)

    entry.runtime_data = {"client": client, "coordinator": coordinator, "ws": ws}
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _async_update_listener(hass: HomeAssistant, entry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry) -> bool:
    """Разгрузка интеграции."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
