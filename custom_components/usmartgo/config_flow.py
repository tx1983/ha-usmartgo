"""Config flow: identifier (phone/email) + password for USmart Go."""
from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .api import UsmartAuthError, UsmartClient
from .const import (
    CONF_IDENTIFIER,
    CONF_PASSWORD,
    CONF_RECORD_COOLDOWN,
    CONF_RECORD_ENABLED,
    CONF_RECORD_KEEP_DAYS,
    CONF_RECORD_SECONDS,
    CONF_SCAN_INTERVAL,
    CONF_UNLOCK_CODE,
    DEFAULT_RECORD_COOLDOWN,
    DEFAULT_RECORD_KEEP_DAYS,
    DEFAULT_RECORD_SECONDS,
    DEFAULT_SCAN_INTERVAL_MINUTES,
    DOMAIN,
    MIN_SCAN_INTERVAL_MINUTES,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_IDENTIFIER): str,
        vol.Required(CONF_PASSWORD): TextSelector(
            TextSelectorConfig(type=TextSelectorType.PASSWORD)
        ),
    }
)

_SCAN_INTERVAL_SELECTOR = NumberSelector(
    NumberSelectorConfig(
        min=MIN_SCAN_INTERVAL_MINUTES,
        max=60,
        step=1,
        unit_of_measurement="min",
        mode=NumberSelectorMode.BOX,
    )
)

_RECORD_SECONDS_SELECTOR = NumberSelector(
    NumberSelectorConfig(
        min=5,
        max=120,
        step=1,
        unit_of_measurement="s",
        mode=NumberSelectorMode.BOX,
    )
)

_RECORD_COOLDOWN_SELECTOR = NumberSelector(
    NumberSelectorConfig(
        min=0,
        max=600,
        step=5,
        unit_of_measurement="s",
        mode=NumberSelectorMode.BOX,
    )
)

_RECORD_KEEP_DAYS_SELECTOR = NumberSelector(
    NumberSelectorConfig(
        min=0,
        max=365,
        step=1,
        unit_of_measurement="d",
        mode=NumberSelectorMode.BOX,
    )
)


class UsmartConfigFlow(ConfigFlow, domain=DOMAIN):
    """Config Flow для интеграции USmart Go."""

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> UsmartOptionsFlow:
        return UsmartOptionsFlow()

    async def _validate(
        self, identifier: str, password: str
    ) -> tuple[dict[str, Any] | None, str | None]:
        session = async_get_clientsession(self.hass)
        try:
            client = UsmartClient(session, identifier, password)
            profile = await client.async_login()
        except UsmartAuthError:
            return None, "invalid_auth"
        except Exception as err:
            _LOGGER.debug("Validation failed: %s", err)
            return None, "cannot_connect"
        return profile, None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            identifier = user_input[CONF_IDENTIFIER].strip()
            password = user_input[CONF_PASSWORD]
            profile, error = await self._validate(identifier, password)
            if error:
                errors["base"] = error
            else:
                uid = str((profile or {}).get("uid") or identifier.lower())
                await self.async_set_unique_id(uid)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=f"USmart Go {identifier}",
                    data={
                        CONF_IDENTIFIER: identifier,
                        CONF_PASSWORD: password,
                    },
                )
        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_SCHEMA, errors=errors
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            identifier = entry.data[CONF_IDENTIFIER]
            password = user_input[CONF_PASSWORD]
            _, error = await self._validate(identifier, password)
            if error:
                errors["base"] = error
            else:
                return self.async_update_reload_and_abort(
                    entry, data={**entry.data, CONF_PASSWORD: password}
                )
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_PASSWORD): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.PASSWORD)
                    )
                }
            ),
            errors=errors,
        )


class UsmartOptionsFlow(OptionsFlow):
    """Options: только интервал опроса."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(data=user_input)
        options = self.config_entry.options
        current = options.get(
            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL_MINUTES
        )
        code = options.get(CONF_UNLOCK_CODE, "")
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_SCAN_INTERVAL, default=current
                    ): _SCAN_INTERVAL_SELECTOR,
                    vol.Optional(
                        CONF_UNLOCK_CODE, default=code
                    ): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.PASSWORD)
                    ),
                    vol.Optional(
                        CONF_RECORD_ENABLED,
                        default=options.get(CONF_RECORD_ENABLED, True),
                    ): bool,
                    vol.Optional(
                        CONF_RECORD_SECONDS,
                        default=options.get(
                            CONF_RECORD_SECONDS, DEFAULT_RECORD_SECONDS
                        ),
                    ): _RECORD_SECONDS_SELECTOR,
                    vol.Optional(
                        CONF_RECORD_COOLDOWN,
                        default=options.get(
                            CONF_RECORD_COOLDOWN,
                            DEFAULT_RECORD_COOLDOWN,
                        ),
                    ): _RECORD_COOLDOWN_SELECTOR,
                    vol.Optional(
                        CONF_RECORD_KEEP_DAYS,
                        default=options.get(
                            CONF_RECORD_KEEP_DAYS,
                            DEFAULT_RECORD_KEEP_DAYS,
                        ),
                    ): _RECORD_KEEP_DAYS_SELECTOR,
                }
            ),
        )
