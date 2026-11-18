# USmart Go for Home Assistant

**Repository:** https://github.com/tx1983/ha-usmartgo

Unofficial [Home Assistant](https://www.home-assistant.io/) integration for Kiwik / USmart Go smart locks with camera. Provides lock state, online/RSSI sensors, unlock-user info, live video, event-triggered recording and doorbell-ring automation hooks.

## Features

One device per lock, with these entities:

| Entity | Description |
|---|---|
| `lock.*` | Lock state. `unlock` requires the PIN from options; `lock` is a safe state refresh (this model has no remote-lock command — the bolt re-extends mechanically ~5 s after opening). |
| `camera.*` | Live MJPEG stream + latest event snapshot. |
| `binary_sensor.*_online` | Device online (ability 2065 / recent comms). |
| `binary_sensor.*_door` | Door contact, when reported. |
| `sensor.*_rssi` | Wi-Fi signal (ability 4103). |
| `sensor.*_battery` | Battery, when the model reports it (unknown otherwise — never faked as 0). |
| `sensor.*_last_event` | Latest lock event name + timestamp. |
| `sensor.*_last_user` | Who unlocked last (alias + method: fingerprint/card/phone/…). |

## Installation

1. Copy `custom_components/usmartgo` into your Home Assistant `config/custom_components/` directory.
2. Restart Home Assistant.

## Configuration

1. `Settings` → `Devices & services` → **Add integration** → search `USmart Go`.
2. Enter the **phone or email** and **password** you use in the USmart Go app.
3. Done — a device appears per lock. Set the unlock PIN and recording options via **Configure** (see below).

## Options (Configure → USmart Go)

| Option | Default | Meaning |
|---|---|---|
| `scan_interval` | 5 min | REST polling interval for abilities/events. |
| `unlock_code` | — | PIN (4–8 digits). **Required** for `lock.unlock`; the service verifies the `code` argument against it. |
| `record_enabled` | on | Record video on `HUMAN_LINGERING` / `REMOTE_UNLOCK`. |
| `record_seconds` | 15 | Capture length for live recordings. |
| `record_cooldown` | 60 s | Minimum gap between recordings per device. |
| `record_keep_days` | 7 | Auto-delete clips older than N days (`0` = keep forever). |

## Device events

Event names pushed by the lock (via WS `EventNotify` / REST `/events`):

- **Ring request:** `REMOTE_UNLOCK` — someone rang the bell; *not* an actual
  unlock.
- **Lingering:** `HUMAN_LINGERING` — a person stands at the door.
- **Locked:** `LOCKED`, `DOOR_LOCKED`, `LOCK_INDOOR_BUTTON_LOCK`,
  `LOCK_INDOOR_LEVER_LOCK`, `LOCK_TIMED_LOCK`, `LOCK_AUTO_LOCKED`,
  `DOOR_LOCK_ARMED`.
- **Unlocked:** `UNLOCKED`, `DOOR_UNLOCKED`, `EMERGENCY_UNLOCK`,
  `LOCK_INDOOR_BUTTON_UNLOCK`, `LOCK_INDOOR_LEVER_UNLOCK`,
  `DOOR_LOCK_UNLOCKED_KNOB`, `ARMED_DOOR_LOCK_UNLOCKED`.
- `ACTIVE_MONITOR` — live-view session started (carries `image_uri` + media
  token).

Note: auto-relocking bolts emit no "locked" event — the lock entity synthesizes
`LOCK_AUTO_LOCKED` ~5 s after an unlock, like the app does.

## Home Assistant bus events (automation triggers)

### `usmartgo_ring` — fired on a doorbell ring

```yaml
trigger.event.data:
  did:       device id
  name:      device name
  event:     "REMOTE_UNLOCK"
  image_url: snapshot URL taken at the ring (https, directly usable in notifications)
```

### `usmartgo_recorded` — fired after a clip is saved

```yaml
trigger.event.data:
  did:   device id
  name:  device name
  path:  /config/www/usmartgo/<did>_<ts>.mp4
  url:   /local/usmartgo/<did>_<ts>.mp4   # browser/app-playable
```

## Automations

### 1. Ring → actionable notification with PIN entry

Paste each block into a separate UI automation in YAML mode.

```yaml
alias: "Doorbell — notify"
trigger:
  - platform: event
    event_type: usmartgo_ring
action:
  - service: notify.mobile_app_YOUR_PHONE
    data:
      title: "Doorbell"
      message: "{{ trigger.event.data.name }}"
      data:
        image: "{{ trigger.event.data.image_url }}"
        actions:
          - action: OPEN_DOOR
            title: "Unlock"
            behavior: "textInput"   # inline reply field — type the PIN
mode: single
```

```yaml
alias: "Doorbell — unlock by PIN"
trigger:
  - platform: event
    event_type: mobile_app_notification_action
    event_data:
      action: OPEN_DOOR
action:
  - service: lock.unlock
    target:
      entity_id: lock.YOUR_LOCK
    data:
      code: "{{ trigger.event.data.reply_text }}"
mode: single
```

A wrong PIN makes `lock.unlock` raise `Invalid unlock code` — append a `notify`
action to get a success confirmation.

### 2. Recording ready → notification with video link

```yaml
alias: "Door clip ready"
trigger:
  - platform: event
    event_type: usmartgo_recorded
action:
  - service: notify.mobile_app_YOUR_PHONE
    data:
      title: "Someone at the door — {{ trigger.event.data.name }}"
      message: "Clip saved"
      data:
        clickAction: "{{ trigger.event.data.url }}"
mode: single
```

Or send the file itself, e.g. `telegram_bot.send_video` with
`file: "{{ trigger.event.data.path }}"` (requires
`allowlist_external_dirs: [/config/www]`).

## Recording storage & archive

- Clips land in `config/www/usmartgo/` (mp4 via ffmpeg, or `.mjpg` fallback) —
  reachable at `/local/usmartgo/<file>` and via any file addon.
  `record_keep_days` auto-prunes old files.
- To browse clips in the **Media** panel, add to `configuration.yaml` and
  restart:

```yaml
homeassistant:
  media_dirs:
    usmartgo: /config/www/usmartgo
```

## Camera stream notes

- One live session per device is enforced server-side — the integration fans a
  single media socket out to all viewers (card + dialog + recorder share it;
  the last viewer closes it).
- Cold start takes ~4–10 s (SELFVIEW → media token → keyframe) — same as the
  native app.
- Framing: `?width=&height=` exact canvas, `?fit=auto|desktop` letterbox,
  `?fit=0|native|mobile|portrait` raw portrait frames. Mobile clients are
  auto-detected and get native portrait.
- Streaming keeps the device awake — avoid leaving a live view open (hard cap
  ~200 s per session, then the frontend reconnects).

## Disclaimer

This is an **unofficial**, community-developed integration. It is not
affiliated with, endorsed by, or supported by Kiwik / USmart Go. Protocol
details were reverse-engineered from the vendor's public web application and
may break without notice if the cloud API changes.

**Use at your own risk.** The authors take no responsibility for any damage or
malfunction — including anything related to remotely unlocking your door.
Test remote-unlock automations carefully, keep the unlock PIN option
protected, and never expose it in scripts or dashboards.

## Support the project

If this integration saves you time, you can
[buy me a coffee](https://pay.cloudtips.ru/p/a039d481).

## License

MIT — see LICENSE.
