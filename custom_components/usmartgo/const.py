"""Constants for the USmart Go (Kiwik, com.kiwik.usmartgo) integration."""

DOMAIN = "usmartgo"

CONF_IDENTIFIER = "identifier"
CONF_PASSWORD = "password"

CONF_SCAN_INTERVAL = "scan_interval"
CONF_UNLOCK_CODE = "unlock_code"
MIN_SCAN_INTERVAL_MINUTES = 1
DEFAULT_SCAN_INTERVAL_MINUTES = 5

# Event-triggered recording (HUMAN_LINGERING, REMOTE_UNLOCK ring): clips
# are written to config/www/usmartgo/ and served at /local/usmartgo/ so
# the notification link works in the companion app too.
CONF_RECORD_ENABLED = "record_enabled"
CONF_RECORD_SECONDS = "record_seconds"
CONF_RECORD_COOLDOWN = "record_cooldown"
CONF_RECORD_KEEP_DAYS = "record_keep_days"
DEFAULT_RECORD_SECONDS = 15
DEFAULT_RECORD_COOLDOWN = 60
DEFAULT_RECORD_KEEP_DAYS = 7

# Live/snapshot canvas bounds — portrait frames are letterboxed to
# ~16:9 so the tall stream fits the camera dialog (override via the
# stream URL: ?width=&height= for an exact box, ?fit=0 to disable).
CAMERA_CANVAS_MAX_W = 1136
CAMERA_CANVAS_MAX_H = 640
# Hard cap for a single viewer session — monitoring lasts ~180s in
# the app (restSeconds), keep a small margin. Bounds battery drain
# if a frontend connection ever lingers.
CAMERA_STREAM_MAX_SECONDS = 200.0
