"""
Nostr platform adapter (NIP-17 private DMs) built on nostr-sdk.

Inbound:  kind 1059 gift wraps → UnwrappedGift.from_gift_wrap → handle_message()
Outbound: send() → Client.send_private_msg() (handles seal/wrap/publish)

Also publishes Kind 0 profile metadata and a Kind 10050 NIP-17 DM inbox list
on connect so compliant senders know where to reach the bot.

Required env vars:
  NOSTR_PRIVATE_KEY   Bot's private key (64-char hex or nsec bech32)
  NOSTR_RELAYS        Comma-separated wss:// relay URLs (≥1 required)

Optional env vars:
  NOSTR_ALLOWED_NPUBS    Comma-separated npub/hex pubkeys (* = allow all; empty = deny all)
  NOSTR_HOME_CHANNEL     Owner's npub or hex pubkey — default recipient for cron delivery
  NOSTR_BOT_NAME         Kind 0 name field (default: bot's npub)
  NOSTR_BOT_ABOUT        Kind 0 about field
  NOSTR_BOT_PICTURE      Kind 0 picture URL
  NOSTR_NIP05            NIP-05 identifier (user@domain.com)
  NOSTR_LUD16            Lightning address for zaps (user@domain.com)
  NOSTR_BOT_WEBSITE      NIP-24 website field
  NOSTR_EXPIRATION_MINUTES  NIP-40 TTL for outbound DMs (default: 10080 = 7 days)
  NOSTR_SEEN_MAX         Dedup cache size (default: 1000)
  NOSTR_LOOKBACK_MINUTES Subscription replay window (default: 2880 = 48h, NIP-59 minimum)
"""

import asyncio
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Set
from urllib.parse import urlparse

try:
    from nostr_sdk import (
        Client,
        EventBuilder,
        Filter,
        HandleNotification,
        Keys,
        Kind,
        KindStandard,
        Metadata,
        NostrSigner,
        PublicKey,
        RelayStatus,
        RelayUrl,
        Tag,
        Timestamp,
        UnwrappedGift,
    )
    _NOSTR_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover
    _NOSTR_SDK_AVAILABLE = False
    HandleNotification = object  # type: ignore[assignment,misc]

from gateway.config import Platform, PlatformConfig

# Register the dynamic ``nostr`` enum member at import time.  The enum's
# ``_missing_`` hook caches the pseudo-member in both ``_value2member_map_``
# and ``_member_map_``, so after this call ``Platform.NOSTR`` resolves via
# attribute access too.  As a bundled plugin under ``plugins/platforms/nostr/``
# nostr no longer has a hardcoded ``Platform`` enum member — it earns the
# attribute by asking for it once (mirrors plugins/platforms/google_chat/).
Platform("nostr")

from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
)

# Pin the logger name to the legacy module path so operator log filters, grep
# aliases, and the gateway's bundled log views keep matching after the in-tree
# → plugin migration (``__name__`` becomes the plugin loader namespace).
logger = logging.getLogger("gateway.platforms.nostr")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NIP40_TTL_SECONDS = 7 * 24 * 3600  # 1 week default
# NIP-59 created_at obfuscation window.
NIP59_MIN_LOOKBACK_MINUTES = 2880

# Watchdog tuning.  The notification loop is a Rust task we can't introspect,
# so we poll observable health every TICK seconds and bounce the client if
# either the task died or the relay pool reports zero connectable members.
WATCHDOG_TICK_SECONDS = 60.0
# Initial fast-retry ramp on a freshly-detected failure: most blips clear in
# under a minute, so try those quickly before settling into a slower cadence.
# Floor of 5s keeps us out of the TIME_WAIT danger zone (~60s on macOS) for
# outbound TCP — we never reopen a tuple faster than the OS can recycle it.
WATCHDOG_RECOVERY_DELAYS_INITIAL = (5.0, 15.0, 45.0)
# Steady-state retry cadence after the initial ramp.  We retry indefinitely
# (matching every other persistent-loop adapter in this codebase — see
# yuanbao.py / signal.py / matrix.py / mattermost.py) rather than capitulating,
# so a long network outage self-heals once connectivity returns.  At 90s
# cadence × N relays the steady-state TIME_WAIT footprint is ~(N * 60 / 90)
# sockets, well below any kernel limit.
WATCHDOG_RECOVERY_DELAY_STEADY = 90.0
# Re-subscribe lookback on recovery.  Much shorter than NIP59_MIN_LOOKBACK
# (used on initial connect) because a recovery cycle is a blip — we only
# need to catch events that arrived during the outage, not replay 48h.
WATCHDOG_RECOVERY_LOOKBACK_SECONDS = 600
# Settle delay between disconnect() and connect() during a recovery cycle —
# lets the Rust pool finish closing sockets before we ask it to open new ones.
WATCHDOG_RECONNECT_SETTLE_SECONDS = 1.0


# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------

def check_nostr_requirements() -> bool:
    """Return True if all required packages are available."""
    if not _NOSTR_SDK_AVAILABLE:
        logger.error("Nostr: 'nostr-sdk' is required. Install with: pip install 'hermes-agent[nostr]'")
        return False
    return True


def parse_pubkey(value: str):
    """Parse npub bech32 or 64-char hex into a PublicKey, or None if invalid."""
    if not _NOSTR_SDK_AVAILABLE:
        return None
    try:
        return PublicKey.parse((value or "").strip())
    except Exception:
        return None


def parse_relay_url(value: str) -> Optional[str]:
    """Canonicalize a relay URL.  Returns a wss:// URL or None if invalid.

    Bare hostnames get `wss://` prepended; anything that resolves to a non-wss
    scheme is rejected.
    """
    url = (value or "").strip()
    if not url:
        return None
    if "://" not in url:
        url = "wss://" + url
    if url.startswith("wss://") and len(url) > len("wss://"):
        return url
    return None


# Identifier of the form `local-part@domain.tld`.  NIP-05 and LUD-16 share
# this shape (NIP-05 restricts to lowercase ASCII; LUD-16 follows the same
# convention).  We accept the broader RFC-style local-part and just require
# the domain to contain a dot.
_IDENT_RE = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def is_valid_local_at_domain(value: str) -> bool:
    return bool(_IDENT_RE.match(value or ""))


def is_valid_http_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except Exception:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class NostrAdapter(BasePlatformAdapter, HandleNotification):
    """Nostr DM adapter using NIP-17 private direct messages."""

    platform = Platform.NOSTR

    # Conservative cap. Relays accept much larger events, but the NIP-17 gift-wrap
    # adds overhead and most Nostr clients render long DMs poorly.
    MAX_MESSAGE_LENGTH = 4096

    # Tool-initiated sends (send_message_tool.py) reuse the gateway's connected
    # adapter instead of spinning up a short-lived one that republishes profile
    # and relay-list metadata on every call. Mirrors YuanbaoAdapter's pattern.
    _active_instance: ClassVar[Optional["NostrAdapter"]] = None

    @classmethod
    def get_active(cls) -> Optional["NostrAdapter"]:
        """Return the currently connected NostrAdapter, or None."""
        return cls._active_instance

    @classmethod
    def set_active(cls, adapter: Optional["NostrAdapter"]) -> None:
        """Register (or clear) the active adapter instance."""
        cls._active_instance = adapter

    def __init__(self, config: PlatformConfig) -> None:
        super().__init__(config, Platform.NOSTR)

        # Private key & derived pubkey (Keys.parse accepts nsec or hex).
        # As a plugin the adapter is constructed leniently — the registry's
        # conformance probe and env-only setups may build it before config is
        # populated — so we do NOT raise on a missing/invalid key or absent SDK
        # here; connect() performs deferred validation and fails cleanly. The
        # env fallback mirrors MatrixAdapter: the generic plugin-enable loop in
        # gateway/config.py seeds extra/home_channel but not ``token``.
        raw_key = (config.token or os.getenv("NOSTR_PRIVATE_KEY", "") or "").strip()
        self._keys: Optional["Keys"] = None
        self._signer: Optional["NostrSigner"] = None
        self._pubkey_hex: str = ""
        self._npub: str = ""
        if raw_key and _NOSTR_SDK_AVAILABLE:
            try:
                self._keys = Keys.parse(raw_key)
                self._signer = NostrSigner.keys(self._keys)
                self._pubkey_hex = self._keys.public_key().to_hex()
                self._npub = self._keys.public_key().to_bech32()
            except Exception:
                logger.warning(
                    "Nostr: could not parse NOSTR_PRIVATE_KEY — expected an "
                    "nsec1... bech32 string or 64-char hex; connect() will fail"
                )

        # Relay list (≥1 required; only wss:// accepted). Env fallback mirrors
        # the key handling above; connect() enforces the ≥1 requirement so a
        # leniently-constructed adapter doesn't raise at build time.
        relay_str = config.extra.get("relays") or os.getenv("NOSTR_RELAYS", "") or ""
        self._relay_urls: List[str] = []
        for raw in relay_str.split(","):
            canonical = parse_relay_url(raw)
            if canonical:
                self._relay_urls.append(canonical)
            elif raw.strip():
                logger.warning("Nostr: relay %r rejected — only wss:// is supported", raw.strip())

        self._bot_name: str = config.extra.get("name") or self._npub
        self._bot_about: str = config.extra.get("about", "")
        self._bot_picture: str = self._validated(
            "NOSTR_BOT_PICTURE", config.extra.get("picture", ""), is_valid_http_url, "http(s) URL"
        )
        self._nip05: str = self._validated(
            "NOSTR_NIP05", config.extra.get("nip05", ""), is_valid_local_at_domain, "local@domain identifier"
        )
        self._lud16: str = self._validated(
            "NOSTR_LUD16", config.extra.get("lud16", ""), is_valid_local_at_domain, "local@domain Lightning address"
        )
        self._bot_website: str = self._validated(
            "NOSTR_BOT_WEBSITE", config.extra.get("website", ""), is_valid_http_url, "http(s) URL"
        )

        # NIP-40 expiration (configurable in minutes)
        try:
            _minutes = int(config.extra.get("expiration_minutes", NIP40_TTL_SECONDS // 60))
            if _minutes < 1:
                raise ValueError
        except (ValueError, TypeError):
            logger.warning(
                "Nostr: invalid NOSTR_EXPIRATION_MINUTES, using default %d min",
                NIP40_TTL_SECONDS // 60,
            )
            _minutes = NIP40_TTL_SECONDS // 60
        self._nip40_ttl_seconds: int = _minutes * 60

        # Allowlist: empty = deny all; * = allow all; otherwise explicit npub/hex list.
        # NOSTR_ALLOW_ALL_USERS=true is honored as a synonym for NOSTR_ALLOWED_NPUBS=*
        # so the cross-platform <PLATFORM>_ALLOW_ALL_USERS convention (see
        # gateway/run.py:_is_user_authorized) actually opens the adapter gate too;
        # without this an operator who set only the boolean would still be denied
        # at message-handling time because the gateway gate is downstream of the
        # adapter's _process_event allowlist check.
        allowed_raw = os.getenv("NOSTR_ALLOWED_NPUBS", "").strip()
        allow_all_flag = os.getenv("NOSTR_ALLOW_ALL_USERS", "").strip().lower() in {"true", "1", "yes"}
        self._allow_all_npubs: bool = allow_all_flag or (allowed_raw == "*")
        self._allowed_pubkeys: Set[str] = set()
        if not self._allow_all_npubs and allowed_raw:
            for entry in allowed_raw.split(","):
                entry = entry.strip()
                if not entry:
                    continue
                pk = parse_pubkey(entry)
                if pk is None:
                    logger.warning("Nostr: could not parse allowed npub '%s', skipping", entry)
                else:
                    self._allowed_pubkeys.add(pk.to_hex())

        # Configurable dedup window size
        try:
            self._seen_max: int = max(1, int(os.getenv("NOSTR_SEEN_MAX", "1000")))
        except (ValueError, TypeError):
            logger.warning("Nostr: invalid NOSTR_SEEN_MAX, using default 1000")
            self._seen_max = 1000

        # Subscription lookback in minutes; caps relay replay on (re)subscribe.
        # Defaults to NIP-59's 48h obfuscation window.
        try:
            _lookback = int(config.extra.get("lookback_minutes", NIP59_MIN_LOOKBACK_MINUTES))
            if _lookback < 1:
                raise ValueError
        except (ValueError, TypeError):
            logger.warning(
                "Nostr: invalid NOSTR_LOOKBACK_MINUTES, using default %d",
                NIP59_MIN_LOOKBACK_MINUTES,
            )
            _lookback = NIP59_MIN_LOOKBACK_MINUTES
        if _lookback < NIP59_MIN_LOOKBACK_MINUTES:
            logger.warning(
                "Nostr: NOSTR_LOOKBACK_MINUTES=%d is below NIP-59's 48h timestamp obfuscation window — DMs whose created_at was randomized further back may be missed",
                _lookback,
            )
        self._lookback_seconds: int = _lookback * 60

        # Dedup state (persisted across restarts).  _seen_event_list preserves
        # insertion order for the rolling window; _seen_event_ids is the
        # fast-lookup index.  Persisted to ~/.hermes/nostr_seen_<pubkey>.json.
        self._seen_event_list: List[str] = []
        self._seen_event_ids: Set[str] = set()

        # Internal state
        self._client: Optional[Client] = None
        self._notif_task: Optional[asyncio.Task] = None
        self._watchdog_task: Optional[asyncio.Task] = None
        # Held during a recovery cycle so successive watchdog ticks (or an
        # operator-initiated disconnect) don't race overlapping reconnects.
        self._recovery_lock: asyncio.Lock = asyncio.Lock()
        # Instance-level mirrors of the watchdog constants so tests can shrink
        # the tick interval / delays without touching module state.
        self._watchdog_tick_seconds: float = WATCHDOG_TICK_SECONDS
        self._watchdog_recovery_delays_initial: tuple = WATCHDOG_RECOVERY_DELAYS_INITIAL
        self._watchdog_recovery_delay_steady: float = WATCHDOG_RECOVERY_DELAY_STEADY
        self._watchdog_reconnect_settle_seconds: float = WATCHDOG_RECONNECT_SETTLE_SECONDS
        self._watchdog_recovery_lookback_seconds: int = WATCHDOG_RECOVERY_LOOKBACK_SECONDS
        self._running: bool = False

        logger.info(
            "Nostr adapter: npub=%s relays=%s allowlist=%s",
            self._npub,
            len(self._relay_urls),
            "open (*)" if self._allow_all_npubs else (f"{len(self._allowed_pubkeys)} npubs" if self._allowed_pubkeys else "deny all"),
        )

    @staticmethod
    def _validated(env_name: str, value: str, predicate, expected_form: str) -> str:
        """Return value if it passes predicate; warn and drop otherwise."""
        if not value:
            return ""
        if predicate(value):
            return value
        logger.warning(
            "Nostr: %s=%r is not a valid %s — omitting from kind 0 profile",
            env_name, value, expected_form,
        )
        return ""

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> bool:
        # Deferred validation: __init__ is lenient (so the plugin registry and
        # env-only setups can construct the adapter); connect() is where missing
        # prerequisites become a clean, non-retryable failure.
        if not _NOSTR_SDK_AVAILABLE:
            self._set_fatal_error(
                "nostr_missing_dependency",
                "Nostr: nostr-sdk not installed. Run: pip install 'hermes-agent[nostr]'",
                retryable=False,
            )
            return False
        if self._keys is None:
            self._set_fatal_error(
                "nostr_missing_credentials",
                "Nostr: NOSTR_PRIVATE_KEY is required (nsec bech32 or 64-char hex)",
                retryable=False,
            )
            return False
        if not self._relay_urls:
            self._set_fatal_error(
                "nostr_missing_relays",
                "Nostr: NOSTR_RELAYS must contain at least one wss:// URL",
                retryable=False,
            )
            return False

        # Guard against two gateway instances driving the same Nostr identity:
        # that would double-process inbound gift wraps, double-send outbound
        # DMs, and corrupt the pubkey-scoped dedup file (non-atomic writes from
        # two processes). Mirrors yuanbao/whatsapp/telegram. On contention this
        # records a non-retryable fatal error and returns False; the lock is
        # released in disconnect() (which the gateway always calls on failure).
        if not self._acquire_platform_lock(
            "nostr-pubkey", self._pubkey_hex, "Nostr identity"
        ):
            return False

        self._load_seen_ids()
        self._client = Client(self._signer)

        added = 0
        for url in self._relay_urls:
            try:
                await self._client.add_relay(RelayUrl.parse(url))
                added += 1
            except Exception as exc:
                logger.warning("Nostr: could not add relay %s: %s", url, exc)
        if added == 0:
            logger.error(
                "Nostr: no relays could be added (tried %d) — refusing to "
                "connect; the bot would be deaf and mute",
                len(self._relay_urls),
            )
            self._client = None
            self._release_platform_lock()
            return False

        await self._client.connect()
        logger.info("Nostr: connected to %d/%d relay(s)", added, len(self._relay_urls))

        self._mark_connected()

        # Publish Kind 0 profile and Kind 10050 DM inbox list
        try:
            await self._publish_profile()
        except Exception:
            logger.exception("Nostr: failed to publish kind 0 profile")
        try:
            await self._publish_relay_list()
        except Exception:
            logger.exception("Nostr: failed to publish kind 10050 relay list")

        # Subscribe to gift wraps tagged with our pubkey, capped by lookback
        bot_pk = self._keys.public_key()
        since_ts = Timestamp.from_secs(max(0, int(time.time()) - self._lookback_seconds))
        f = (
            Filter()
            .pubkey(bot_pk)
            .kind(Kind.from_std(KindStandard.GIFT_WRAP))
            .since(since_ts)
        )
        await self._client.subscribe(f)

        # Run the event handler loop
        self._notif_task = asyncio.create_task(self._client.handle_notifications(self))

        # Supervise the notification loop.  Started after the loop so a
        # never-started loop is never "unhealthy".
        self._watchdog_task = asyncio.create_task(self._watchdog_loop())

        NostrAdapter.set_active(self)

        logger.info("Nostr: connected (npub=%s, relays=%d)", self._npub, added)
        return True

    async def disconnect(self) -> None:
        # Order matters: stop the watchdog first so it can't start a recovery
        # cycle while we are tearing the client down.  The notif task and the
        # client follow, mirroring connect()'s construction order in reverse.
        self._mark_disconnected()
        if self._watchdog_task:
            self._watchdog_task.cancel()
            try:
                await self._watchdog_task
            except (asyncio.CancelledError, Exception):
                pass
            self._watchdog_task = None
        if self._notif_task:
            self._notif_task.cancel()
            try:
                await self._notif_task
            except asyncio.CancelledError:
                pass
            self._notif_task = None
        if self._client:
            try:
                await self._client.disconnect()
            except Exception:
                pass
            self._client = None
        if NostrAdapter._active_instance is self:
            NostrAdapter.set_active(None)
        self._release_platform_lock()
        logger.info("Nostr: disconnected")

    # ------------------------------------------------------------------
    # Watchdog — supervises the Rust-side notification loop
    # ------------------------------------------------------------------

    # Relay statuses we treat as "the pool is still trying to deliver".
    # DISCONNECTED/BANNED/TERMINATED are terminal; SLEEPING is between retry
    # attempts (the SDK wakes it on its own) so we count it as alive.
    _CONNECTABLE_RELAY_STATUSES = (
        ("CONNECTED", "CONNECTING", "PENDING", "INITIALIZED", "SLEEPING")
        if not _NOSTR_SDK_AVAILABLE
        else (
            RelayStatus.CONNECTED,
            RelayStatus.CONNECTING,
            RelayStatus.PENDING,
            RelayStatus.INITIALIZED,
            RelayStatus.SLEEPING,
        )
    )

    async def _is_loop_healthy(self) -> bool:
        """True when the notif task is alive and ≥1 relay is in a connectable state.

        Returns False on any inspection error — callers treat that as
        "ambiguously unhealthy" and the watchdog logs+skips that tick rather
        than triggering recovery off a transient SDK glitch.
        """
        if not self._client:
            return False
        task = self._notif_task
        if task is None or task.done():
            return False
        relays = await self._client.relays()
        if not relays:
            return False
        for relay in relays.values():
            try:
                if relay.status() in self._CONNECTABLE_RELAY_STATUSES:
                    return True
            except Exception:
                continue
        return False

    async def _watchdog_loop(self) -> None:
        """Poll loop health every tick; trigger recovery on degradation.

        On recovery failure we do NOT capitulate — _attempt_recovery loops
        until either the loop is healthy again or _running goes False.  This
        matches every other persistent-loop adapter in this codebase
        (signal.py, yuanbao.py, matrix.py, mattermost.py): a long network
        outage self-heals once connectivity returns instead of permanently
        silencing the bot.
        """
        try:
            while self._running:
                try:
                    await asyncio.sleep(self._watchdog_tick_seconds)
                except asyncio.CancelledError:
                    raise
                if not self._running:
                    return
                try:
                    healthy = await self._is_loop_healthy()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception(
                        "Nostr watchdog: health check raised; skipping this tick"
                    )
                    continue
                if healthy:
                    continue
                logger.warning(
                    "Nostr watchdog: notification loop unhealthy — attempting recovery"
                )
                try:
                    await self._attempt_recovery()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("Nostr watchdog: recovery raised unexpectedly")
                    # Don't break — next tick will try again.
        except asyncio.CancelledError:
            raise

    async def _attempt_recovery(self) -> None:
        """Soft-reconnect until healthy or disconnect() is called.

        Uses the initial fast-ramp delays for the first few attempts, then
        falls back to the steady-state cadence forever.  The cadence resets
        the next time the watchdog observes a transition from healthy →
        unhealthy (a fresh failure event), so each new outage gets the fast
        ramp; we don't punish a transient blip after a long uptime.
        """
        async with self._recovery_lock:
            initial = self._watchdog_recovery_delays_initial
            steady = self._watchdog_recovery_delay_steady
            attempt = 0
            while self._running:
                attempt += 1
                delay = initial[attempt - 1] if attempt <= len(initial) else steady
                logger.info(
                    "Nostr watchdog: recovery attempt %d (delay %.1fs)",
                    attempt, delay,
                )
                try:
                    await asyncio.sleep(delay)
                except asyncio.CancelledError:
                    return
                if not self._running:
                    return
                try:
                    await self._soft_reconnect_cycle()
                except asyncio.CancelledError:
                    return
                except Exception:
                    logger.exception(
                        "Nostr watchdog: reconnect cycle %d raised", attempt
                    )
                    continue
                try:
                    if await self._is_loop_healthy():
                        logger.info(
                            "Nostr watchdog: recovery succeeded on attempt %d",
                            attempt,
                        )
                        return
                except Exception:
                    logger.exception(
                        "Nostr watchdog: post-recovery health check raised on attempt %d",
                        attempt,
                    )

    async def _soft_reconnect_cycle(self) -> None:
        """Cancel notif task → disconnect client → settle → reconnect → re-subscribe → restart loop.

        Does NOT re-publish Kind 0 / Kind 10050 — relays already hold those
        events and a reconnect storm must not fan out duplicate metadata.
        Re-subscribe uses a short lookback (10 min) instead of the full
        NIP-59 48h window: we only need to backfill what arrived during the
        outage, not replay history dedup will silently drop anyway.
        """
        # Cancel and reap the old loop task so it can't race the new one on
        # handle()/_process_event mutations of _seen_event_ids.
        if self._notif_task and not self._notif_task.done():
            self._notif_task.cancel()
            try:
                await self._notif_task
            except (asyncio.CancelledError, Exception):
                pass
        self._notif_task = None
        # Tear down the existing client cleanly so the Rust pool drops its
        # sockets before we ask it to open new ones.
        if self._client:
            try:
                await self._client.disconnect()
            except Exception:
                pass
        # Settle: lets the OS move closed sockets toward TIME_WAIT before
        # reuse, and gives the Rust pool a moment to finish teardown.
        try:
            await asyncio.sleep(self._watchdog_reconnect_settle_seconds)
        except asyncio.CancelledError:
            raise
        if not self._client or not self._running:
            return
        await self._client.connect()
        bot_pk = self._keys.public_key()
        since_ts = Timestamp.from_secs(
            max(0, int(time.time()) - self._watchdog_recovery_lookback_seconds)
        )
        f = (
            Filter()
            .pubkey(bot_pk)
            .kind(Kind.from_std(KindStandard.GIFT_WRAP))
            .since(since_ts)
        )
        await self._client.subscribe(f)
        self._notif_task = asyncio.create_task(
            self._client.handle_notifications(self)
        )

    # ------------------------------------------------------------------
    # nostr-sdk HandleNotification protocol
    # ------------------------------------------------------------------

    async def handle(self, relay_url, subscription_id, event) -> None:
        """Called by nostr-sdk for every event the subscription delivers."""
        try:
            await self._process_event(event, str(relay_url))
        except Exception:
            logger.exception("Nostr: error handling event")

    async def handle_msg(self, relay_url, msg) -> None:
        """Required by HandleNotification. EOSE/NOTICE/etc. are not actioned here."""
        return None

    # ------------------------------------------------------------------
    # Inbound: unwrap and dispatch
    # ------------------------------------------------------------------

    async def _process_event(self, event, relay_url: str) -> None:
        event_id = event.id().to_hex()

        # Fast-path dedup: skip events we've already accepted and processed
        if event_id in self._seen_event_ids:
            return

        # Only process gift wraps (subscription should be filtered, but be defensive)
        if event.kind().as_std() != KindStandard.GIFT_WRAP:
            return

        logger.info("Nostr: received gift wrap %s from %s", event_id[:16], relay_url)

        try:
            unwrapped = await UnwrappedGift.from_gift_wrap(self._signer, event)
        except Exception as exc:
            logger.info("Nostr: failed to unwrap event %s: %s", event_id[:16], exc)
            return

        sender: PublicKey = unwrapped.sender()
        rumor = unwrapped.rumor()

        # Only handle kind 14 (private DM)
        if rumor.kind().as_std() != KindStandard.PRIVATE_DIRECT_MESSAGE:
            logger.info(
                "Nostr: ignoring rumor of kind %s in event %s",
                rumor.kind().as_u16(),
                event_id[:16],
            )
            return

        sender_pubkey_hex = sender.to_hex()

        # Filter self-messages
        if sender_pubkey_hex == self._pubkey_hex:
            logger.info("Nostr: ignoring self-message %s", event_id[:16])
            return

        # Allowlist check.  Must happen before recording in seen list — flooding
        # from disallowed senders must not pollute the dedup window.
        if not self._allow_all_npubs and sender_pubkey_hex not in self._allowed_pubkeys:
            logger.info(
                "Nostr: rejected DM from %s — not in NOSTR_ALLOWED_NPUBS",
                sender.to_bech32(),
            )
            return

        # Record as seen only after the event has passed all checks
        self._seen_event_ids.add(event_id)
        self._seen_event_list.append(event_id)
        if len(self._seen_event_list) > self._seen_max:
            evicted = self._seen_event_list[:-self._seen_max]
            self._seen_event_list = self._seen_event_list[-self._seen_max:]
            self._seen_event_ids -= set(evicted)
        self._save_seen_ids()

        text = rumor.content()
        chat_id = sender_pubkey_hex  # pubkey is the stable chat identity

        source = self.build_source(
            chat_id=chat_id,
            chat_name=sender_pubkey_hex[:16] + "...",
            chat_type="dm",
            user_id=sender_pubkey_hex,
            user_name=sender_pubkey_hex[:16] + "...",
        )

        event_obj = MessageEvent(
            source=source,
            text=text,
            message_type=MessageType.TEXT,
        )

        logger.debug("Nostr: message from %s: %s", sender_pubkey_hex[:16], text[:60])
        await self.handle_message(event_obj)

    # ------------------------------------------------------------------
    # Outbound: send
    # ------------------------------------------------------------------

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """
        Send a NIP-17 DM to the recipient identified by chat_id (hex pubkey or npub).
        All events carry a NIP-40 expiration tag (default 1 week TTL).
        """
        if not self._client:
            return SendResult(success=False, error="Nostr: not connected")

        if not content or not content.strip():
            return SendResult(success=True, message_id=None)

        try:
            recipient_pk = PublicKey.parse(chat_id.strip())
        except Exception:
            return SendResult(success=False, error=f"Invalid recipient pubkey: {chat_id}")

        exp_ts = int(time.time()) + self._nip40_ttl_seconds
        expiration = Tag.expiration(Timestamp.from_secs(exp_ts))

        # Long replies are split into multiple DMs. Relays accept large events,
        # but each NIP-17 message is a separate gift wrap and most Nostr clients
        # render very long DMs poorly. truncate_message preserves code-fence
        # boundaries and appends "(1/N)" indicators. Mirrors whatsapp.py:937.
        chunks = self.truncate_message(content, self.MAX_MESSAGE_LENGTH)

        self_pk = self._keys.public_key()
        last_message_id: Optional[str] = None
        for chunk in chunks:
            try:
                output = await self._client.send_private_msg(recipient_pk, chunk, [expiration])
            except Exception as exc:
                logger.error("Nostr: failed to send DM: %s", exc)
                return SendResult(success=False, error=str(exc))

            # NIP-17: also send a copy to ourselves so we can recover sent-message
            # history from any other client we sign in with.
            try:
                await self._client.send_private_msg(self_pk, chunk, [expiration])
            except Exception as exc:
                logger.debug("Nostr: failed to publish self-copy: %s", exc)

            # Try to expose a message_id; tolerate shape changes between sdk
            # versions. The last chunk's id is returned (matches whatsapp.py).
            try:
                last_message_id = output.id.to_hex()  # type: ignore[attr-defined]
            except Exception:
                try:
                    last_message_id = output.id().to_hex()  # type: ignore[attr-defined]
                except Exception:
                    pass

        return SendResult(success=True, message_id=last_message_id)

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        """Nostr has no typing-indicator protocol; this is a no-op."""

    def format_tool_event(
        self,
        event: Any,
        *,
        mode: str = "all",
        preview_max_len: int = 40,
    ) -> Optional[str]:
        """Drop tool-progress chrome on Nostr (return None).

        The base implementation renders each tool call as an emoji+name+preview
        string that the gateway then ships as a regular message. Telegram can
        absorb that into a single edited bubble, but Nostr has no in-place
        message editing (NIP-09 is event deletion, not editing) — every tool
        progress event would land as its own NIP-17 gift-wrap published to
        every relay. A multi-tool turn would flood the recipient.

        Returning None tells the dispatcher to eat the event entirely, so
        only the final agent response reaches the user.
        """
        return None

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        return {
            "name": chat_id[:16] + "...",
            "type": "dm",
            "chat_id": chat_id,
        }

    # ------------------------------------------------------------------
    # Profile and inbox publishing
    # ------------------------------------------------------------------

    async def _publish_profile(self) -> None:
        """Publish a Kind 0 metadata event (NIP-01 / NIP-05 / NIP-24)."""
        meta_dict: Dict[str, Any] = {
            "name": self._bot_name,
            "display_name": self._bot_name,  # NIP-24
            "bot": True,                      # NIP-24: marks this as an automated account
        }
        if self._bot_about:
            meta_dict["about"] = self._bot_about
        if self._bot_picture:
            meta_dict["picture"] = self._bot_picture
        if self._nip05:
            meta_dict["nip05"] = self._nip05
        if self._lud16:
            meta_dict["lud16"] = self._lud16
        if self._bot_website:
            meta_dict["website"] = self._bot_website
        metadata = Metadata.from_json(json.dumps(meta_dict, ensure_ascii=False))
        await self._client.set_metadata(metadata)
        logger.debug("Nostr: published Kind 0 profile as %s", self._npub)

    async def _publish_relay_list(self) -> None:
        """Publish a Kind 10050 NIP-17 DM inbox list so senders know where to reach us."""
        tags = [Tag.parse(["relay", url]) for url in self._relay_urls]
        await self._client.send_event_builder(
            EventBuilder(Kind(10050), "").tags(tags)
        )
        logger.debug("Nostr: published Kind 10050 relay list (%d relays)", len(self._relay_urls))

    # ------------------------------------------------------------------
    # Seen-event persistence
    # ------------------------------------------------------------------

    def _seen_ids_path(self) -> Path:
        from hermes_constants import get_hermes_home
        return get_hermes_home() / f"nostr_seen_{self._pubkey_hex[:16]}.json"

    def _load_seen_ids(self) -> None:
        path = self._seen_ids_path()
        try:
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8"))
                ids = [i for i in data.get("seen", []) if isinstance(i, str)]
                self._seen_event_list = ids[-self._seen_max:]
                self._seen_event_ids = set(self._seen_event_list)
                logger.debug("Nostr: loaded %d seen event IDs", len(self._seen_event_list))
        except Exception as exc:
            logger.warning("Nostr: could not load seen IDs (%s), starting fresh", exc)
            self._seen_event_list = []
            self._seen_event_ids = set()

    def _save_seen_ids(self) -> None:
        path = self._seen_ids_path()
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(
                json.dumps({"seen": self._seen_event_list}),
                encoding="utf-8",
            )
            tmp.replace(path)
        except Exception as exc:
            logger.warning("Nostr: could not save seen IDs: %s", exc)


# ===========================================================================
# Plugin registration surface
# ===========================================================================
# Everything below replaces the per-platform touchpoints nostr used to carry in
# core (gateway/config.py enum+checker+env block, gateway/run.py adapter
# factory, tools/send_message_tool.py _send_nostr, hermes_cli/setup.py
# _setup_nostr, toolsets/status/scheduler entries).  The gateway discovers it
# all via the platform registry — see plugins/platforms/google_chat/ for the
# reference pattern. #41112.


def _build_adapter(config: PlatformConfig) -> "NostrAdapter":
    """Factory: construct a NostrAdapter from a PlatformConfig.

    __init__ is lenient (does not raise on missing key/relays/SDK) so this is
    safe to call with the registry's synthetic conformance config; connect()
    performs the real validation.
    """
    return NostrAdapter(config)


def _is_connected(config) -> bool:
    """True when a private key + ≥1 relay are configured.

    Reads via ``hermes_cli.gateway.get_env_value`` so setup-status callers that
    patch get_env_value observe the same value, and ``PlatformConfig`` extras
    (relays, seeded by ``_env_enablement``) are honored too. Replaces the legacy
    ``_PLATFORM_CONNECTED_CHECKERS[Platform.NOSTR]`` entry. #41112.
    """
    extra = getattr(config, "extra", {}) or {}
    import hermes_cli.gateway as gateway_mod
    key = getattr(config, "token", None) or gateway_mod.get_env_value("NOSTR_PRIVATE_KEY") or ""
    relays = extra.get("relays") or gateway_mod.get_env_value("NOSTR_RELAYS") or ""
    return bool(str(key).strip() and str(relays).strip())


def _env_enablement() -> Optional[Dict[str, Any]]:
    """Seed ``PlatformConfig.extra`` (+ home_channel) from NOSTR_* env vars.

    Called by the core env-populator (gateway/config.py) BEFORE the adapter is
    constructed, so ``gateway status`` / ``get_connected_platforms()`` reflect
    env-only configuration. Returns ``None`` when the required key + relays
    aren't set, so the caller skips auto-enabling. Replaces the legacy nostr
    block in ``_apply_env_overrides``. The ``token`` (private key) is NOT
    returned here — the core loop only merges into ``extra``; the adapter reads
    the key via its ``config.token or os.getenv("NOSTR_PRIVATE_KEY")`` fallback.
    """
    privkey = os.getenv("NOSTR_PRIVATE_KEY")
    relays = os.getenv("NOSTR_RELAYS")
    if not (privkey and relays):
        return None
    seed: Dict[str, Any] = {"relays": relays}
    for env_key, extra_key in (
        ("NOSTR_BOT_NAME", "name"),
        ("NOSTR_BOT_ABOUT", "about"),
        ("NOSTR_BOT_PICTURE", "picture"),
        ("NOSTR_NIP05", "nip05"),
        ("NOSTR_LUD16", "lud16"),
        ("NOSTR_BOT_WEBSITE", "website"),
        ("NOSTR_EXPIRATION_MINUTES", "expiration_minutes"),
        ("NOSTR_LOOKBACK_MINUTES", "lookback_minutes"),
    ):
        val = os.getenv(env_key, "").strip()
        if val:
            seed[extra_key] = val
    home = os.getenv("NOSTR_HOME_CHANNEL")
    if home:
        pk = parse_pubkey(home)
        if pk is not None:
            seed["home_channel"] = {
                "chat_id": pk.to_hex(),
                "name": os.getenv("NOSTR_HOME_CHANNEL_NAME", "Owner"),
            }
        else:
            logger.warning(
                "Nostr: NOSTR_HOME_CHANNEL is not a valid npub or hex pubkey — ignoring"
            )
    return seed


def _apply_yaml_config(yaml_cfg: dict, nostr_cfg: dict) -> Optional[dict]:
    """Translate ``config.yaml`` nostr: keys into NOSTR_* env vars
    (apply_yaml_config_fn contract). Env vars take precedence. Nostr is DM-only
    (NIP-17); the only allowlist is ``allow_from`` → ``NOSTR_ALLOWED_NPUBS`` (the
    npub allowlist the authz layer reads; ``*`` = allow all). Mirrors the legacy
    nostr YAML bridge removed from gateway/config.py. Returns None — everything
    flows through env.
    """
    af = nostr_cfg.get("allow_from")
    if af is not None and not os.getenv("NOSTR_ALLOWED_NPUBS"):
        if isinstance(af, list):
            af = ",".join(str(v) for v in af)
        os.environ["NOSTR_ALLOWED_NPUBS"] = str(af)
    return None


async def _standalone_send(
    pconfig,
    chat_id,
    message,
    *,
    thread_id=None,
    media_files=None,
    force_document=False,
):
    """Out-of-process Nostr delivery (standalone_sender_fn contract).

    Reuses the gateway's connected adapter when present (avoids republishing
    profile/relay-list metadata on every send); otherwise spins up a
    short-lived adapter for one message. Replaces the legacy ``_send_nostr`` in
    tools/send_message_tool.py.
    """
    if not check_nostr_requirements():
        return {"error": "Nostr dependencies not installed. Run: pip install 'hermes-agent[nostr]'"}

    adapter = NostrAdapter.get_active()
    if adapter is not None:
        result = await adapter.send(chat_id, message)
        if result.success:
            return {"success": True, "platform": "nostr", "chat_id": chat_id, "message_id": result.message_id}
        return {"error": f"Nostr send failed: {result.error}"}

    # Standalone: instantiate a short-lived adapter for one message.
    try:
        adapter = NostrAdapter(pconfig)
        connected = await adapter.connect()
        if not connected:
            return {"error": "Nostr: failed to connect to relays for standalone send"}
        try:
            result = await adapter.send(chat_id, message)
        finally:
            await adapter.disconnect()
        if result.success:
            return {"success": True, "platform": "nostr", "chat_id": chat_id, "message_id": result.message_id}
        return {"error": f"Nostr send failed: {result.error}"}
    except Exception as e:
        return {"error": f"Nostr standalone send failed: {e}"}


# ---------------------------------------------------------------------------
# Interactive setup (moved from hermes_cli/setup.py::_setup_nostr)
# ---------------------------------------------------------------------------

def _install_nostr_extra() -> bool:
    """Ensure nostr-sdk is installed into the running Python's environment.

    nostr-sdk is a Rust/PyO3 binding distributed as wheels only (no sdist); if
    no wheel exists for the current Python/platform the install fails (Termux/
    Android is the main unsupported environment). Tries uv, then pip, then
    ensurepip→pip for uv-created venvs that lack pip.
    """
    from hermes_cli.cli_output import print_info, print_success, print_warning
    try:
        __import__("nostr_sdk")
        return True
    except ImportError:
        pass
    print_info("Installing nostr-sdk (Nostr protocol library)...")
    import sys as _sys
    import shutil as _shutil
    import subprocess
    import platform as _platform
    pkg = "nostr-sdk>=0.44.2,<0.45"
    venv_root = Path(_sys.executable).parent.parent
    env = os.environ.copy()
    env["VIRTUAL_ENV"] = str(venv_root)
    env.pop("PYTHONHOME", None)

    errors: list = []

    def _run(cmd: list, label: str) -> bool:
        result = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if result.returncode == 0:
            print_success(f"nostr-sdk installed (via {label})")
            return True
        combined = (result.stderr or "") + (result.stdout or "")
        lines = [ln for ln in combined.splitlines() if ln.strip()]
        errors.append((label, "\n".join(lines[-15:]) or f"exit {result.returncode}"))
        return False

    uv_bin = _shutil.which("uv")
    if uv_bin and _run([uv_bin, "pip", "install", pkg], "uv"):
        return True
    if _run([_sys.executable, "-m", "pip", "install", pkg], "pip"):
        return True
    if any("No module named pip" in snip for _, snip in errors):
        print_info("Bootstrapping pip into the venv (ensurepip)...")
        bootstrap = subprocess.run(
            [_sys.executable, "-m", "ensurepip", "--upgrade"],
            env=env, capture_output=True, text=True,
        )
        if bootstrap.returncode == 0 and _run(
            [_sys.executable, "-m", "pip", "install", pkg], "pip (after ensurepip)"
        ):
            return True

    print_warning("nostr-sdk install failed.")
    print_info(f"Python: {_sys.version.split()[0]} on {_platform.system()} {_platform.machine()}")
    for label, snippet in errors:
        print_info(f"   ── {label} ──")
        for ln in snippet.splitlines():
            print_info(f"      {ln}")
    print_info("nostr-sdk ships as wheels only (no sdist). If no wheel exists for")
    print_info("your Python+platform, the Nostr platform isn't supported there.")
    return False


def _normalize_npub_input(entry: str, own_secret_hex: str = "") -> tuple:
    """Validate a pubkey input and return (status, npub).

    status: "ok" (npub in field 2), "private_key" (nsec), "own_private_key"
    (bot's own key), "invalid". The input value is never echoed in error states.
    """
    e = (entry or "").strip()
    if not e:
        return ("invalid", "")
    if e.lower().startswith("nsec"):
        return ("private_key", "")
    pk = parse_pubkey(e)
    if pk is None:
        return ("invalid", "")
    if own_secret_hex and pk.to_hex() == own_secret_hex:
        return ("own_private_key", "")
    return ("ok", pk.to_bech32())


def interactive_setup() -> None:
    """Configure the Nostr NIP-17 DM gateway via ``hermes setup``.

    Replaces hermes_cli/setup.py::_setup_nostr and the static
    _PLATFORMS["nostr"] dict; wired via the registry's ``setup_fn``. CLI helpers
    are lazy-imported to keep plugin import cheap.
    """
    from hermes_cli.config import get_env_value, save_env_value
    from hermes_cli.colors import Colors, color
    from hermes_cli.cli_output import (
        prompt,
        prompt_yes_no,
        print_header,
        print_info,
        print_success,
        print_warning,
        print_error,
    )

    print_header("Nostr (NIP-17 Private DMs)")
    if get_env_value("NOSTR_PRIVATE_KEY"):
        print_info("Nostr: already configured")
        if not prompt_yes_no("Reconfigure Nostr?", False):
            return

    print_info("Connects Hermes to the Nostr decentralized messaging protocol.")
    print_info("Users send NIP-17 encrypted DMs to the bot's npub from any Nostr client.")
    print()

    have_nostr_sdk = _install_nostr_extra()

    print()
    print_info("🔑 Bot's Nostr private key")
    npub: Optional[str] = None
    if prompt_yes_no("Generate a new keypair for the bot?", True):
        if not have_nostr_sdk:
            print_warning("nostr-sdk is required to generate a keypair — skipping Nostr setup")
            return
        from nostr_sdk import Keys
        keys = Keys.generate()
        privkey_hex = keys.secret_key().to_hex()
        npub = keys.public_key().to_bech32()
        save_env_value("NOSTR_PRIVATE_KEY", privkey_hex)
        print_success("Generated new keypair using nostr-sdk (OS CSPRNG)")
    else:
        if not have_nostr_sdk:
            print_warning("nostr-sdk is required to validate keys — skipping Nostr setup")
            return
        from nostr_sdk import Keys as _Keys
        privkey_hex = ""
        for _ in range(3):
            entered = prompt("Nostr private key (64-char hex or nsec bech32)", password=True)
            if not entered:
                print_warning("Private key is required — skipping Nostr setup")
                return
            try:
                parsed = _Keys.parse(entered.strip())
            except Exception:
                print_error("Invalid key — expected nsec1... bech32 or 64-char hex. Try again.")
                continue
            privkey_hex = parsed.secret_key().to_hex()
            npub = parsed.public_key().to_bech32()
            break
        else:
            print_warning("Three invalid attempts — skipping Nostr setup")
            return
        save_env_value("NOSTR_PRIVATE_KEY", privkey_hex)
        print_success("Nostr private key saved")

    if npub:
        print()
        print(color("   npub — share this so others can DM the bot:", Colors.YELLOW))
        print("   " + color(npub, Colors.CYAN, Colors.BOLD))
        print()

    print()
    valid_relays: list = []
    for _ in range(3):
        relays = prompt(
            "Relay URLs (comma-separated wss://, press Enter for defaults)",
            default="wss://relay.damus.io,wss://nos.lol",
        )
        if not relays:
            print_warning("At least one relay is required — skipping Nostr setup")
            return
        valid_relays, rejected = [], []
        for raw in relays.split(","):
            canonical = parse_relay_url(raw)
            if canonical:
                valid_relays.append(canonical)
            elif raw.strip():
                rejected.append(raw.strip())
        if rejected:
            print_error(f"Rejected — only wss:// relays are accepted: {', '.join(rejected)}")
        if valid_relays and not rejected:
            break
        print_error("Try again.")
    else:
        print_warning("Three invalid attempts — skipping Nostr setup")
        return
    save_env_value("NOSTR_RELAYS", ",".join(valid_relays))
    print_success(f"Nostr relays saved ({len(valid_relays)})")

    print()
    print_info("🔒 Who can message this bot? (npub or hex pubkey, comma-separated)")
    print_info("   Leave empty to deny all. Use * for open access.")
    allowed_value: Optional[str] = None
    for _ in range(3):
        allowed = prompt("NOSTR_ALLOWED_NPUBS")
        if not allowed:
            allowed_value = ""
            break
        if allowed.strip() == "*":
            allowed_value = "*"
            break
        normalized, had_error = [], False
        for raw in allowed.split(","):
            entry = raw.strip()
            if not entry:
                continue
            status, npub_form = _normalize_npub_input(entry, privkey_hex)
            if status == "ok":
                normalized.append(npub_form)
            elif status == "private_key":
                print_error("Rejected: that looks like a private key (nsec). Pubkeys start with npub1.")
                had_error = True
            elif status == "own_private_key":
                print_error("Rejected: that's the bot's own private key — never paste it as a pubkey.")
                had_error = True
            else:
                print_error("Rejected: invalid pubkey (expected npub1... or 64-char hex).")
                had_error = True
        if normalized and not had_error:
            allowed_value = ",".join(normalized)
            break
        print_error("Try again.")
    else:
        print_warning("Three invalid attempts — leaving allowlist unset (deny all).")
        allowed_value = ""
    if allowed_value:
        save_env_value("NOSTR_ALLOWED_NPUBS", allowed_value)
        if allowed_value == "*":
            print_info("⚠️  Open access — anyone on Nostr can DM the bot!")
        else:
            count = allowed_value.count(",") + 1
            print_success(f"Nostr allowlist configured ({count} npub{'s' if count != 1 else ''})")
    else:
        print_info("No npubs set — bot will deny all inbound messages until NOSTR_ALLOWED_NPUBS is configured.")

    print()
    print_info("👤 Owner npub — where cron job results and notifications are delivered.")
    _allowed_raw = get_env_value("NOSTR_ALLOWED_NPUBS") or ""
    _first_allowed = next(
        (e.strip() for e in _allowed_raw.split(",") if e.strip() and e.strip() != "*"),
        "",
    )
    owner_prompt = (
        "NOSTR_HOME_CHANNEL" if _first_allowed else "NOSTR_HOME_CHANNEL (leave empty to set later)"
    )
    if _first_allowed:
        print_info(f"   Press Enter to use {_first_allowed} as the owner.")
    for _ in range(3):
        home = prompt(owner_prompt, default=_first_allowed)
        if not home:
            break
        status, npub_form = _normalize_npub_input(home, privkey_hex)
        if status == "ok":
            save_env_value("NOSTR_HOME_CHANNEL", npub_form)
            break
        if status == "private_key":
            print_error("Rejected: that looks like a private key (nsec). Pubkeys start with npub1.")
        elif status == "own_private_key":
            print_error("Rejected: that's the bot's own private key — never paste it as a pubkey.")
        else:
            print_error("Rejected: invalid pubkey (expected npub1... or 64-char hex).")
    else:
        print_warning("Three invalid attempts — leaving owner unset.")

    print()
    bot_name = prompt("NOSTR_BOT_NAME (leave empty for npub)")
    if bot_name:
        save_env_value("NOSTR_BOT_NAME", bot_name.strip())

    print()
    print_success("Nostr configured!")
    print_info("Optional env vars: NOSTR_BOT_ABOUT, NOSTR_BOT_PICTURE, NOSTR_BOT_WEBSITE,")
    print_info("   NOSTR_NIP05, NOSTR_LUD16, NOSTR_EXPIRATION_MINUTES, NOSTR_SEEN_MAX, NOSTR_LOOKBACK_MINUTES")


def register(ctx) -> None:
    """Plugin entry point — called by the Hermes plugin system at startup.

    The gateway's adapter creation, env-enablement, cron delivery, send_message
    routing, authz allowlist, status display, setup wizard, and system-prompt
    hint all flow from this single registration. #41112.
    """
    ctx.register_platform(
        name="nostr",
        label="Nostr",
        adapter_factory=_build_adapter,
        check_fn=check_nostr_requirements,
        is_connected=_is_connected,
        required_env=["NOSTR_PRIVATE_KEY", "NOSTR_RELAYS"],
        install_hint="pip install 'hermes-agent[nostr]'",
        setup_fn=interactive_setup,
        apply_yaml_config_fn=_apply_yaml_config,
        env_enablement_fn=_env_enablement,
        cron_deliver_env_var="NOSTR_HOME_CHANNEL",
        standalone_sender_fn=_standalone_send,
        allowed_users_env="NOSTR_ALLOWED_NPUBS",
        allow_all_env="NOSTR_ALLOW_ALL_USERS",
        max_message_length=4096,
        pii_safe=False,
        emoji="🔑",
        allow_update_command=True,
        platform_hint=(
            "You are on Nostr, communicating via NIP-17 end-to-end-encrypted "
            "direct messages. Plain text only — no markdown rendering, no "
            "groups, no threads, and no native media uploads. Keep responses "
            "concise. Recipients are identified by npub (bech32) or hex pubkey; "
            "use target='nostr:<npub-or-hex>' to send a DM."
        ),
    )
