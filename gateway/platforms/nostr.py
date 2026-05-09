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
from typing import Any, Dict, List, Optional, Set
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
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NIP40_TTL_SECONDS = 7 * 24 * 3600  # 1 week default
# NIP-59 created_at obfuscation window.
NIP59_MIN_LOOKBACK_MINUTES = 2880


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

    def __init__(self, config: PlatformConfig) -> None:
        super().__init__(config, Platform.NOSTR)

        if not _NOSTR_SDK_AVAILABLE:
            raise ImportError(
                "nostr-sdk is required. Install with: pip install 'hermes-agent[nostr]'"
            )

        # Private key & derived pubkey (Keys.parse accepts nsec or hex)
        raw_key = (config.token or "").strip()
        if not raw_key:
            raise ValueError("Nostr: NOSTR_PRIVATE_KEY is required")
        try:
            self._keys: Keys = Keys.parse(raw_key)
        except Exception as exc:
            raise ValueError(
                "Nostr: could not parse NOSTR_PRIVATE_KEY — expected an "
                "nsec1... bech32 string or 64-char hex"
            ) from exc
        self._signer: NostrSigner = NostrSigner.keys(self._keys)
        self._pubkey_hex: str = self._keys.public_key().to_hex()
        self._npub: str = self._keys.public_key().to_bech32()

        # Relay list (≥1 required; only wss:// accepted)
        relay_str = config.extra.get("relays", "")
        self._relay_urls: List[str] = []
        for raw in relay_str.split(","):
            canonical = parse_relay_url(raw)
            if canonical:
                self._relay_urls.append(canonical)
            elif raw.strip():
                logger.warning("Nostr: relay %r rejected — only wss:// is supported", raw.strip())
        if not self._relay_urls:
            raise ValueError("Nostr: NOSTR_RELAYS must contain at least one wss:// URL")

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
        allowed_raw = os.getenv("NOSTR_ALLOWED_NPUBS", "").strip()
        self._allow_all_npubs: bool = (allowed_raw == "*")
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
        self._load_seen_ids()
        self._client = Client(self._signer)

        for url in self._relay_urls:
            try:
                await self._client.add_relay(RelayUrl.parse(url))
            except Exception as exc:
                logger.warning("Nostr: could not add relay %s: %s", url, exc)
        await self._client.connect()
        logger.info("Nostr: connected to %d relay(s)", len(self._relay_urls))

        self._running = True

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

        logger.info("Nostr: connected (npub=%s, relays=%d)", self._npub, len(self._relay_urls))
        return True

    async def disconnect(self) -> None:
        self._running = False
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
        logger.info("Nostr: disconnected")

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

        try:
            recipient_pk = PublicKey.parse(chat_id.strip())
        except Exception:
            return SendResult(success=False, error=f"Invalid recipient pubkey: {chat_id}")

        exp_ts = int(time.time()) + self._nip40_ttl_seconds
        expiration = Tag.expiration(Timestamp.from_secs(exp_ts))

        try:
            output = await self._client.send_private_msg(recipient_pk, content, [expiration])
        except Exception as exc:
            logger.error("Nostr: failed to send DM: %s", exc)
            return SendResult(success=False, error=str(exc))

        # NIP-17: also send a copy to ourselves so we can recover sent-message
        # history from any other client we sign in with.
        try:
            await self._client.send_private_msg(self._keys.public_key(), content, [expiration])
        except Exception as exc:
            logger.debug("Nostr: failed to publish self-copy: %s", exc)

        # Try to expose a message_id; tolerate shape changes between sdk versions.
        message_id: Optional[str] = None
        try:
            message_id = output.id.to_hex()  # type: ignore[attr-defined]
        except Exception:
            try:
                message_id = output.id().to_hex()  # type: ignore[attr-defined]
            except Exception:
                pass

        return SendResult(success=True, message_id=message_id)

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        """Nostr has no typing-indicator protocol; this is a no-op."""

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
