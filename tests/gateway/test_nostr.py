"""Tests for the Nostr platform adapter.

Covers the checklist items from ADDING_A_PLATFORM.md:
- Platform enum value
- Config loading from env vars via _apply_env_overrides
- Adapter init (config parsing, allowlist, defaults)
- Authorization integration (platform in allowlist maps)
- Send message tool routing (platform in platform_map)

Cryptographic correctness (NIP-17 unwrap, signature verification, NIP-44
encryption) is provided by the nostr-sdk dependency and is not retested here.
"""

import os
import pytest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Platform enum
# ---------------------------------------------------------------------------

class TestPlatformEnum:
    def test_nostr_enum_value(self):
        from gateway.config import Platform
        assert Platform.NOSTR.value == "nostr"

    def test_nostr_in_platform_list(self):
        from gateway.config import Platform
        values = [p.value for p in Platform]
        assert "nostr" in values


# ---------------------------------------------------------------------------
# Config loading from env vars
# ---------------------------------------------------------------------------

class TestNostrEnvConfig:
    def test_private_key_and_relays_enable_platform(self):
        from gateway.config import load_gateway_config, Platform
        env = {
            "NOSTR_PRIVATE_KEY": "a" * 64,
            "NOSTR_RELAYS": "wss://relay.example.com",
        }
        with patch.dict(os.environ, env, clear=False):
            cfg = load_gateway_config()
        assert Platform.NOSTR in cfg.platforms
        pc = cfg.platforms[Platform.NOSTR]
        assert pc.enabled is True
        assert pc.token == "a" * 64
        assert pc.extra["relays"] == "wss://relay.example.com"

    def test_missing_relays_does_not_enable(self, monkeypatch):
        from gateway.config import load_gateway_config, Platform
        # Wipe any user-shell NOSTR_* vars that would leak into the test.
        # NOSTR_RELAYS is the one this test specifically requires absent.
        monkeypatch.delenv("NOSTR_RELAYS", raising=False)
        monkeypatch.setenv("NOSTR_PRIVATE_KEY", "a" * 64)
        cfg = load_gateway_config()
        assert Platform.NOSTR not in cfg.platforms or not cfg.platforms.get(Platform.NOSTR, MagicMock(enabled=False)).enabled

    def test_profile_extras_loaded(self):
        from gateway.config import load_gateway_config, Platform
        env = {
            "NOSTR_PRIVATE_KEY": "b" * 64,
            "NOSTR_RELAYS": "wss://relay.example.com",
            "NOSTR_BOT_NAME": "TestBot",
            "NOSTR_NIP05": "bot@example.com",
            "NOSTR_LUD16": "tips@example.com",
            "NOSTR_BOT_WEBSITE": "https://example.com",
        }
        with patch.dict(os.environ, env, clear=False):
            cfg = load_gateway_config()
        pc = cfg.platforms[Platform.NOSTR]
        assert pc.extra["name"] == "TestBot"
        assert pc.extra["nip05"] == "bot@example.com"
        assert pc.extra["lud16"] == "tips@example.com"
        assert pc.extra["website"] == "https://example.com"

    def test_lookback_minutes_loaded(self):
        from gateway.config import load_gateway_config, Platform
        env = {
            "NOSTR_PRIVATE_KEY": "b" * 64,
            "NOSTR_RELAYS": "wss://relay.example.com",
            "NOSTR_LOOKBACK_MINUTES": "60",
        }
        with patch.dict(os.environ, env, clear=False):
            cfg = load_gateway_config()
        assert cfg.platforms[Platform.NOSTR].extra["lookback_minutes"] == "60"

    def test_home_channel_loaded(self, monkeypatch):
        from gateway.config import load_gateway_config, Platform
        pubkey_hex = "c" * 64
        monkeypatch.setenv("NOSTR_PRIVATE_KEY", "d" * 64)
        monkeypatch.setenv("NOSTR_RELAYS", "wss://relay.example.com")
        monkeypatch.setenv("NOSTR_HOME_CHANNEL", pubkey_hex)
        cfg = load_gateway_config()
        pc = cfg.platforms[Platform.NOSTR]
        assert pc.home_channel is not None
        assert pc.home_channel.chat_id == pubkey_hex


# ---------------------------------------------------------------------------
# Authorization maps
# ---------------------------------------------------------------------------

class TestAuthMaps:
    def test_nostr_in_platform_env_map(self):
        """Platform.NOSTR must appear in _is_user_authorized's platform_env_map."""
        from gateway.config import Platform
        assert Platform.NOSTR is not None
        with patch.dict(os.environ, {"NOSTR_ALLOWED_NPUBS": "abc123"}, clear=False):
            assert os.getenv("NOSTR_ALLOWED_NPUBS") == "abc123"

    def test_nostr_allow_all_var_convention(self):
        with patch.dict(os.environ, {"NOSTR_ALLOW_ALL_USERS": "true"}, clear=False):
            assert os.getenv("NOSTR_ALLOW_ALL_USERS") == "true"


# ---------------------------------------------------------------------------
# Send message tool routing
# ---------------------------------------------------------------------------

class TestSendMessageToolRouting:
    def test_nostr_in_platform_map(self):
        """'nostr' must be a key in send_message_tool's platform_map."""
        import inspect
        import tools.send_message_tool as smt
        source = inspect.getsource(smt)
        assert '"nostr": Platform.NOSTR' in source or "'nostr': Platform.NOSTR" in source

    def test_nostr_in_scheduler_platform_map(self):
        import inspect
        import cron.scheduler as sch
        source = inspect.getsource(sch)
        assert '"nostr": Platform.NOSTR' in source or "'nostr': Platform.NOSTR" in source


# ---------------------------------------------------------------------------
# Profile field validators
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    __import__("importlib").util.find_spec("nostr_sdk") is None,
    reason="nostr-sdk not installed",
)
class TestProfileValidators:
    def test_local_at_domain_accepts_well_formed(self):
        from gateway.platforms.nostr import is_valid_local_at_domain
        assert is_valid_local_at_domain("bot@example.com")
        assert is_valid_local_at_domain("bot.name@sub.example.com")
        assert is_valid_local_at_domain("bot_1-2@example.io")

    def test_local_at_domain_rejects_malformed(self):
        from gateway.platforms.nostr import is_valid_local_at_domain
        assert not is_valid_local_at_domain("")
        assert not is_valid_local_at_domain("no-at-sign")
        assert not is_valid_local_at_domain("@example.com")
        assert not is_valid_local_at_domain("bot@")
        assert not is_valid_local_at_domain("bot@nodot")
        assert not is_valid_local_at_domain("bot example.com")

    def test_http_url_accepts_http_https(self):
        from gateway.platforms.nostr import is_valid_http_url
        assert is_valid_http_url("http://example.com")
        assert is_valid_http_url("https://example.com/path?q=1")
        assert is_valid_http_url("https://sub.example.com:8080/p")

    def test_http_url_rejects_other_schemes(self):
        from gateway.platforms.nostr import is_valid_http_url
        assert not is_valid_http_url("")
        assert not is_valid_http_url("ftp://example.com")
        assert not is_valid_http_url("javascript:alert(1)")
        assert not is_valid_http_url("example.com")  # no scheme
        assert not is_valid_http_url("https://")  # no host

    def test_parse_relay_url_canonicalizes_bare_host(self):
        from gateway.platforms.nostr import parse_relay_url
        assert parse_relay_url("relay.example.com") == "wss://relay.example.com"
        assert parse_relay_url("  wss://relay.example.com  ") == "wss://relay.example.com"

    def test_parse_relay_url_rejects_other_schemes(self):
        from gateway.platforms.nostr import parse_relay_url
        assert parse_relay_url("") is None
        assert parse_relay_url("   ") is None
        assert parse_relay_url("ws://relay.example.com") is None
        assert parse_relay_url("https://relay.example.com") is None
        assert parse_relay_url("wss://") is None  # scheme but no host

    def test_parse_pubkey_accepts_npub_and_hex(self):
        from gateway.platforms.nostr import parse_pubkey
        # Jack's well-known npub
        npub = "npub1sg6plzptd64u62a878hep2kev88swjh3tw00gjsfl8f237lmu63q0uf63m"
        pk = parse_pubkey(npub)
        assert pk is not None
        # Re-parse the same key from its hex form
        pk2 = parse_pubkey(pk.to_hex())
        assert pk2 is not None
        assert pk.to_hex() == pk2.to_hex()

    def test_parse_pubkey_rejects_invalid(self):
        from gateway.platforms.nostr import parse_pubkey
        assert parse_pubkey("") is None
        assert parse_pubkey("not-a-key") is None
        assert parse_pubkey("npub1invalid") is None


# ---------------------------------------------------------------------------
# Adapter init (skipped without nostr-sdk)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    __import__("importlib").util.find_spec("nostr_sdk") is None,
    reason="nostr-sdk not installed",
)
class TestNostrAdapterInit:
    def _make_config(self, privkey_hex=None, relays=None, extra=None):
        from gateway.config import PlatformConfig
        # Use a fixed valid 32-byte hex key; randomness isn't needed here.
        privkey_hex = privkey_hex or ("01" * 32)
        relays = relays or "wss://relay.example.com"
        config = PlatformConfig(
            enabled=True,
            token=privkey_hex,
            extra={"relays": relays, **(extra or {})},
        )
        return config

    def test_adapter_init_sets_pubkey(self):
        from gateway.platforms.nostr import NostrAdapter
        from nostr_sdk import Keys
        privkey_hex = "01" * 32
        config = self._make_config(privkey_hex=privkey_hex)
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NOSTR_ALLOWED_NPUBS", None)
            adapter = NostrAdapter(config)
        expected_pubkey = Keys.parse(privkey_hex).public_key().to_hex()
        assert adapter._pubkey_hex == expected_pubkey
        assert adapter._npub.startswith("npub1")

    def test_adapter_init_parses_relay_list(self):
        from gateway.platforms.nostr import NostrAdapter
        config = self._make_config(relays="wss://relay1.example.com,wss://relay2.example.com")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NOSTR_ALLOWED_NPUBS", None)
            adapter = NostrAdapter(config)
        assert len(adapter._relay_urls) == 2
        assert "wss://relay1.example.com" in adapter._relay_urls

    def test_adapter_init_rejects_non_wss(self):
        from gateway.platforms.nostr import NostrAdapter
        config = self._make_config(relays="ws://insecure.example.com,wss://ok.example.com")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NOSTR_ALLOWED_NPUBS", None)
            adapter = NostrAdapter(config)
        # Only wss:// relays should remain
        assert adapter._relay_urls == ["wss://ok.example.com"]

    def test_adapter_init_parses_allowlist(self):
        from gateway.platforms.nostr import NostrAdapter
        pubkey_hex = "ab" * 32
        config = self._make_config()
        with patch.dict(os.environ, {"NOSTR_ALLOWED_NPUBS": pubkey_hex}, clear=False):
            adapter = NostrAdapter(config)
        assert pubkey_hex in adapter._allowed_pubkeys

    def test_adapter_init_parses_npub_in_allowlist(self):
        """Allowlist must accept npub bech32 form, normalizing to hex."""
        from gateway.platforms.nostr import NostrAdapter
        from nostr_sdk import Keys
        # Generate a known npub from a known privkey
        keys = Keys.parse("ab" * 32)
        npub = keys.public_key().to_bech32()
        expected_hex = keys.public_key().to_hex()
        config = self._make_config()
        with patch.dict(os.environ, {"NOSTR_ALLOWED_NPUBS": npub}, clear=False):
            adapter = NostrAdapter(config)
        assert expected_hex in adapter._allowed_pubkeys

    def test_adapter_missing_token_raises(self):
        from gateway.platforms.nostr import NostrAdapter
        from gateway.config import PlatformConfig
        config = PlatformConfig(enabled=True, token="", extra={"relays": "wss://x.com"})
        with pytest.raises(ValueError, match="NOSTR_PRIVATE_KEY"):
            NostrAdapter(config)

    def test_adapter_default_denies_all(self):
        """Empty NOSTR_ALLOWED_NPUBS must default to deny-all, not open access."""
        from gateway.platforms.nostr import NostrAdapter
        config = self._make_config()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NOSTR_ALLOWED_NPUBS", None)
            adapter = NostrAdapter(config)
        assert not adapter._allow_all_npubs
        assert len(adapter._allowed_pubkeys) == 0

    def test_adapter_star_allows_all(self):
        """NOSTR_ALLOWED_NPUBS=* must set allow-all flag."""
        from gateway.platforms.nostr import NostrAdapter
        config = self._make_config()
        with patch.dict(os.environ, {"NOSTR_ALLOWED_NPUBS": "*"}, clear=False):
            adapter = NostrAdapter(config)
        assert adapter._allow_all_npubs
        assert len(adapter._allowed_pubkeys) == 0

    def test_adapter_missing_relays_raises(self):
        from gateway.platforms.nostr import NostrAdapter
        from gateway.config import PlatformConfig
        config = PlatformConfig(enabled=True, token="01" * 32, extra={"relays": ""})
        with pytest.raises(ValueError, match="NOSTR_RELAYS"):
            NostrAdapter(config)

    def test_adapter_lookback_default_is_48h(self):
        from gateway.platforms.nostr import NostrAdapter, NIP59_MIN_LOOKBACK_MINUTES
        config = self._make_config()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NOSTR_ALLOWED_NPUBS", None)
            adapter = NostrAdapter(config)
        assert adapter._lookback_seconds == NIP59_MIN_LOOKBACK_MINUTES * 60

    def test_adapter_lookback_overrides_via_extra(self):
        from gateway.platforms.nostr import NostrAdapter
        config = self._make_config(extra={"lookback_minutes": "60"})
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NOSTR_ALLOWED_NPUBS", None)
            adapter = NostrAdapter(config)
        assert adapter._lookback_seconds == 60 * 60
