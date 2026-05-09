"""Shared helpers for canonicalising Nostr sender identity.

A Nostr public key has two interchangeable serialisations:

- Bech32 form: ``npub1...``
- Hex form:    ``deadbeef...``

Either may show up in a sender field or in a config allow-list, and the
two surfaces aren't string-equal. The authorisation path
(:mod:`gateway.run`) needs to treat them as the same identity, so this
module is the single source of truth for that resolution — mirroring
:mod:`gateway.whatsapp_identity` for the WhatsApp bridge.

Public helpers:

- :func:`expand_nostr_aliases` — return the full alias set (both bech32
  and hex forms) for an identifier. Used by authorisation code that needs
  to match any known form of a sender against an allow-list.
"""

from __future__ import annotations

from typing import Set


def expand_nostr_aliases(identifier: str) -> Set[str]:
    """Return both npub bech32 and hex forms of a Nostr pubkey.

    Accepts either form (or a wildcard ``"*"``) and returns the set of
    equivalent identifiers, so callers can ``in``-check against an
    allow-list without caring which serialisation either side used.

    Returns an empty set if ``identifier`` is empty. Returns the input
    unchanged in a single-element set if ``nostr_sdk`` is unavailable
    or the value can't be parsed as a public key.
    """
    value = (identifier or "").strip()
    if not value:
        return set()
    if value == "*":
        return {value}
    try:
        from nostr_sdk import PublicKey
        pk = PublicKey.parse(value)
        return {pk.to_hex(), pk.to_bech32()}
    except Exception:
        return {value}
