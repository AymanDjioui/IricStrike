"""IricStrike session slice (Phase 0.5 interface slice).

Holds two engagement-scoped identities (a, b) declared in scope.yaml and, in
later pieces, replays a GET request AS a named identity to compare access across
accounts. The interface shape is locked here; internals are stubbed.

Decoupled from the frozen scope-guard engine: it reads the identity block from
scope.yaml directly. Session material is never echoed (see identity.Identity).
"""
from .identity import (IDENTITY_NAMES, Identity, IdentityError,
                       load_identities, load_identities_from_file,
                       require_identity)
from .replay import ReplayError, build_curl, replay_get

__all__ = ["IDENTITY_NAMES", "Identity", "IdentityError", "load_identities",
           "load_identities_from_file", "require_identity",
           "ReplayError", "build_curl", "replay_get"]
__version__ = "0.1.0"
