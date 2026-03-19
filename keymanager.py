"""
SecureVault Key Manager
Shamir's Secret Sharing + key generation/management

Master key → 5 shares (3 shares needed to recover)
Vault key  → 3 shares (2 shares needed to recover)

Physical locations of key shares are decided by humans. No automatic distribution.
"""

import os
import json
import hmac
import hashlib
import secrets
from dataclasses import dataclass
from typing import List, Tuple, Optional
from datetime import datetime, timezone

from engine import KEY_SIZE


# ─── Shamir's Secret Sharing (GF(256)) ──────────────────────

class ShamirSecret:
    """Shamir's Secret Sharing over GF(2^8)

    Implemented without external libraries — minimal dependencies.
    GF(256) arithmetic for byte-level split/recover.
    """

    # GF(2^8): polynomial 0x11D (x^8+x^4+x^3+x^2+1), generator 2
    # 2 is primitive root (order 255) in 0x11D — standard for Shamir SSS
    # Note: in 0x11B (AES field) order of 2 is 51 so it cannot be used
    _EXP = [0] * 512
    _LOG = [0] * 256
    _initialized = False

    @classmethod
    def _init_tables(cls):
        """Initialize GF(2^8) log/exp tables"""
        if cls._initialized:
            return
        x = 1
        for i in range(255):
            cls._EXP[i] = x
            cls._LOG[x] = i
            x = x << 1
            if x >= 256:
                x ^= 0x11D  # x^8+x^4+x^3+x^2+1 (2 is primitive root)
        for i in range(255, 512):
            cls._EXP[i] = cls._EXP[i - 255]
        cls._initialized = True

    @classmethod
    def _gf_mul(cls, a: int, b: int) -> int:
        """GF(2^8) multiplication"""
        if a == 0 or b == 0:
            return 0
        cls._init_tables()
        return cls._EXP[cls._LOG[a] + cls._LOG[b]]

    @classmethod
    def _gf_inv(cls, a: int) -> int:
        """GF(2^8) inverse"""
        if a == 0:
            raise ZeroDivisionError("No inverse for 0 in GF(256)")
        cls._init_tables()
        return cls._EXP[255 - cls._LOG[a]]

    @classmethod
    def _eval_poly(cls, coeffs: List[int], x: int) -> int:
        """Evaluate polynomial over GF(256)"""
        result = 0
        for coeff in reversed(coeffs):
            result = cls._gf_mul(result, x) ^ coeff
        return result

    @classmethod
    def split(cls, secret: bytes, n: int, k: int) -> List[Tuple[int, bytes]]:
        """Split secret into n shares (k shares needed to recover)

        Args:
            secret: secret bytes to split
            n: total share count (2 ≤ n ≤ 255)
            k: recovery threshold (2 ≤ k ≤ n)

        Returns:
            [(x, share_bytes), ...] — x is 1~n
        """
        cls._init_tables()

        if not (2 <= k <= n <= 255):
            raise ValueError(f"Invalid parameters: n={n}, k={k} (2 ≤ k ≤ n ≤ 255)")

        shares = [(i, bytearray()) for i in range(1, n + 1)]

        for byte in secret:
            # k-1 random coefficients + secret byte as constant term
            coeffs = [byte] + [secrets.randbelow(256) for _ in range(k - 1)]
            for idx, (x, share_buf) in enumerate(shares):
                share_buf.append(cls._eval_poly(coeffs, x))

        return [(x, bytes(buf)) for x, buf in shares]

    @classmethod
    def recover(cls, shares: List[Tuple[int, bytes]]) -> bytes:
        """Recover secret from shares (Lagrange interpolation)

        Args:
            shares: [(x, share_bytes), ...] — at least k

        Returns:
            recovered secret
        """
        cls._init_tables()

        if len(shares) < 2:
            raise ValueError("At least 2 shares required")

        # verify all shares have the same length
        length = len(shares[0][1])
        if not all(len(s[1]) == length for _, s in enumerate(shares)):
            raise ValueError("Share length mismatch")

        result = bytearray(length)

        for byte_idx in range(length):
            # recover f(0) via Lagrange interpolation
            value = 0
            for i, (xi, si) in enumerate(shares):
                yi = si[byte_idx]
                # compute Lagrange basis polynomial
                basis = 1
                for j, (xj, _) in enumerate(shares):
                    if i != j:
                        # basis *= xj / (xj ^ xi)  in GF(256)
                        basis = cls._gf_mul(basis, cls._gf_mul(xj, cls._gf_inv(xj ^ xi)))
                value ^= cls._gf_mul(yi, basis)
            result[byte_idx] = value

        return bytes(result)


# ─── Key Manager ─────────────────────────────────────────────

@dataclass
class KeyInfo:
    """Key metadata"""
    key_id: str
    key_type: str       # "master", "vault", "session", "node"
    created_at: str
    shamir_n: int = 0   # split count
    shamir_k: int = 0   # threshold
    locations: list = None  # share storage locations (recorded by humans)

    def __post_init__(self):
        if self.locations is None:
            self.locations = []


class KeyManager:
    """SecureVault key manager

    Principles:
    - Physical locations of key shares are decided by humans
    - No automatic key distribution
    - Manages key metadata only (does not store actual keys/shares)
    """

    def __init__(self, metadata_path: Optional[str] = None):
        self.metadata_path = metadata_path
        self._keys: dict[str, KeyInfo] = {}
        if metadata_path and os.path.exists(metadata_path):
            self._load_metadata()

    # ─── Key generation ─────────────────────────────────────────────

    def generate_master_key(self) -> bytes:
        """Generate master key (32 bytes = AES-256)"""
        return os.urandom(KEY_SIZE)

    def generate_vault_key(self) -> bytes:
        """Generate vault key"""
        return os.urandom(KEY_SIZE)

    def generate_session_key(self) -> bytes:
        """Generate session key (memory only, not saved to disk)"""
        return os.urandom(KEY_SIZE)

    # ─── Shamir split/recover ────────────────────────────────────

    def split_key(
        self,
        key: bytes,
        n: int,
        k: int,
        key_type: str = "master",
        locations: Optional[List[str]] = None,
    ) -> Tuple[str, List[Tuple[int, bytes]]]:
        """Split key into Shamir shares

        Args:
            key: key to split
            n: total share count
            k: recovery threshold
            key_type: key type
            locations: share storage location list (specified by humans)

        Returns:
            (key_id, [(share_idx, share_bytes), ...])
        """
        shares = ShamirSecret.split(key, n, k)

        # generate key ID (based on key hash, key itself not stored)
        key_id = hashlib.sha256(key).hexdigest()[:16]

        info = KeyInfo(
            key_id=key_id,
            key_type=key_type,
            created_at=datetime.now(timezone.utc).isoformat(),
            shamir_n=n,
            shamir_k=k,
            locations=locations or [f"share{i+1}: (location unset)" for i in range(n)],
        )
        self._keys[key_id] = info
        self._save_metadata()

        return key_id, shares

    def recover_key(self, shares: List[Tuple[int, bytes]]) -> bytes:
        """Recover key from Shamir shares"""
        return ShamirSecret.recover(shares)

    # ─── HMAC key (for vssh auth) ───────────────────────────────

    @staticmethod
    def generate_hmac_key() -> bytes:
        """Generate vssh HMAC auth key (32 bytes)"""
        return os.urandom(32)

    @staticmethod
    def derive_node_key(master_hmac: bytes, node_id: str) -> bytes:
        """Derive per-node key from master HMAC

        When using per-node keys across 100+ nodes:
        node_key = HMAC-SHA256(master_hmac, node_id)
        """
        return hmac.new(
            master_hmac,
            node_id.encode("utf-8"),
            hashlib.sha256,
        ).digest()

    # ─── Key verification ─────────────────────────────────────────────

    @staticmethod
    def verify_key(key: bytes, expected_id: str) -> bool:
        """Verify key matches expected ID"""
        actual_id = hashlib.sha256(key).hexdigest()[:16]
        return hmac.compare_digest(actual_id, expected_id)

    # ─── Metadata management ─────────────────────────────────────

    def _save_metadata(self):
        if not self.metadata_path:
            return
        data = {}
        for key_id, info in self._keys.items():
            data[key_id] = {
                "key_id": info.key_id,
                "key_type": info.key_type,
                "created_at": info.created_at,
                "shamir_n": info.shamir_n,
                "shamir_k": info.shamir_k,
                "locations": info.locations,
            }
        os.makedirs(os.path.dirname(self.metadata_path), exist_ok=True)
        with open(self.metadata_path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _load_metadata(self):
        try:
            with open(self.metadata_path) as f:
                content = f.read().strip()
                if not content:
                    return  # empty file — ignore
                data = json.loads(content)
            for key_id, info_dict in data.items():
                self._keys[key_id] = KeyInfo(**info_dict)
        except (json.JSONDecodeError, KeyError):
            pass  # corrupted file — start empty

    def list_keys(self) -> List[KeyInfo]:
        """List of registered keys"""
        return list(self._keys.values())

    def get_key_info(self, key_id: str) -> Optional[KeyInfo]:
        """Look up key metadata"""
        return self._keys.get(key_id)

    def update_locations(self, key_id: str, locations: List[str]):
        """Update key share locations (manually by humans)"""
        if key_id not in self._keys:
            raise KeyError(f"Key ID not found: {key_id}")
        self._keys[key_id].locations = locations
        self._save_metadata()
