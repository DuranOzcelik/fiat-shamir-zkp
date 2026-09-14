from dataclasses import dataclass
from enum import Enum, auto
from typing import List
import secrets

from keygen import PublicKey


class TranscriptType(Enum):
    REAL = auto()
    SIMULATED = auto()


@dataclass(frozen=True)
class Transcript:
    x: int
    e: int
    y: int
    y_squared: int
    expected: int
    valid: bool
    transcript_type: TranscriptType


def _mod_inverse(a: int, m: int) -> int:
    a, m = a % m, m
    old_r, r = a, m
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    if old_r != 1:
        raise ValueError(f"{a} has no inverse modulo {m}.")
    return old_s % m


class ZKSimulator:
    """
    Produces transcripts (x, e, y) that satisfy the verification equation
    y² ≡ x · vᵉ (mod n) without knowing the secret s.

    Technique (backwards construction):
        1. Choose y randomly from Z*_n.
        2. Choose e randomly from {0, 1}.
        3. Compute x = y² · v⁻ᵉ mod n.
        The transcript (x, e, y) satisfies verification by construction.
    """

    def __init__(self, public_key: PublicKey) -> None:
        self.n = public_key.n
        self.v = public_key.v
        self._v_inv: int = _mod_inverse(self.v, self.n)

    def simulate_transcript(self) -> Transcript:
        e = secrets.randbelow(2)
        y = secrets.randbelow(self.n - 2) + 2
        y_sq = pow(y, 2, self.n)
        if e == 0:
            x = y_sq
        else:
            x = (y_sq * self._v_inv) % self.n
        expected = x % self.n if e == 0 else (x * self.v) % self.n
        valid = y_sq == expected
        return Transcript(
            x=x,
            e=e,
            y=y,
            y_squared=y_sq,
            expected=expected,
            valid=valid,
            transcript_type=TranscriptType.SIMULATED,
        )

    def simulate_multiple(self, count: int) -> List[Transcript]:
        return [self.simulate_transcript() for _ in range(count)]