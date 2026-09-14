from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional
import secrets

from keygen import PublicKey, PrivateKey


class ProverType(Enum):
    HONEST = auto()
    DISHONEST = auto()


@dataclass(frozen=True)
class Commitment:
    x: int
    r: int


@dataclass(frozen=True)
class Response:
    y: int


class Prover:
    """Honest prover: knows the secret s and follows the protocol correctly."""

    def __init__(self, public_key: PublicKey, private_key: PrivateKey) -> None:
        self.n = public_key.n
        self.v = public_key.v
        self.s = private_key.s
        self._current_r: Optional[int] = None

    def commit(self) -> Commitment:
        self._current_r = secrets.randbelow(self.n - 2) + 2
        x = pow(self._current_r, 2, self.n)
        return Commitment(x=x, r=self._current_r)

    def respond(self, challenge: int) -> Response:
        if self._current_r is None:
            raise ValueError("commit() must be called before respond().")
        if challenge not in (0, 1):
            raise ValueError("Challenge must be 0 or 1.")
        if challenge == 0:
            y = self._current_r % self.n
        else:
            y = (self._current_r * self.s) % self.n
        self._current_r = None
        return Response(y=y)

    @property
    def prover_type(self) -> ProverType:
        return ProverType.HONEST


class DishonestProver:
    """
    Dishonest prover: does not know s.
    Strategy: always return y = r regardless of challenge.
    This satisfies verification only when e == 0.
    """

    def __init__(self, public_key: PublicKey) -> None:
        self.n = public_key.n
        self.v = public_key.v
        self._current_r: Optional[int] = None

    def commit(self) -> Commitment:
        self._current_r = secrets.randbelow(self.n - 2) + 2
        x = pow(self._current_r, 2, self.n)
        return Commitment(x=x, r=self._current_r)

    def respond(self, challenge: int) -> Response:
        if self._current_r is None:
            raise ValueError("commit() must be called before respond().")
        y = self._current_r % self.n
        self._current_r = None
        return Response(y=y)

    @property
    def prover_type(self) -> ProverType:
        return ProverType.DISHONEST