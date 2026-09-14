from dataclasses import dataclass
import secrets

from keygen import PublicKey


@dataclass(frozen=True)
class Challenge:
    e: int


@dataclass(frozen=True)
class VerificationResult:
    success: bool
    lhs: int
    rhs: int
    y_squared: int
    expected: int


class Verifier:
    """
    Verifier (Bob): issues random challenges and verifies the prover's responses.
    Holds only the public key (n, v).
    """

    def __init__(self, public_key: PublicKey) -> None:
        self.n = public_key.n
        self.v = public_key.v

    def challenge(self) -> Challenge:
        e = secrets.randbelow(2)
        return Challenge(e=e)

    def verify(self, x: int, y: int, e: int) -> VerificationResult:
        if y == 0:
            return VerificationResult(
                success=False,
                lhs=0,
                rhs=-1,
                y_squared=0,
                expected=-1,
            )
        y_squared = pow(y, 2, self.n)
        if e == 0:
            expected = x % self.n
        else:
            expected = (x * self.v) % self.n
        success = y_squared == expected
        return VerificationResult(
            success=success,
            lhs=y_squared,
            rhs=expected,
            y_squared=y_squared,
            expected=expected,
        )