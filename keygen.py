from dataclasses import dataclass
from math import gcd
import secrets
from sympy import randprime

from config import DEFAULT_KEY_SIZE, SUPPORTED_KEY_SIZES, MILLER_RABIN_ITERATIONS


@dataclass(frozen=True)
class PublicKey:
    n: int
    v: int


@dataclass(frozen=True)
class PrivateKey:
    s: int
    p: int
    q: int


@dataclass(frozen=True)
class KeyPair:
    public: PublicKey
    private: PrivateKey


def generate_prime(bit_length: int) -> int:
    lower = 1 << (bit_length - 1)
    upper = (1 << bit_length) - 1
    return randprime(lower, upper)


def generate_safe_secret(n: int, key_size: int) -> int:
    max_attempts = 10_000
    for _ in range(max_attempts):
        s = secrets.randbelow(n - 2) + 2
        if gcd(s, n) == 1 and s * s > n and 1 < s < n:
            return s
    raise RuntimeError("Could not generate a safe secret within attempt limit.")


def generate_keypair(key_size: int = DEFAULT_KEY_SIZE) -> KeyPair:
    if key_size not in SUPPORTED_KEY_SIZES:
        raise ValueError(
            f"Unsupported key size {key_size}. Choose from {SUPPORTED_KEY_SIZES}."
        )
    prime_bits = key_size // 2
    p = generate_prime(prime_bits)
    q = generate_prime(prime_bits)
    while p == q:
        q = generate_prime(prime_bits)
    n = p * q
    s = generate_safe_secret(n, key_size)
    v = pow(s, 2, n)
    return KeyPair(
        public=PublicKey(n=n, v=v),
        private=PrivateKey(s=s, p=p, q=q),
    )