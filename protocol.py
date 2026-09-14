from dataclasses import dataclass, field
from typing import List, Union
import time

from config import DEFAULT_ROUNDS, MIN_ROUNDS, MAX_ROUNDS
from keygen import KeyPair, PublicKey, PrivateKey, generate_keypair
from prover import Prover, DishonestProver, ProverType
from verifier import Verifier, VerificationResult
from simulator import ZKSimulator, Transcript, TranscriptType


@dataclass(frozen=True)
class RoundResult:
    round_number: int
    r: int
    x: int
    e: int
    y: int
    y_squared: int
    expected: int
    lhs_equals_rhs: bool
    prover_passed: bool
    verifier_decision: str


@dataclass
class ProtocolResult:
    rounds: int
    round_results: List[RoundResult]
    prover_type: ProverType
    all_passed: bool
    passed_count: int
    failed_count: int
    execution_time_ms: float
    n: int
    v: int

    @property
    def acceptance_rate(self) -> float:
        return self.passed_count / self.rounds * 100 if self.rounds else 0.0


class FiatShamirProtocol:
    """
    Orchestrates the Fiat-Shamir identification protocol for t rounds.
    Supports both honest and dishonest provers.
    """

    def __init__(self, keypair: KeyPair, prover_type: ProverType = ProverType.HONEST) -> None:
        self.keypair = keypair
        self.prover_type = prover_type
        self.verifier = Verifier(keypair.public)

        if prover_type == ProverType.HONEST:
            self.prover: Union[Prover, DishonestProver] = Prover(
                keypair.public, keypair.private
            )
        else:
            self.prover = DishonestProver(keypair.public)

    def run(self, rounds: int = DEFAULT_ROUNDS) -> ProtocolResult:
        if not (MIN_ROUNDS <= rounds <= MAX_ROUNDS):
            raise ValueError(
                f"rounds must be between {MIN_ROUNDS} and {MAX_ROUNDS}, got {rounds}."
            )

        round_results: List[RoundResult] = []
        start = time.perf_counter()

        for i in range(1, rounds + 1):
            commitment = self.prover.commit()
            challenge = self.verifier.challenge()
            response = self.prover.respond(challenge.e)
            result: VerificationResult = self.verifier.verify(
                commitment.x, response.y, challenge.e
            )
            round_results.append(
                RoundResult(
                    round_number=i,
                    r=commitment.r,
                    x=commitment.x,
                    e=challenge.e,
                    y=response.y,
                    y_squared=result.y_squared,
                    expected=result.expected,
                    lhs_equals_rhs=result.lhs == result.rhs,
                    prover_passed=result.success,
                    verifier_decision="ACCEPT" if result.success else "REJECT",
                )
            )

        elapsed_ms = (time.perf_counter() - start) * 1000
        passed = sum(1 for r in round_results if r.prover_passed)

        return ProtocolResult(
            rounds=rounds,
            round_results=round_results,
            prover_type=self.prover_type,
            all_passed=passed == rounds,
            passed_count=passed,
            failed_count=rounds - passed,
            execution_time_ms=elapsed_ms,
            n=self.keypair.public.n,
            v=self.keypair.public.v,
        )

    def run_zk_simulation(self, count: int = 100) -> List[Transcript]:
        simulator = ZKSimulator(self.keypair.public)
        return simulator.simulate_multiple(count)


def run_protocol(
    key_size: int = 512,
    rounds: int = DEFAULT_ROUNDS,
    prover_type: ProverType = ProverType.HONEST,
    keypair: KeyPair = None,
) -> ProtocolResult:
    if keypair is None:
        keypair = generate_keypair(key_size)
    protocol = FiatShamirProtocol(keypair, prover_type)
    return protocol.run(rounds)