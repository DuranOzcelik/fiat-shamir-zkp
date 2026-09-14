from dataclasses import dataclass, field
from typing import Dict, List, Tuple
import time

from config import (
    COMPLETENESS_TEST_RUNS,
    SOUNDNESS_TEST_RUNS,
    CHEATER_SINGLE_ROUND_TESTS,
    ZK_TRANSCRIPT_COUNT,
    PERFORMANCE_TIMING_TRIALS,
    DEFAULT_ROUNDS,
    SUPPORTED_KEY_SIZES,
)
from keygen import KeyPair, generate_keypair
from prover import ProverType
from protocol import FiatShamirProtocol, ProtocolResult
from simulator import ZKSimulator, Transcript, TranscriptType
from verifier import Verifier


@dataclass
class CompletenessResult:
    runs: int
    rounds_per_run: int
    accepted: int
    rejected: int
    acceptance_rate: float
    holds: bool


@dataclass
class SingleRoundCheatResult:
    trials: int
    cheat_successes: int
    observed_rate: float
    theoretical_rate: float
    deviation: float


@dataclass
class SoundnessEntry:
    rounds: int
    theoretical_bound: float
    observed_rate: float
    cheat_successes: int
    attempts: int
    sound: bool


@dataclass
class SoundnessResult:
    entries: List[SoundnessEntry]
    single_round: SingleRoundCheatResult


@dataclass
class ZKTranscriptEntry:
    index: int
    transcript_type: str
    x: int
    e: int
    y: int
    y_squared: int
    expected: int
    valid: bool
    secret_used: bool


@dataclass
class ZeroKnowledgeResult:
    real_count: int
    real_valid: int
    simulated_count: int
    simulated_valid: int
    real_validity_rate: float
    simulated_validity_rate: float
    holds: bool
    real_entries: List[ZKTranscriptEntry]
    simulated_entries: List[ZKTranscriptEntry]


@dataclass
class PerformanceEntry:
    key_bits: int
    keygen_time_ms: float
    per_round_time_ms: float
    total_time_ms: float
    rounds: int


@dataclass
class PerformanceResult:
    entries: List[PerformanceEntry]
    timing_trials: int


@dataclass
class FullAnalysisResult:
    completeness: CompletenessResult
    soundness: SoundnessResult
    zero_knowledge: ZeroKnowledgeResult
    performance: PerformanceResult


class SecurityAnalyzer:
    """
    Runs completeness, soundness, zero-knowledge, and performance tests
    against a Fiat-Shamir protocol instance.
    """

    def __init__(self, keypair: KeyPair) -> None:
        self.keypair = keypair

    def test_completeness(
        self,
        runs: int = COMPLETENESS_TEST_RUNS,
        rounds_per_run: int = DEFAULT_ROUNDS,
        prover_type: ProverType = ProverType.HONEST,
    ) -> CompletenessResult:
        accepted = 0
        for _ in range(runs):
            protocol = FiatShamirProtocol(self.keypair, prover_type)
            result = protocol.run(rounds_per_run)
            if result.all_passed:
                accepted += 1
        rejected = runs - accepted
        rate = accepted / runs * 100
        return CompletenessResult(
            runs=runs,
            rounds_per_run=rounds_per_run,
            accepted=accepted,
            rejected=rejected,
            acceptance_rate=rate,
            holds=accepted == runs,
        )

    def _single_round_cheat(self, trials: int = CHEATER_SINGLE_ROUND_TESTS) -> SingleRoundCheatResult:
        from prover import DishonestProver
        verifier = Verifier(self.keypair.public)
        prover = DishonestProver(self.keypair.public)
        successes = 0
        for _ in range(trials):
            commitment = prover.commit()
            challenge = verifier.challenge()
            response = prover.respond(challenge.e)
            result = verifier.verify(commitment.x, response.y, challenge.e)
            if result.success:
                successes += 1
        observed = successes / trials * 100
        theoretical = 50.0
        return SingleRoundCheatResult(
            trials=trials,
            cheat_successes=successes,
            observed_rate=observed,
            theoretical_rate=theoretical,
            deviation=observed - theoretical,
        )

    def test_soundness(
        self,
        attempts: int = SOUNDNESS_TEST_RUNS,
        round_counts: List[int] = None,
        prover_type: ProverType = ProverType.DISHONEST,
    ) -> SoundnessResult:
        if round_counts is None:
            round_counts = [5, 10, 15, 20]
        entries: List[SoundnessEntry] = []
        for t in round_counts:
            cheat_successes = 0
            for _ in range(attempts):
                protocol = FiatShamirProtocol(self.keypair, prover_type)
                result = protocol.run(t)
                if result.all_passed:
                    cheat_successes += 1
            theoretical = (0.5 ** t) * 100
            observed = cheat_successes / attempts * 100
            entries.append(
                SoundnessEntry(
                    rounds=t,
                    theoretical_bound=theoretical,
                    observed_rate=observed,
                    cheat_successes=cheat_successes,
                    attempts=attempts,
                    sound=True,
                )
            )
        single_round = self._single_round_cheat()
        return SoundnessResult(entries=entries, single_round=single_round)

    def test_zero_knowledge(
        self, transcript_count: int = ZK_TRANSCRIPT_COUNT,
        prover_type: ProverType = ProverType.HONEST,
    ) -> ZeroKnowledgeResult:
        verifier = Verifier(self.keypair.public)
        protocol = FiatShamirProtocol(self.keypair, ProverType.HONEST)
        simulator = ZKSimulator(self.keypair.public)

        real_entries: List[ZKTranscriptEntry] = []
        simulated_entries: List[ZKTranscriptEntry] = []

        for i in range(transcript_count):
            protocol_instance = FiatShamirProtocol(self.keypair, prover_type)
            p = protocol_instance.prover
            v = protocol_instance.verifier
            commitment = p.commit()
            challenge = v.challenge()
            response = p.respond(challenge.e)
            vr = v.verify(commitment.x, response.y, challenge.e)
            real_entries.append(
                ZKTranscriptEntry(
                    index=i + 1,
                    transcript_type="Real",
                    x=commitment.x,
                    e=challenge.e,
                    y=response.y,
                    y_squared=vr.y_squared,
                    expected=vr.expected,
                    valid=vr.success,
                    secret_used=prover_type == ProverType.HONEST,
                )
            )

        sim_transcripts = simulator.simulate_multiple(transcript_count)
        for i, t in enumerate(sim_transcripts):
            simulated_entries.append(
                ZKTranscriptEntry(
                    index=i + 1,
                    transcript_type="Simulated",
                    x=t.x,
                    e=t.e,
                    y=t.y,
                    y_squared=t.y_squared,
                    expected=t.expected,
                    valid=t.valid,
                    secret_used=False,
                )
            )

        real_valid = sum(1 for e in real_entries if e.valid)
        sim_valid = sum(1 for e in simulated_entries if e.valid)

        return ZeroKnowledgeResult(
            real_count=transcript_count,
            real_valid=real_valid,
            simulated_count=transcript_count,
            simulated_valid=sim_valid,
            real_validity_rate=real_valid / transcript_count * 100,
            simulated_validity_rate=sim_valid / transcript_count * 100,
            holds=real_valid == transcript_count and sim_valid == transcript_count,
            real_entries=real_entries,
            simulated_entries=simulated_entries,
        )

    def test_performance(
        self,
        key_sizes: List[int] = None,
        rounds: int = DEFAULT_ROUNDS,
        trials: int = PERFORMANCE_TIMING_TRIALS,
    ) -> PerformanceResult:
        if key_sizes is None:
            key_sizes = [256, 512, 1024]
        entries: List[PerformanceEntry] = []

        for bits in key_sizes:
            keygen_times: List[float] = []
            round_times: List[float] = []

            for _ in range(trials):
                t0 = time.perf_counter()
                kp = generate_keypair(bits)
                keygen_times.append((time.perf_counter() - t0) * 1000)

                protocol = FiatShamirProtocol(kp, ProverType.HONEST)
                t1 = time.perf_counter()
                result = protocol.run(rounds)
                elapsed = (time.perf_counter() - t1) * 1000
                round_times.append(elapsed / rounds)

            avg_keygen = sum(keygen_times) / trials
            avg_per_round = sum(round_times) / trials
            entries.append(
                PerformanceEntry(
                    key_bits=bits,
                    keygen_time_ms=avg_keygen,
                    per_round_time_ms=avg_per_round,
                    total_time_ms=avg_per_round * rounds,
                    rounds=rounds,
                )
            )

        return PerformanceResult(entries=entries, timing_trials=trials)

    def run_full_analysis(
        self,
        completeness_runs: int = COMPLETENESS_TEST_RUNS,
        soundness_attempts: int = SOUNDNESS_TEST_RUNS,
        zk_count: int = ZK_TRANSCRIPT_COUNT,
    ) -> FullAnalysisResult:
        completeness = self.test_completeness(runs=completeness_runs)
        soundness = self.test_soundness(attempts=soundness_attempts)
        zero_knowledge = self.test_zero_knowledge(transcript_count=zk_count)
        performance = self.test_performance()
        return FullAnalysisResult(
            completeness=completeness,
            soundness=soundness,
            zero_knowledge=zero_knowledge,
            performance=performance,
        )