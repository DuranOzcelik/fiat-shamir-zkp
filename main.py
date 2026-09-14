import argparse
import sys

from config import DEFAULT_KEY_SIZE, DEFAULT_ROUNDS, SUPPORTED_KEY_SIZES
from keygen import generate_keypair
from prover import ProverType
from protocol import FiatShamirProtocol
from analysis import SecurityAnalyzer


def _trunc(n: int, length: int = 24) -> str:
    s = str(n)
    return s[:length] + "..." if len(s) > length else s


def print_round_table(results) -> None:
    header = (
        f"{'Rnd':>4} | {'r':>20} | {'x=r²modn':>20} | {'e':>2} | "
        f"{'y=r·sᵉmodn':>20} | {'y²modn':>20} | {'x·vᵉmodn':>20} | "
        f"{'LHS=RHS':>8} | {'Decision':>8}"
    )
    sep = "-" * len(header)
    print(sep)
    print(header)
    print(sep)
    for r in results:
        lhs_rhs = "Yes" if r.lhs_equals_rhs else "No"
        print(
            f"{r.round_number:>4} | {_trunc(r.r):>20} | {_trunc(r.x):>20} | {r.e:>2} | "
            f"{_trunc(r.y):>20} | {_trunc(r.y_squared):>20} | {_trunc(r.expected):>20} | "
            f"{lhs_rhs:>8} | {r.verifier_decision:>8}"
        )
    print(sep)


def cmd_run(args) -> None:
    print(f"\nGenerating {args.key_size}-bit keypair...")
    keypair = generate_keypair(args.key_size)
    pub = keypair.public
    priv = keypair.private
    print(f"  p = {_trunc(priv.p)}")
    print(f"  q = {_trunc(priv.q)}")
    print(f"  n = {_trunc(pub.n)}")
    print(f"  s = {_trunc(priv.s)}  [secret]")
    print(f"  v = {_trunc(pub.v)}  [public]\n")

    prover_type = ProverType.DISHONEST if args.dishonest else ProverType.HONEST
    label = "DISHONEST" if args.dishonest else "HONEST"
    print(f"Running protocol with {label} prover, t={args.rounds} rounds...\n")

    protocol = FiatShamirProtocol(keypair, prover_type)
    result = protocol.run(args.rounds)

    print_round_table(result.round_results)
    print(f"\nPassed: {result.passed_count}/{result.rounds}")
    print(f"Outcome: {'ACCEPTED' if result.all_passed else 'REJECTED'}")
    print(f"Execution time: {result.execution_time_ms:.3f} ms\n")


def cmd_completeness(args) -> None:
    print(f"\nGenerating {args.key_size}-bit keypair...")
    keypair = generate_keypair(args.key_size)
    analyzer = SecurityAnalyzer(keypair)
    print(f"Running completeness test: {args.runs} runs, {args.rounds} rounds each...\n")
    r = analyzer.test_completeness(runs=args.runs, rounds_per_run=args.rounds)
    print(f"  Runs:            {r.runs}")
    print(f"  Accepted:        {r.accepted}")
    print(f"  Rejected:        {r.rejected}")
    print(f"  Acceptance rate: {r.acceptance_rate:.1f}%")
    print(f"  Completeness:    {'HOLDS' if r.holds else 'FAILED'}\n")


def cmd_soundness(args) -> None:
    print(f"\nGenerating {args.key_size}-bit keypair...")
    keypair = generate_keypair(args.key_size)
    analyzer = SecurityAnalyzer(keypair)
    print(f"Running soundness test: {args.attempts} attempts per round count...\n")
    r = analyzer.test_soundness(attempts=args.attempts)

    print(f"Single-round cheat probability:")
    sr = r.single_round
    print(f"  Trials:      {sr.trials}")
    print(f"  Observed:    {sr.observed_rate:.2f}%")
    print(f"  Theoretical: {sr.theoretical_rate:.2f}%")
    print(f"  Deviation:   {sr.deviation:+.2f}%\n")

    header = f"{'Rounds':>8} | {'Theoretical %':>14} | {'Observed %':>12} | {'Cheats':>8} | {'Sound':>6}"
    sep = "-" * len(header)
    print(sep)
    print(header)
    print(sep)
    for e in r.entries:
        print(
            f"{e.rounds:>8} | {e.theoretical_bound:>14.4f} | {e.observed_rate:>12.4f} | "
            f"{e.cheat_successes:>8} | {'Yes' if e.sound else 'No':>6}"
        )
    print(sep + "\n")


def cmd_zk(args) -> None:
    print(f"\nGenerating {args.key_size}-bit keypair...")
    keypair = generate_keypair(args.key_size)
    analyzer = SecurityAnalyzer(keypair)
    print(f"Running zero-knowledge test: {args.count} transcripts each...\n")
    r = analyzer.test_zero_knowledge(transcript_count=args.count)
    print(f"  Real transcripts valid:      {r.real_valid}/{r.real_count} ({r.real_validity_rate:.1f}%)")
    print(f"  Simulated transcripts valid: {r.simulated_valid}/{r.simulated_count} ({r.simulated_validity_rate:.1f}%)")
    print(f"  Zero-knowledge property:     {'HOLDS' if r.holds else 'FAILED'}\n")


def cmd_performance(args) -> None:
    sizes = [256, 512, 1024]
    print(f"\nRunning performance test: key sizes {sizes}, {args.rounds} rounds, {args.trials} trials each...\n")
    keypair = generate_keypair(256)
    analyzer = SecurityAnalyzer(keypair)
    r = analyzer.test_performance(key_sizes=sizes, rounds=args.rounds, trials=args.trials)
    header = f"{'Bits':>8} | {'Key gen (ms)':>14} | {'Per round (ms)':>15} | {'Total (ms)':>12}"
    sep = "-" * len(header)
    print(sep)
    print(header)
    print(sep)
    for e in r.entries:
        print(
            f"{e.key_bits:>8} | {e.keygen_time_ms:>14.2f} | {e.per_round_time_ms:>15.4f} | {e.total_time_ms:>12.3f}"
        )
    print(sep + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fiat-Shamir Zero-Knowledge Proof Protocol — CLI"
    )
    parser.add_argument("--key-size", type=int, default=DEFAULT_KEY_SIZE,
                        choices=SUPPORTED_KEY_SIZES)
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="Execute the protocol")
    p_run.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS)
    p_run.add_argument("--dishonest", action="store_true")
    p_run.set_defaults(func=cmd_run)

    p_comp = sub.add_parser("completeness", help="Completeness test")
    p_comp.add_argument("--runs", type=int, default=100)
    p_comp.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS)
    p_comp.set_defaults(func=cmd_completeness)

    p_sound = sub.add_parser("soundness", help="Soundness test")
    p_sound.add_argument("--attempts", type=int, default=200)
    p_sound.set_defaults(func=cmd_soundness)

    p_zk = sub.add_parser("zk", help="Zero-knowledge test")
    p_zk.add_argument("--count", type=int, default=100)
    p_zk.set_defaults(func=cmd_zk)

    p_perf = sub.add_parser("performance", help="Performance benchmarks")
    p_perf.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS)
    p_perf.add_argument("--trials", type=int, default=10)
    p_perf.set_defaults(func=cmd_performance)

    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)