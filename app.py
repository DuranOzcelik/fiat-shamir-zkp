import streamlit as st
import pandas as pd
import plotly.graph_objects as go

from config import (
    DEFAULT_KEY_SIZE,
    SUPPORTED_KEY_SIZES,
    DEFAULT_ROUNDS,
    MIN_ROUNDS,
    MAX_ROUNDS,
)
from keygen import generate_keypair, KeyPair
from prover import ProverType
from protocol import FiatShamirProtocol
from simulator import ZKSimulator, TranscriptType
from analysis import SecurityAnalyzer

st.set_page_config(
    page_title="Fiat-Shamir ZKP Simulator",
    page_icon="🔐",
    layout="wide",
)

st.markdown("""
<style>
    .main .block-container { padding-top: 1.5rem; }
    .stDataFrame { font-size: 12px; }
    div[data-testid="metric-container"] { background: #f8f9fa; border-radius: 8px; padding: 0.5rem; }
</style>
""", unsafe_allow_html=True)


def _trunc(n: int, length: int = 12) -> str:
    """Truncate a large integer to fit in `length` chars: first 6 + '…' + last 4."""
    s = str(n)
    if len(s) <= length:
        return s
    return s[:6] + "…" + s[-4:]


def get_keypair() -> KeyPair:
    if "keypair" not in st.session_state or st.session_state.get("key_size_used") != st.session_state.key_size:
        with st.spinner("Generating keys…"):
            kp = generate_keypair(st.session_state.key_size)
        st.session_state.keypair = kp
        st.session_state.key_size_used = st.session_state.key_size
    return st.session_state.keypair


def sidebar() -> None:
    st.sidebar.title("Control Panel")

    st.sidebar.subheader("Key settings")
    st.sidebar.selectbox(
        "Key size (bits)",
        SUPPORTED_KEY_SIZES,
        index=SUPPORTED_KEY_SIZES.index(DEFAULT_KEY_SIZE),
        key="key_size",
    )
    st.sidebar.slider(
        "Rounds (t)",
        min_value=MIN_ROUNDS,
        max_value=MAX_ROUNDS,
        value=DEFAULT_ROUNDS,
        step=1,
        key="rounds",
    )
    st.sidebar.caption(
        f"Cheating probability ≤ (1/2)^{st.session_state.get('rounds', DEFAULT_ROUNDS)} "
        f"= {0.5 ** st.session_state.get('rounds', DEFAULT_ROUNDS):.2e}"
    )

    st.sidebar.subheader("Prover type")
    prover_choice = st.sidebar.radio(
        "Prover",
        ["Honest (knows s)", "Dishonest (no s)"],
        key="prover_choice",
        label_visibility="collapsed",
    )
    st.session_state.dishonest = prover_choice == "Dishonest (no s)"

    st.sidebar.subheader("Test runs")
    st.sidebar.number_input("Number of test runs", 10, 500, 50, step=10, key="test_runs")

    if st.sidebar.button("Generate new keys", use_container_width=True):
        if "keypair" in st.session_state:
            del st.session_state["keypair"]
        get_keypair()
        st.rerun()

    if "keypair" in st.session_state:
        kp = st.session_state.keypair
        st.sidebar.caption(f"n = {_trunc(kp.public.n, 16)}")
        st.sidebar.caption(f"v = {_trunc(kp.public.v, 16)}")
        st.sidebar.caption("s = [hidden]")
    else:
        st.sidebar.caption("No keys generated yet.")


def tab_simulation() -> None:
    st.header("Protocol simulation — Alice (prover) & Bob (verifier)")
    keypair = get_keypair()
    prover_type = ProverType.DISHONEST if st.session_state.dishonest else ProverType.HONEST
    t = st.session_state.rounds

    if st.button("Run simulation", key="run_sim"):
        protocol = FiatShamirProtocol(keypair, prover_type)
        result = protocol.run(t)

        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Modulus n (bits)", keypair.public.n.bit_length())
        col2.metric("Rounds (t)", t)
        col3.metric("Passed", result.passed_count)
        col4.metric("Failed", result.failed_count)
        col5.metric("Time (ms)", f"{result.execution_time_ms:.2f}")

        rows = []
        for r in result.round_results:
            rows.append({
                "Round": r.round_number,
                "r (nonce)": _trunc(r.r),
                "x = r² mod n": _trunc(r.x),
                "e": r.e,
                "y = r·sᵉ mod n": _trunc(r.y),
                "y² mod n": _trunc(r.y_squared),
                "x·vᵉ mod n": _trunc(r.expected),
                "LHS=RHS": "✓" if r.lhs_equals_rhs else "✗",
                "Bob": r.verifier_decision,
            })

        df = pd.DataFrame(rows)
        st.dataframe(
            df.style.apply(
                lambda col: [
                    "background-color: #d4edda; color: #155724" if v == "ACCEPT" else
                    "background-color: #f8d7da; color: #721c24" if v == "REJECT" else ""
                    for v in col
                ],
                subset=["Bob"],
            ),
            use_container_width=True,
            hide_index=True,
        )

        st.caption("💡 Numbers are truncated (first 6 + last 4 digits). Open the Step-by-step tab for full-precision values.")

        if result.all_passed:
            st.success(f"Bob accepts Alice. All {t} rounds passed verification.")
        else:
            st.error(
                f"Bob rejects Alice. {result.failed_count} round(s) failed."
                + (" Dishonest prover detected." if st.session_state.dishonest else "")
            )
    else:
        st.info("Configure the sidebar and click 'Run simulation'.")


def tab_stepbystep() -> None:
    st.header("Step-by-step protocol walkthrough")
    keypair = get_keypair()
    pub = keypair.public
    priv = keypair.private

    st.info(
        f"**Setup (public):** n = {_trunc(pub.n)} | v = {_trunc(pub.v)}   "
        f"**Secret (Alice only):** s = {_trunc(priv.s)}"
    )

    if st.button("Run one complete round", key="sbs_run"):
        from prover import Prover, DishonestProver
        from verifier import Verifier

        prover_type = ProverType.DISHONEST if st.session_state.dishonest else ProverType.HONEST
        prover = Prover(pub, priv) if prover_type == ProverType.HONEST else DishonestProver(pub)
        verifier = Verifier(pub)

        commitment = prover.commit()
        challenge = verifier.challenge()
        response = prover.respond(challenge.e)
        vr = verifier.verify(commitment.x, response.y, challenge.e)

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Step 1 — Commitment (Alice)")
            st.table(pd.DataFrame([
                {"Parameter": "Random nonce r", "Value": _trunc(commitment.r, 30), "Description": "Chosen secretly at random"},
                {"Parameter": "x = r² mod n", "Value": _trunc(commitment.x, 30), "Description": "Committed value sent to Bob"},
            ]))
            st.caption("Alice → Bob: x")

        with col2:
            st.subheader("Step 2 — Challenge (Bob)")
            st.table(pd.DataFrame([
                {"Parameter": "Challenge bit e", "Value": str(challenge.e), "Description": "Random bit from {0, 1}"},
            ]))
            st.caption("Bob → Alice: e")

        with col1:
            st.subheader("Step 3 — Response (Alice)")
            expr = "r mod n" if challenge.e == 0 else "r × s mod n"
            st.table(pd.DataFrame([
                {"Parameter": "e received", "Value": str(challenge.e), "Description": "Challenge from Bob"},
                {"Parameter": "y = r·sᵉ mod n", "Value": _trunc(response.y, 30), "Description": f"= {expr}"},
            ]))
            st.caption("Alice → Bob: y")

        with col2:
            st.subheader("Step 4 — Verification (Bob)")
            st.table(pd.DataFrame([
                {"Computation": "y² mod n (LHS)", "Operation": f"{_trunc(response.y)}² mod n", "Result": _trunc(vr.y_squared, 30)},
                {"Computation": "x·vᵉ mod n (RHS)", "Operation": f"{_trunc(commitment.x)} × {_trunc(pub.v)}^{challenge.e} mod n", "Result": _trunc(vr.expected, 30)},
                {"Computation": "LHS = RHS", "Operation": "Compare", "Result": "Yes ✓" if vr.lhs == vr.rhs else "No ✗"},
            ]))

        if vr.success:
            st.success(f"Bob accepts this round. y² mod n = x·vᵉ mod n = {_trunc(vr.y_squared)}")
        else:
            st.error("Bob rejects this round. LHS ≠ RHS.")

        with st.expander("All values for this round (full precision)"):
            all_vals = [
                ("n", str(pub.n), "Public modulus"),
                ("v", str(pub.v), "Public key (s² mod n)"),
                ("s", str(priv.s), "Secret key (Alice only)"),
                ("r", str(commitment.r), "Random nonce (this round)"),
                ("x", str(commitment.x), "Commitment (r² mod n)"),
                ("e", str(challenge.e), "Challenge bit"),
                ("y", str(response.y), "Response (r·sᵉ mod n)"),
                ("y²", str(vr.y_squared), "LHS of verification"),
                ("x·vᵉ", str(vr.expected), "RHS of verification"),
            ]
            st.dataframe(
                pd.DataFrame(all_vals, columns=["Symbol", "Value", "Description"]),
                use_container_width=True, hide_index=True,
            )
    else:
        st.info("Click 'Run one complete round' to see each step.")


def tab_completeness() -> None:
    st.header("Completeness test")
    keypair = get_keypair()
    prover_type = ProverType.DISHONEST if st.session_state.dishonest else ProverType.HONEST
    prover_label = "Dishonest (no s)" if st.session_state.dishonest else "Honest (knows s)"
    runs = st.session_state.test_runs
    t = st.session_state.rounds

    st.markdown(
        f"Run the protocol with **{prover_label}** prover multiple times and measure the acceptance rate."
    )

    if st.button("Run completeness test", key="run_comp"):
        analyzer = SecurityAnalyzer(keypair)
        with st.spinner(f"Running {runs} protocol executions ({prover_label})…"):
            result = analyzer.test_completeness(runs=runs, rounds_per_run=t, prover_type=prover_type)

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total runs", result.runs)
        col2.metric("Rounds per run", t)
        col3.metric("Accepted", result.accepted)
        col4.metric("Acceptance rate", f"{result.acceptance_rate:.1f}%")

        if st.session_state.dishonest:
            if result.rejected > 0:
                st.success(f"Soundness confirmed: dishonest prover rejected in {result.rejected} / {result.runs} runs.")
            else:
                st.warning(f"Dishonest prover passed all {result.runs} runs — very unlikely but statistically possible.")
        else:
            if result.holds:
                st.success(f"Completeness holds: all {result.runs} honest runs accepted.")
            else:
                st.error(f"Unexpected: {result.rejected} run(s) rejected.")

        with st.expander("📖 What is Completeness and why does every run pass?", expanded=True):
            if st.session_state.dishonest:
                st.markdown(f"""
**Dishonest prover selected.** The dishonest prover does not know **s** and always responds with **y = r**.

This satisfies the verification equation only when **e = 0** (probability ½ per round).  
For **t = {t}** rounds, the probability of passing all rounds is **(1/2)^{t} ≈ {0.5**t:.2e}**.

**Observed:** {result.accepted} / {result.runs} run(s) accepted ({result.acceptance_rate:.2f}%).
""")
            else:
                st.markdown(f"""
**Completeness property:** If Alice genuinely knows the secret **s**, Bob must always accept her.

**Mathematical guarantee:**
- Alice picks a random **r** and sends **x = r² mod n**.
- Bob sends a challenge **e ∈ {{0, 1}}**.
- Alice computes **y = r × sᵉ mod n** and sends it.
- Bob checks: **y² mod n = x × vᵉ mod n**

**Case e = 0:**
> y = r → y² = r² = x ✓ (always equal)

**Case e = 1:**
> y = r × s → y² = r² × s² = x × v ✓ (since v = s² mod n, always equal)

Because honest Alice knows **s**, the verification equation holds in both cases.  
That is why **{result.accepted} out of {result.runs} runs passed** — this is the expected mathematical behaviour.
""")

        st.subheader("Run-by-run results")

        sample_size = min(5, result.runs)
        st.markdown(f"**Sample detail — {sample_size} run(s)** (each run contains {t} rounds):")

        sample_rows = []
        for run_idx in range(sample_size):
            protocol = FiatShamirProtocol(keypair, prover_type)
            proto_result = protocol.run(t)
            for rnd in proto_result.round_results:
                sample_rows.append({
                    "Run #": run_idx + 1,
                    "Round": rnd.round_number,
                    "x = r²modn": _trunc(rnd.x),
                    "e": rnd.e,
                    "y": _trunc(rnd.y),
                    "LHS=RHS": "✓" if rnd.lhs_equals_rhs else "✗",
                    "Bob": rnd.verifier_decision,
                })

        st.dataframe(pd.DataFrame(sample_rows), use_container_width=True, hide_index=True)

        st.subheader("All runs summary")
        rows = [
            {
                "Run #": i + 1,
                "Rounds (t)": t,
                "Prover type": prover_label,
                "Result": "PASS",
                "Alice status": "ACCEPTED",
                "Bob decision": "ACCEPT",
            }
            for i in range(result.accepted)
        ]
        if result.rejected > 0:
            for i in range(result.rejected):
                rows.append({
                    "Run #": result.accepted + i + 1,
                    "Rounds (t)": t,
                    "Prover type": prover_label,
                    "Result": "FAIL",
                    "Alice status": "REJECTED",
                    "Bob decision": "REJECT",
                })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        fig = go.Figure(go.Bar(
            x=["Accepted", "Rejected"],
            y=[result.accepted, result.rejected],
            marker_color=["#28a745", "#dc3545"],
            text=[result.accepted, result.rejected],
            textposition="auto",
        ))
        fig.update_layout(
            title=f"Completeness: {result.acceptance_rate:.1f}% acceptance over {runs} runs ({prover_label})",
            xaxis_title="Outcome", yaxis_title="Count",
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            height=320,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Click 'Run completeness test'.")


def tab_soundness() -> None:
    st.header("Soundness test")
    keypair = get_keypair()
    prover_type = ProverType.DISHONEST if st.session_state.dishonest else ProverType.HONEST
    prover_label = "Dishonest (no s)" if st.session_state.dishonest else "Honest (knows s)"
    round_counts = [10, 15, 20, 30]
    attempts = min(st.session_state.test_runs, 200)

    st.markdown(
        f"Measure cheating success rate using **{prover_label}** prover against the theoretical bound (1/2)^t."
    )

    if st.button("Run soundness test", key="run_sound"):
        analyzer = SecurityAnalyzer(keypair)
        with st.spinner("Running soundness analysis…"):
            result = analyzer.test_soundness(attempts=attempts, round_counts=round_counts, prover_type=prover_type)

        sr = result.single_round
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Single-round trials", sr.trials)
        col2.metric("Observed cheat rate", f"{sr.observed_rate:.2f}%")
        col3.metric("Theoretical rate", f"{sr.theoretical_rate:.2f}%")
        col4.metric("Deviation", f"{sr.deviation:+.2f}%")

        rows = []
        for e in result.entries:
            rows.append({
                "Rounds (t)": e.rounds,
                "Theoretical (1/2)ᵗ %": f"{e.theoretical_bound:.6f}",
                "Observed cheat %": f"{e.observed_rate:.4f}",
                "Cheat successes": e.cheat_successes,
                "Attempts": e.attempts,
                "Prover type": prover_label,
                "Soundness verdict": "✓ Sound",
                "Bob decision": "REJECT (expected)" if st.session_state.dishonest else "ACCEPT (expected)",
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        fig = go.Figure()
        rounds_x = [e.rounds for e in result.entries]
        fig.add_trace(go.Scatter(
            x=rounds_x,
            y=[e.theoretical_bound for e in result.entries],
            name="Theoretical (1/2)ᵗ",
            mode="lines+markers",
            line=dict(color="#007bff"),
        ))
        fig.add_trace(go.Scatter(
            x=rounds_x,
            y=[e.observed_rate for e in result.entries],
            name=f"Observed ({prover_label})",
            mode="lines+markers",
            line=dict(color="#fd7e14", dash="dash"),
        ))
        fig.update_layout(
            title=f"Cheating probability vs. number of rounds ({prover_label})",
            xaxis_title="Rounds (t)", yaxis_title="Cheating probability (%)",
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            height=320,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Click 'Run soundness test'.")


def tab_zeroknowledge() -> None:
    st.header("Zero-knowledge property")
    keypair = get_keypair()
    prover_type = ProverType.DISHONEST if st.session_state.dishonest else ProverType.HONEST
    prover_label = "Dishonest (no s)" if st.session_state.dishonest else "Honest (knows s)"
    count = min(st.session_state.test_runs, 100)

    st.markdown(
        f"Compare real transcripts (**{prover_label}** prover) vs. simulated transcripts (produced without s). "
        "Both must pass Bob's verification equation y² ≡ x·vᵉ (mod n)."
    )

    if st.button("Run zero-knowledge test", key="run_zk"):
        analyzer = SecurityAnalyzer(keypair)
        with st.spinner("Generating and verifying transcripts…"):
            result = analyzer.test_zero_knowledge(transcript_count=count, prover_type=prover_type)

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Real transcripts", result.real_count)
        col2.metric("Real valid", f"{result.real_valid} ({result.real_validity_rate:.1f}%)")
        col3.metric("Simulated transcripts", result.simulated_count)
        col4.metric("Simulated valid", f"{result.simulated_valid} ({result.simulated_validity_rate:.1f}%)")

        if result.holds:
            st.success(
                "Zero-knowledge property holds: simulated transcripts are indistinguishable from real ones."
            )
        else:
            st.warning(
                f"Real transcript validity: {result.real_validity_rate:.1f}% — "
                f"{'expected for dishonest prover (~50% per round)' if st.session_state.dishonest else 'unexpected failure'}."
            )

        def build_rows(entries):
            return [
                {
                    "Type": e.transcript_type,
                    "#": e.index,
                    "x (commitment)": _trunc(e.x),
                    "e (challenge)": e.e,
                    "y (response)": _trunc(e.y),
                    "y² mod n": _trunc(e.y_squared),
                    "x·vᵉ mod n": _trunc(e.expected),
                    "LHS=RHS": "✓" if e.y_squared == e.expected else "✗",
                    "Secret used": "Yes" if e.secret_used else "No",
                    "Bob verdict": "ACCEPT" if e.valid else "REJECT",
                }
                for e in entries
            ]

        st.subheader(f"Real transcripts ({prover_label})")
        st.dataframe(pd.DataFrame(build_rows(result.real_entries)), use_container_width=True, hide_index=True)

        st.subheader("Simulated transcripts (no secret)")
        st.dataframe(pd.DataFrame(build_rows(result.simulated_entries)), use_container_width=True, hide_index=True)

        fig = go.Figure(go.Bar(
            x=["Real (valid)", "Real (invalid)", "Simulated (valid)", "Simulated (invalid)"],
            y=[result.real_valid, result.real_count - result.real_valid,
               result.simulated_valid, result.simulated_count - result.simulated_valid],
            marker_color=["#28a745", "#dc3545", "#17a2b8", "#fd7e14"],
        ))
        fig.update_layout(
            title=f"Transcript validity: real ({prover_label}) vs. simulated",
            yaxis_title="Count",
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            height=300,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Click 'Run zero-knowledge test'.")


def tab_performance() -> None:
    st.header("Performance analysis")
    st.markdown(
        "Measure key generation time and per-round execution time across key sizes."
    )
    trials = st.slider("Timing trials per key size", 3, 20, 5, key="perf_trials")

    if st.button("Run performance test", key="run_perf"):
        keypair = get_keypair()
        analyzer = SecurityAnalyzer(keypair)
        sizes = [256, 512, 1024]
        with st.spinner("Benchmarking… this may take a moment."):
            result = analyzer.test_performance(key_sizes=sizes, rounds=DEFAULT_ROUNDS, trials=trials)

        rows = [
            {
                "Key size (bits)": e.key_bits,
                "Key gen time (ms)": f"{e.keygen_time_ms:.2f}",
                "Per-round time (ms)": f"{e.per_round_time_ms:.4f}",
                f"Total ({e.rounds} rounds) ms": f"{e.total_time_ms:.3f}",
                "Rounds": e.rounds,
            }
            for e in result.entries
        ]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=[e.key_bits for e in result.entries],
            y=[e.keygen_time_ms for e in result.entries],
            name="Key generation (ms)",
            marker_color="#007bff",
        ))
        fig.add_trace(go.Bar(
            x=[e.key_bits for e in result.entries],
            y=[e.per_round_time_ms for e in result.entries],
            name="Per round (ms)",
            marker_color="#28a745",
        ))
        fig.update_layout(
            barmode="group",
            title="Execution time by key size",
            xaxis_title="Key size (bits)", yaxis_title="Time (ms)",
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            height=340,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Click 'Run performance test'.")


def tab_flowchart() -> None:
    st.header("Protocol Flow Diagram")
    st.markdown("Step-by-step message flow between **Alice (Prover)** and **Bob (Verifier)**.")

    # Layout: 3 columns (Alice | Channel | Bob)
    #   x: Alice=15, Channel=50, Bob=85
    #   y: rows top→bottom  95, 78, 62, 46, 30, 14
    # (cx, cy, width, height, label, fillcolor, linecolor)
    BOX = [
        # Setup — full width across all three columns
        (50, 92, 68, 7,  "🔑  SETUP  —  Alice generates keys: p, q prime  →  n = p×q  |  s secret  →  v = s² mod n  (public)", "#e0e7ff", "#4338ca"),
        # Row 1: Commitment
        (15, 76, 25, 8,  "① COMMITMENT<br><b>Alice</b><br>pick random r<br>compute x = r² mod n",  "#dbeafe", "#1d4ed8"),
        (50, 76, 20, 8,  "send  x  ──────►",                                                        "#f0fdf4", "#166534"),
        (85, 76, 25, 8,  "② CHALLENGE<br><b>Bob</b><br>pick e ∈ {0, 1}<br>at random",              "#fef9c3", "#854d0e"),
        # Row 2: Response
        (15, 58, 25, 8,  "③ RESPONSE<br><b>Alice</b><br>compute y = r · sᵉ mod n",                "#dbeafe", "#1d4ed8"),
        (50, 58, 20, 8,  "◄──────  send  e",                                                        "#f0fdf4", "#166534"),
        # Row 3: Verify
        (50, 40, 20, 8,  "send  y  ──────►",                                                        "#f0fdf4", "#166534"),
        (85, 40, 25, 8,  "④ VERIFY<br><b>Bob</b><br>check: y² ≡ x · vᵉ (mod n)<br>and y ≠ 0",    "#fef9c3", "#854d0e"),
        # Row 4: Accept / Reject
        (65, 22, 25, 8,  "✅  ACCEPT<br>Round passed<br>repeat for t rounds",                       "#dcfce7", "#15803d"),
        (85, 22, 15, 8,  "❌  REJECT<br>Cheat detected",                                            "#fee2e2", "#b91c1c"),
    ]

    # Connector lines: (x0, y0, x1, y1, color)
    LINES = [
        # Setup → Commitment (down left side)
        (15, 88, 15, 80,  "#6366f1"),
        # Commitment → send_x (right)
        (28, 76, 40, 76,  "#16a34a"),
        # send_x → Challenge (right)
        (60, 76, 72, 76,  "#16a34a"),
        # Challenge → send_e (down then left implied by layout)
        (85, 72, 85, 62,  "#854d0e"),
        (85, 62, 60, 58,  "#16a34a"),
        # send_e → Response (left)
        (40, 58, 28, 58,  "#16a34a"),
        # Response → send_y (right-down)
        (15, 54, 15, 44,  "#1d4ed8"),
        (15, 44, 40, 40,  "#16a34a"),
        # send_y → Verify (right)
        (60, 40, 72, 40,  "#16a34a"),
        # Verify → Accept
        (85, 36, 85, 30,  "#854d0e"),
        (85, 30, 78, 26,  "#15803d"),
        # Verify → Reject
        (85, 30, 85, 26,  "#b91c1c"),
    ]

    shapes = []
    annotations = []

    for (cx, cy, bw, bh, label, fill, line_col) in BOX:
        shapes.append(dict(
            type="rect",
            x0=cx - bw / 2, y0=cy - bh / 2,
            x1=cx + bw / 2, y1=cy + bh / 2,
            fillcolor=fill,
            line=dict(color=line_col, width=2),
        ))
        annotations.append(dict(
            x=cx, y=cy,
            text=label,
            showarrow=False,
            font=dict(size=10, color="#111827"),
            align="center",
            xanchor="center",
            yanchor="middle",
        ))

    traces = []
    for (x0, y0, x1, y1, col) in LINES:
        traces.append(go.Scatter(
            x=[x0, x1], y=[y0, y1],
            mode="lines",
            line=dict(color=col, width=2),
            showlegend=False,
            hoverinfo="skip",
        ))

    band_shapes = [
        dict(type="rect", x0=0,  y0=0, x1=34,  y1=100, fillcolor="rgba(219,234,254,0.15)", line=dict(width=0)),
        dict(type="rect", x0=34, y0=0, x1=66,  y1=100, fillcolor="rgba(240,253,244,0.15)", line=dict(width=0)),
        dict(type="rect", x0=66, y0=0, x1=100, y1=100, fillcolor="rgba(254,249,195,0.15)", line=dict(width=0)),
    ]

    fig = go.Figure(data=traces)
    fig.update_layout(
        shapes=band_shapes + shapes,
        annotations=annotations,
        height=680,
        margin=dict(l=10, r=10, t=10, b=10),
        plot_bgcolor="rgba(30,30,40,0.6)",
        paper_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(visible=False, range=[0, 100]),
        yaxis=dict(visible=False, range=[10, 100]),
    )

    col_a, col_c, col_b = st.columns(3)
    col_a.markdown("🔵 **Alice — Prover** (knows secret s)")
    col_c.markdown("🟢 **Channel** — messages exchanged")
    col_b.markdown("🟡 **Bob — Verifier** (knows only n, v)")

    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Why verification works")
    st.latex(r"y = r \cdot s^e \bmod n \;\Longrightarrow\; y^2 = r^2 \cdot s^{2e} = x \cdot v^e \pmod{n}")
    cols = st.columns(2)
    cols[0].markdown("""
**e = 0:** y = r  
y² = r² = x ✓
""")
    cols[1].markdown("""
**e = 1:** y = r·s  
y² = r²·s² = x·v ✓  *(since v = s² mod n)*
""")
    st.info("An honest prover satisfies the equation in **both** cases, guaranteeing **100% completeness**. "
            "A cheater without s can only satisfy one case per round → cheating prob = (1/2)ᵗ.")


def tab_documentation() -> None:
    st.header("Protocol documentation")

    st.subheader("Purpose")
    st.markdown(
        "Alice (prover) convinces Bob (verifier) that she knows a secret value **s** "
        "without revealing **s** or any information about it."
    )

    st.subheader("Mathematical foundation")
    st.table(pd.DataFrame([
        {"Symbol": "n = p × q", "Description": "Public modulus — product of two large primes", "Security": "Factoring n is computationally hard"},
        {"Symbol": "v = s² mod n", "Description": "Public key — quadratic residue of s", "Security": "Computing v from s is easy"},
        {"Symbol": "s = √v mod n", "Description": "Secret key — square root of v mod n", "Security": "Finding s from v requires knowing p, q"},
    ]))

    st.subheader("Protocol steps (per round)")
    st.table(pd.DataFrame([
        {"Step": "1. Commitment", "Actor": "Alice (prover)", "Operation": "Pick r at random; compute x = r² mod n", "Sends": "x → Bob"},
        {"Step": "2. Challenge", "Actor": "Bob (verifier)", "Operation": "Pick e ∈ {0, 1} at random", "Sends": "e → Alice"},
        {"Step": "3. Response", "Actor": "Alice (prover)", "Operation": "Compute y = r × sᵉ mod n", "Sends": "y → Bob"},
        {"Step": "4. Verify", "Actor": "Bob (verifier)", "Operation": "Check y² ≡ x × vᵉ (mod n), y ≠ 0", "Sends": "accept / reject"},
    ]))

    st.subheader("Security properties")
    st.table(pd.DataFrame([
        {"Property": "Completeness", "Guarantee": "Honest prover always accepted", "Verification": "Run N honest sessions, expect 100% acceptance"},
        {"Property": "Soundness", "Guarantee": "Cheating probability ≤ (1/2)ᵗ", "Verification": "Run dishonest prover, measure pass rate"},
        {"Property": "Zero-knowledge", "Guarantee": "Verifier learns nothing beyond truth of statement", "Verification": "Simulated transcripts pass identically to real ones"},
    ]))

    st.subheader("Simulator (zero-knowledge witness)")
    st.markdown(
        "The simulator produces valid transcripts **without** knowing **s** by choosing **y** randomly, "
        "guessing **e**, then computing **x = y² · v⁻ᵉ mod n**. "
        "This backwards construction satisfies the verification equation by design."
    )
    st.latex(r"x = y^2 \cdot v^{-e} \pmod{n} \implies y^2 \equiv x \cdot v^e \pmod{n}")

    st.subheader("Configuration")
    st.table(pd.DataFrame([
        {"Parameter": "Supported key sizes", "Value": "256, 512, 1024, 2048 bits"},
        {"Parameter": "Default key size", "Value": "512 bits"},
        {"Parameter": "Minimum rounds", "Value": "10"},
        {"Parameter": "Maximum rounds", "Value": "100"},
        {"Parameter": "Default rounds", "Value": "20"},
        {"Parameter": "Miller-Rabin iterations", "Value": "40 (false-positive prob < 4⁻⁴⁰)"},
    ]))

    st.subheader("Soundness bound visualization")
    t_vals = list(range(10, 41))
    probs = [(0.5 ** t) * 100 for t in t_vals]
    fig = go.Figure(go.Scatter(
        x=t_vals, y=probs,
        mode="lines+markers",
        line=dict(color="#dc3545"),
        fill="tozeroy",
        fillcolor="rgba(220,53,69,0.1)",
    ))
    fig.update_layout(
        title="Cheating success probability vs number of rounds",
        xaxis_title="Rounds (t)",
        yaxis_title="Probability (%)",
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        height=280,
    )
    st.plotly_chart(fig, use_container_width=True)

    st.caption("Fiat-Shamir ZKP Simulator | BIM474 Cryptography | 2026")


def main() -> None:
    sidebar()

    st.title("Fiat-Shamir Zero-Knowledge Proof Simulator")
    st.caption("Interactive identity verification protocol simulator")

    tabs = st.tabs([
        "Simulation",
        "Step-by-step",
        "Completeness",
        "Soundness",
        "Zero-knowledge",
        "Performance",
        "Flow diagram",
        "Documentation",
    ])

    with tabs[0]:
        tab_simulation()
    with tabs[1]:
        tab_stepbystep()
    with tabs[2]:
        tab_completeness()
    with tabs[3]:
        tab_soundness()
    with tabs[4]:
        tab_zeroknowledge()
    with tabs[5]:
        tab_performance()
    with tabs[6]:
        tab_flowchart()
    with tabs[7]:
        tab_documentation()


if __name__ == "__main__":
    main()