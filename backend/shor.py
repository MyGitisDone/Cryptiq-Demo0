"""
shor.py — Shor's algorithm for factoring small integers.

This is a *real* implementation of the quantum period-finding subroutine
(quantum phase estimation over the modular-multiplication operator a^x mod N),
followed by the classical continued-fractions post-processing that turns a
measured phase into the order r, and finally the reduction from order to
factors.

It is deliberately simulator-friendly: the controlled-U_a operators are built
as classical permutation matrices and loaded as unitary gates. That keeps the
circuit correct and easy to read, but it only scales to small N (the work
register needs n = ceil(log2 N) qubits, and Aer can comfortably simulate up to
~24-28 total qubits). That is exactly the point of the demo — Shor works, it is
just bounded by the hardware/simulator we can access today.

The strongest thing we can honestly break here is a product of two small primes,
i.e. a *tiny RSA modulus*. Everything about the method is identical to what
would break RSA-2048; only the size differs.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Callable, Optional

import numpy as np
from qiskit import QuantumCircuit
from qiskit.circuit.library import UnitaryGate, QFT


# ----------------------------------------------------------------------------
# Classical helpers
# ----------------------------------------------------------------------------

def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in range(2, int(math.isqrt(n)) + 1):
        if n % p == 0:
            return False
    return True


def modular_mult_matrix(a: int, N: int, n_qubits: int) -> np.ndarray:
    """Permutation matrix for |x> -> |a*x mod N> on n_qubits qubits.

    States x >= N (which cannot occur in a valid run) map to themselves so the
    matrix stays a valid permutation / unitary.
    """
    dim = 2 ** n_qubits
    U = np.zeros((dim, dim))
    for x in range(dim):
        if x < N:
            U[(a * x) % N, x] = 1
        else:
            U[x, x] = 1
    return U


def controlled_modular_exp_gate(a: int, power: int, N: int, n_qubits: int) -> UnitaryGate:
    """Controlled-U where U|x> = |a^(2^power) * x mod N>."""
    a_exp = pow(a, 2 ** power, N)
    U = modular_mult_matrix(a_exp, N, n_qubits)
    gate = UnitaryGate(U, label=f"{a}^2^{power} mod {N}")
    return gate.control(1)


# ----------------------------------------------------------------------------
# Quantum circuit
# ----------------------------------------------------------------------------

def build_period_finding_circuit(a: int, N: int, n_count: Optional[int] = None) -> QuantumCircuit:
    """Quantum phase estimation circuit for the order of a modulo N."""
    n_work = max(1, math.ceil(math.log2(N)))
    if n_count is None:
        n_count = 2 * n_work  # standard choice, gives enough resolution for r

    qc = QuantumCircuit(n_count + n_work, n_count)

    # Superposition over the counting register.
    for q in range(n_count):
        qc.h(q)

    # Work register starts in |1>.
    qc.x(n_count)

    # Controlled modular exponentiation.
    for i in range(n_count):
        gate = controlled_modular_exp_gate(a, i, N, n_work)
        qc.append(gate, [i] + list(range(n_count, n_count + n_work)))

    # Inverse QFT on the counting register.
    qc.append(QFT(n_count, inverse=True).to_gate(label="IQFT"), range(n_count))

    qc.measure(range(n_count), range(n_count))
    return qc


# ----------------------------------------------------------------------------
# Post-processing: phase -> order -> factors
# ----------------------------------------------------------------------------

def phase_to_order(phase: Fraction, N: int, max_denominator: int) -> Optional[int]:
    frac = phase.limit_denominator(max_denominator)
    r = frac.denominator
    return r if r > 0 else None


@dataclass
class ShorResult:
    N: int
    factors: Optional[tuple[int, int]]
    success: bool
    a_values_tried: list[int] = field(default_factory=list)
    order_found: Optional[int] = None
    attempts: int = 0
    total_shots: int = 0
    method: str = "quantum"
    log: list[str] = field(default_factory=list)


def factor_from_order(a: int, r: int, N: int) -> Optional[tuple[int, int]]:
    if r % 2 != 0:
        return None
    x = pow(a, r // 2, N)
    if x == N - 1:
        return None
    f1 = math.gcd(x - 1, N)
    f2 = math.gcd(x + 1, N)
    for f in (f1, f2):
        if 1 < f < N and N % f == 0:
            return (f, N // f)
    return None


# ----------------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------------

def run_shor(
    N: int,
    sampler: Callable[[QuantumCircuit, int], dict[str, int]],
    shots: int = 512,
    max_attempts: int = 8,
    rng: Optional[random.Random] = None,
    on_log: Optional[Callable[[str], None]] = None,
) -> ShorResult:
    """Factor N with Shor's algorithm.

    `sampler(circuit, shots)` runs the circuit on a backend (Aer or IBM) and
    returns a counts dict {bitstring: count}. This indirection is what lets the
    same algorithm run on a local simulator or real quantum hardware.
    """
    rng = rng or random.Random()
    result = ShorResult(N=N, factors=None, success=False)

    def log(msg: str) -> None:
        result.log.append(msg)
        if on_log:
            on_log(msg)

    if N % 2 == 0:
        result.factors = (2, N // 2)
        result.success = True
        result.method = "classical-trivial"
        log(f"N={N} is even; 2 is a factor (no quantum needed).")
        return result

    # Perfect power check (Shor assumes N is not a prime power).
    for b in range(2, int(math.log2(N)) + 1):
        root = round(N ** (1 / b))
        for cand in (root - 1, root, root + 1):
            if cand > 1 and cand ** b == N:
                result.factors = (cand, N // cand)
                result.success = True
                result.method = "classical-perfect-power"
                log(f"N={N} = {cand}^{b}; handled classically.")
                return result

    n_work = max(1, math.ceil(math.log2(N)))
    n_count = 2 * n_work

    coprimes = [a for a in range(2, N) if math.gcd(a, N) == 1]

    for attempt in range(1, max_attempts + 1):
        result.attempts = attempt
        # Prefer a base coprime to N so the quantum order-finding actually runs.
        # (A gcd>1 hit is a valid but uninteresting classical shortcut.)
        if coprimes:
            a = rng.choice(coprimes)
        else:
            a = rng.randrange(2, N)
        g = math.gcd(a, N)
        if g > 1:
            result.factors = (g, N // g)
            result.success = True
            result.method = "classical-lucky-gcd"
            log(f"gcd({a}, {N}) = {g} — lucky non-quantum factor.")
            return result

        result.a_values_tried.append(a)
        log(f"Attempt {attempt}: base a={a}. Running quantum order-finding…")

        circuit = build_period_finding_circuit(a, N, n_count)
        counts = sampler(circuit, shots)
        result.total_shots += shots

        # Try the most-probable measurement outcomes first.
        ordered = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
        for bitstring, _cnt in ordered:
            measured = int(bitstring.replace(" ", ""), 2)
            phase = Fraction(measured, 2 ** n_count)
            if phase == 0:
                continue
            r = phase_to_order(phase, N, N)
            if r is None:
                continue
            # r might be a divisor of the true order; try small multiples too.
            for mult in range(1, 4):
                rr = r * mult
                if pow(a, rr, N) == 1:
                    factors = factor_from_order(a, rr, N)
                    if factors:
                        result.factors = factors
                        result.order_found = rr
                        result.success = True
                        log(f"Order r={rr} recovered. Factors: {factors[0]} x {factors[1]}.")
                        return result
        log(f"Attempt {attempt} did not yield usable order; retrying with new base.")

    log("Exhausted attempts without recovering the order.")
    return result
