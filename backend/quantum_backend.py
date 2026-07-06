"""
quantum_backend.py — where the circuits actually run.

Exposes a single `get_sampler(...)` that returns a callable
`sampler(circuit, shots) -> counts_dict`. Swap the backend without touching the
algorithm:

  * "aer"  — local Qiskit Aer simulator. Default. No account needed.
  * "ibm"  — real IBM Quantum hardware via qiskit-ibm-runtime, if a token is set.

The IBM path is intentionally lazy-imported so the app runs with zero cloud
dependencies out of the box.
"""

from __future__ import annotations

import os
from typing import Callable, Optional

from qiskit import QuantumCircuit, transpile

Sampler = Callable[[QuantumCircuit, int], dict]


# ---------------------------------------------------------------------------
# Local Aer simulator
# ---------------------------------------------------------------------------

def _aer_sampler(noise: bool = False) -> Sampler:
    from qiskit_aer import AerSimulator

    sim = AerSimulator()

    def sampler(circuit: QuantumCircuit, shots: int) -> dict:
        tqc = transpile(circuit, sim, optimization_level=0)
        result = sim.run(tqc, shots=shots).result()
        return result.get_counts()

    return sampler


# ---------------------------------------------------------------------------
# Real IBM Quantum hardware
# ---------------------------------------------------------------------------

def _ibm_sampler(backend_name: Optional[str], shots_cap: int = 1024) -> Sampler:
    """Requires: pip install qiskit-ibm-runtime, and IBM_QUANTUM_TOKEN in env.

    Only tiny circuits (e.g. N=15) are realistic on today's noisy hardware; the
    result may be wrong and the run may queue for a while. That reality is part
    of the story the demo tells.
    """
    from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2

    token = os.environ.get("IBM_QUANTUM_TOKEN")
    if not token:
        raise RuntimeError(
            "IBM hardware selected but IBM_QUANTUM_TOKEN is not set. "
            "Get a free token at https://quantum.cloud.ibm.com and put it in .env"
        )

    service = QiskitRuntimeService(channel="ibm_quantum_platform", token=token)
    backend = (
        service.backend(backend_name)
        if backend_name
        else service.least_busy(operational=True, simulator=False)
    )

    def sampler(circuit: QuantumCircuit, shots: int) -> dict:
        tqc = transpile(circuit, backend, optimization_level=1)
        sampler_v2 = SamplerV2(mode=backend)
        job = sampler_v2.run([tqc], shots=min(shots, shots_cap))
        result = job.result()
        # SamplerV2 returns per-register bit arrays; grab the classical register.
        data = result[0].data
        creg = next(iter(data.values()))
        return creg.get_counts()

    return sampler


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def get_sampler(kind: str = "aer", backend_name: Optional[str] = None) -> Sampler:
    kind = (kind or "aer").lower()
    if kind == "ibm":
        return _ibm_sampler(backend_name)
    return _aer_sampler()


def available_backends() -> dict:
    """Report what the running instance can offer (for the frontend)."""
    info = {"aer": True, "ibm": False, "ibm_reason": ""}
    if os.environ.get("IBM_QUANTUM_TOKEN"):
        try:
            import qiskit_ibm_runtime  # noqa: F401
            info["ibm"] = True
        except ImportError:
            info["ibm_reason"] = "qiskit-ibm-runtime not installed"
    else:
        info["ibm_reason"] = "no IBM_QUANTUM_TOKEN set"
    return info
