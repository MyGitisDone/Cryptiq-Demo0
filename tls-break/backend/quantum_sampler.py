"""quantum_sampler.py — local Aer simulator sampler for Shor's circuit."""
from __future__ import annotations
from typing import Callable
from qiskit import QuantumCircuit, transpile

def get_sampler() -> Callable[[QuantumCircuit, int], dict]:
    from qiskit_aer import AerSimulator
    sim = AerSimulator()
    def sampler(circuit: QuantumCircuit, shots: int) -> dict:
        tqc = transpile(circuit, sim, optimization_level=0)
        return sim.run(tqc, shots=shots).result().get_counts()
    return sampler
