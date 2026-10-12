"""CARA: Causal Autonomous Red Teamer - Base Detector Module.

Causal Autonomous Red Teamer (CARA) for Network Anomaly Detection.
Integrates causal discovery, counterfactual reasoning, and automated red teaming.
"""

from __future__ import annotations

from .detector import CARADetector
from .causal_recon import CausalReconEngine
from .counterfactual_planner import CounterfactualPlanner
from .execution_engine import ExecutionEngine

__all__ = [
    "CARADetector",
    "CausalReconEngine",
    "CounterfactualPlanner",
    "ExecutionEngine",
]

__version__ = "0.2.0"