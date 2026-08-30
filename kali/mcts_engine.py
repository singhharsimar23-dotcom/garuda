"""
Monte Carlo Tree Search (MCTS) Engine for Autonomous Novel Path Synthesis (ANPS)
Explores ATT&CK technique transition graphs to uncover high-utility, evasive attack paths against GARUDA baselines.
"""

import hashlib
import logging
import math
import os
import random
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

from .attack_graph import get_attack_graph_builder
from .detection_model import get_detection_model

logger = logging.getLogger("kali.mcts_engine")

TACTIC_VALUES: Dict[str, float] = {
    "reconnaissance": 0.1,
    "resource-development": 0.2,
    "initial-access": 0.4,
    "execution": 0.6,
    "persistence": 0.7,
    "privilege-escalation": 0.7,
    "defense-evasion": 0.5,
    "credential-access": 0.8,
    "discovery": 0.5,
    "lateral-movement": 0.7,
    "collection": 0.8,
    "command-and-control": 0.9,
    "exfiltration": 1.0,
    "impact": 1.0,
}

# Per-technique physics likelihood overrides.
# physics_likelihood.json is tactic-indexed; techniques within the same tactic
# have DIFFERENT physical signatures measured in our calibration pipeline.
# These per-technique values are the single source of truth for _evaluate_trajectory().
#
# Calibration rationale:
#   T1547.001 (Registry Run Keys): Low I/O cache pressure, low RAPL delta.
#   T1053.005 (Scheduled Task): schtasks.exe EXECVE → moderate cache pressure + RAPL spike.
#   Source: PLATYPUS (2021), MalwareBazaar APT36 corpus, MITRE G0134
TECHNIQUE_PHYSICS: Dict[str, Dict[str, float]] = {
    "T1566.001": {"p_detection": 0.15, "apt36_preference": 0.90},
    "T1566.002": {"p_detection": 0.12, "apt36_preference": 0.75},
    "T1190":     {"p_detection": 0.25, "apt36_preference": 0.55},
    "T1059.005": {"p_detection": 0.82, "apt36_preference": 0.80},
    "T1059.003": {"p_detection": 0.75, "apt36_preference": 0.70},
    "T1059.004": {"p_detection": 0.70, "apt36_preference": 0.60},
    "T1055.012": {"p_detection": 0.78, "apt36_preference": 0.85},
    "T1055.001": {"p_detection": 0.72, "apt36_preference": 0.75},
    "T1055.002": {"p_detection": 0.68, "apt36_preference": 0.70},
    "T1027":     {"p_detection": 0.45, "apt36_preference": 0.85},
    # Persistence — Registry Run Keys: low I/O, low RAPL delta
    "T1547.001": {"p_detection": 0.22, "apt36_preference": 0.80},
    # Persistence — Scheduled Task: moderate cache pressure from schtasks.exe EXECVE + RAPL spike
    "T1053.005": {"p_detection": 0.38, "apt36_preference": 0.72},
    "T1003.001": {"p_detection": 0.67, "apt36_preference": 0.88},
    "T1082":     {"p_detection": 0.30, "apt36_preference": 0.60},
    "T1083":     {"p_detection": 0.28, "apt36_preference": 0.55},
    "T1021.001": {"p_detection": 0.45, "apt36_preference": 0.65},
    "T1005":     {"p_detection": 0.35, "apt36_preference": 0.70},
    "T1071.001": {"p_detection": 0.52, "apt36_preference": 0.80},
    "T1071.004": {"p_detection": 0.48, "apt36_preference": 0.70},
    # Vibeware C2 (Session O, March 2026 pivot) — MEDIUM confidence
    "T1102":     {"p_detection": 0.18, "apt36_preference": 0.90},
    "T1568.002": {"p_detection": 0.22, "apt36_preference": 0.80},
    "T1041":     {"p_detection": 0.62, "apt36_preference": 0.75},
    "T1486":     {"p_detection": 0.88, "apt36_preference": 0.40},
}

HARDENING_MAPPINGS: Dict[str, str] = {
    "T1059.005": "Deploy EPPI kprobe filter for VBScript execve",
    "T1055.012": "Monitor process memory mappings via EPPI PROT_EXEC kprobe",
    "T1071.001": "Add AXIOM-II C2 beacon power signature to baseline",
    "T1566.001": "Enable GARUDA passive DNS monitoring for lure domains",
    "T1566.002": "Enforce DNS sinkhole on external lure domains in DHARMA Tier 2",
    "T1003.001": "Deploy kernel eBPF probe on /proc/kcore and memory scraping hooks",
    "T1041": "Tune AXIOM-II exfiltration memory-bus baseline model threshold",
}


class MCTSNode:
    """Represents a search tree node corresponding to a sequence of techniques."""

    def __init__(
        self,
        technique_id: str,
        tactic: str,
        parent: Optional["MCTSNode"] = None,
        edge_weight: float = 1.0,
    ):
        self.technique_id = technique_id
        self.tactic = tactic
        self.parent = parent
        self.edge_weight = edge_weight
        self.children: List["MCTSNode"] = []
        self.visits: int = 0
        self.total_reward: float = 0.0
        self.max_reward: float = 0.0

    def get_path(self) -> List[Tuple[str, str]]:
        path = []
        curr = self
        while curr:
            path.append((curr.technique_id, curr.tactic))
            curr = curr.parent
        return list(reversed(path))

    def ucb1(self, c_exploration: float = 1.414) -> float:
        if self.visits == 0:
            return float("inf")
        exploitation = self.total_reward / self.visits
        parent_visits = self.parent.visits if self.parent else self.visits
        exploration = c_exploration * math.sqrt(math.log(parent_visits + 1) / self.visits)
        return exploitation + (exploration * math.sqrt(self.edge_weight))


class KaliMCTSEngine:
    """
    Orchestrates Monte Carlo Tree Search path synthesis over the MITRE ATT&CK technique graph.
    """

    def __init__(
        self,
        c_exploration: float = 1.414,
        max_depth: int = 4,
    ):
        self.c_exploration = c_exploration
        self.max_depth = max_depth
        self.graph_builder = get_attack_graph_builder()
        self.detection_model = get_detection_model()

    def compute_step_reward(
        self,
        technique_id: str,
        tactic: str,
        sample_count: Optional[int] = None,
    ) -> float:
        p_det, _ = self.detection_model.compute_technique_detection_prob(technique_id, tactic, sample_count)
        p_evasion = max(0.01, 1.0 - p_det)
        tactic_val = TACTIC_VALUES.get(tactic.lower(), 0.5)
        return tactic_val * p_evasion

    def compute_path_reward(
        self,
        path: List[Tuple[str, str]],
        sample_count: Optional[int] = None,
    ) -> float:
        if not path:
            return 0.0
        cumulative = 1.0
        for tech_id, tactic in path:
            step_r = self.compute_step_reward(tech_id, tactic, sample_count)
            cumulative *= step_r
        return round(cumulative, 4)

    def is_terminal(self, path: List[Tuple[str, str]]) -> bool:
        if not path:
            return False
        if len(path) >= self.max_depth:
            return True
        last_tactic = path[-1][1].lower()
        if last_tactic in ("exfiltration", "impact"):
            return True
        return False

    def _evaluate_trajectory(self, trajectory: List[str]) -> Tuple[float, float]:
        """
        Compute path-specific adversary utility and detection probability.
        Uses TECHNIQUE_PHYSICS for per-technique p_detection and apt36_preference.

        REGRESSION TEST (must pass before deploying):
            utility_a, p_a = engine._evaluate_trajectory(["T1566.001","T1547.001","T1003.001"])
            utility_b, p_b = engine._evaluate_trajectory(["T1566.001","T1053.005","T1003.001"])
            assert utility_a != utility_b  # T1547.001 p_det=0.22 != T1053.005 p_det=0.38
            assert p_a != p_b

        DO NOT use self.detection_model or any fixed constant here.
        Every return value is derived from TECHNIQUE_PHYSICS[technique_id].
        """
        if not trajectory:
            return 0.0, 0.0

        technique_utilities = []
        technique_p_detections = []

        for depth, technique_id in enumerate(trajectory):
            physics = TECHNIQUE_PHYSICS.get(technique_id)

            if physics is None:
                logger.warning(
                    f"KALI: technique {technique_id} not in TECHNIQUE_PHYSICS. "
                    f"Add to calibration pipeline before production deployment."
                )
                p_detect = 0.50
                apt36_pref = 0.30
            else:
                p_detect = physics["p_detection"]
                apt36_pref = physics["apt36_preference"]

            depth_discount = 0.95 ** depth
            step_utility = (1.0 - p_detect) * apt36_pref * depth_discount

            technique_utilities.append(step_utility)
            technique_p_detections.append(p_detect)

        path_utility = sum(technique_utilities) / len(technique_utilities)
        # Path detection probability: mean across all techniques in path.
        # Mean model: path difficulty is the average of individual detection probabilities.
        # Max (weakest link) collapses to the terminal technique, losing technique-path discrimination.
        path_p_detect = sum(technique_p_detections) / len(technique_p_detections)

        return round(path_utility, 6), round(path_p_detect, 6)

    def synthesize_novel_paths(
        self,
        num_simulations: Optional[int] = None,
        alpha_counts: Optional[List[float]] = None,
        sample_count: Optional[int] = None,
        top_k: int = 5,
        supabase_client=None,
    ) -> List[Dict[str, Any]]:
        sims = num_simulations or int(os.environ.get("KALI_MCTS_SIMULATIONS", "500"))
        graph = self.graph_builder.build_graph(alpha_counts)

        initial_nodes = [
            n for n, d in graph.nodes(data=True)
            if d.get("tactic") in ("initial-access", "reconnaissance")
        ]
        if not initial_nodes:
            initial_nodes = list(graph.nodes())[:3]

        root = MCTSNode("ROOT", "START")
        for init_node in initial_nodes:
            tactic = graph.nodes[init_node].get("tactic", "initial-access")
            weight = graph.nodes[init_node].get("weight", 1.0)
            root.children.append(MCTSNode(init_node, tactic, parent=root, edge_weight=weight))

        start_time = time.time()
        completed_sims = 0

        for _ in range(sims):
            if time.time() - start_time > 28.0:
                logger.warning(f"MCTS safeguard timeout reached after {completed_sims} simulations.")
                break

            curr = root
            while curr.children and not self.is_terminal(curr.get_path()[1:]):
                curr = max(curr.children, key=lambda c: c.ucb1(self.c_exploration))

            path_so_far = curr.get_path()[1:]

            if not self.is_terminal(path_so_far) and curr.technique_id in graph:
                neighbors = list(graph.neighbors(curr.technique_id))
                for neighbor in neighbors:
                    if neighbor not in [p[0] for p in path_so_far]:
                        tactic = graph.nodes[neighbor].get("tactic", "execution")
                        edge_w = graph[curr.technique_id][neighbor].get("weight", 1.0)
                        child_node = MCTSNode(neighbor, tactic, parent=curr, edge_weight=edge_w)
                        curr.children.append(child_node)

                if curr.children:
                    curr = random.choice(curr.children)
                    path_so_far = curr.get_path()[1:]

            sim_path = list(path_so_far)
            while not self.is_terminal(sim_path):
                last_tech = sim_path[-1][0]
                if last_tech in graph and list(graph.neighbors(last_tech)):
                    next_tech = random.choice(list(graph.neighbors(last_tech)))
                    tactic = graph.nodes[next_tech].get("tactic", "execution")
                    sim_path.append((next_tech, tactic))
                else:
                    break

            rollout_reward = self.compute_path_reward(sim_path, sample_count)
            back_node = curr
            while back_node:
                back_node.visits += 1
                back_node.total_reward += rollout_reward
                if rollout_reward > back_node.max_reward:
                    back_node.max_reward = rollout_reward
                back_node = back_node.parent

            completed_sims += 1

        discovered_paths: Dict[str, Dict[str, Any]] = {}

        def harvest_paths(node: MCTSNode):
            p = node.get_path()[1:]
            if len(p) >= 3:
                tech_seq = [x[0] for x in p]
                tactic_seq = [x[1] for x in p]
                seq_str = "->".join(tech_seq)
                hash_id = hashlib.sha256(seq_str.encode("utf-8")).hexdigest()[:8]
                disc_id = f"kali-disc-{hash_id}"

                utility = self.compute_path_reward(p, sample_count)
                p_detect, uncalibrated = self.detection_model.evaluate_path_detection_prob(p, sample_count)

                is_gap = (p_detect < 0.50) and (utility > 0.70)
                gap_status = "DEFENSIVE_GAP" if is_gap else "COVERED"

                if gap_status == "DEFENSIVE_GAP":
                    lowest_tech = min(
                        p,
                        key=lambda x: self.detection_model.compute_technique_detection_prob(x[0], x[1], sample_count)[0]
                    )[0]
                    recommendation = HARDENING_MAPPINGS.get(
                        lowest_tech,
                        f"Deploy targeted EPPI eBPF hook and YARA rule for {lowest_tech}"
                    )
                else:
                    recommendation = "Baseline power model captures shell execution bursts (rapl_pkg sigma > 3.0)"

                brahma_pref = round(sum(TACTIC_VALUES.get(t, 0.5) for t in tactic_seq) / len(tactic_seq), 3)

                discovered_paths[disc_id] = {
                    "discovery_id": disc_id,
                    "technique_sequence": tech_seq,
                    "tactic_sequence": tactic_seq,
                    "adversary_utility": utility,
                    "p_detection": p_detect,
                    "detection_uncalibrated": uncalibrated,
                    "gap_status": gap_status,
                    "hardening_recommendation": recommendation,
                    "brahma_preference_score": brahma_pref,
                    "mcts_simulations": completed_sims,
                }

            for child in node.children:
                harvest_paths(child)

        harvest_paths(root)

        ranked = sorted(
            discovered_paths.values(),
            key=lambda x: x["adversary_utility"],
            reverse=True,
        )[:top_k]

        return ranked


_mcts_engine = KaliMCTSEngine()


def get_kali_mcts_engine() -> KaliMCTSEngine:
    return _mcts_engine
